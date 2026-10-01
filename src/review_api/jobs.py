"""Review job store and worker (requirements 3, 4, 5).

Owns the review lifecycle behind the HTTP API:

  requested -> cloning -> reviewing -> completed
                              |-------> failed      (restartable)
                              |-------> cancelled   (restartable)
                              |-------> paused      (resumable)

Paused is cancelled with intent: the run stops between units (so the
checkpoint is complete) and a `<id>.paused.json` marker records it on disk,
so the review still reads as paused after this process restarts.

State lives in memory, so this is the local/dev control plane; the platform
replaces it with the durable PostgreSQL state machine [04-low-level-design].
What it does provide today is the important half: because the underlying
pipeline checkpoints every completed unit, a failed or cancelled review can
be RESTARTED and resumes instead of starting over (requirement 4).

CREDENTIAL HANDLING (requirement 5). A caller may supply an `access_token`
for a private repository. It is held in a separate in-memory map for the
lifetime of the clone and then deleted. It is never written to the job
record, the report, a checkpoint, a log line, or any HTTP response — the job
record only remembers the boolean `authenticated`.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from code_review_mcp import llm
from code_review_mcp.config import settings
from code_review_mcp.findings import FindingsError
from code_review_mcp.llm import LLMUnavailableError
from code_review_mcp.pipeline import (ReviewCancelled, RetryError,
                                      retry_failed, run_review)
from code_review_mcp.repo_ingest import IngestError

from . import review_state

TERMINAL = ("completed", "failed", "cancelled", "paused")
# Every status the pipeline reports while it works. "scanning" and
# "retrying" were missing, so a review in its scanner phase did not count
# as running: a second review could start beside it, and it could not be
# cancelled or paused.
ACTIVE = ("requested", "cloning", "scanning", "reviewing", "retrying")

# The two per-file progress message shapes the engine emits in deep mode
# (code_review_mcp.review.review_one): "<path>: reviewing" as a file starts,
# then heartbeats "<path>: thinking|answering (...)", and "<path> done (n/N)"
# when it finishes. Matched strictly on those verbs, so a status message
# that merely contains ": " never counts as a file starting.
_ACTIVE_FILE = re.compile(r"^(?P<path>.+?): (?:reviewing|thinking|answering)\b")
_FINISHED_FILE = re.compile(r"^(?P<path>.+) done \(\d+/\d+\)$")


def _now() -> str:
    return (datetime.now(timezone.utc).isoformat(timespec="seconds")
            .replace("+00:00", "Z"))


@dataclass
class Job:
    """One review. Everything here is safe to serialize to a client."""

    job_id: str
    review_id: str
    repo_url: str
    mode: str
    provider: str
    model: str
    # Per-review endpoint override ("point this run at 100.x.y.z"). Empty =
    # use the provider's configured base_url. Not a secret: it is provenance
    # worth showing, so it appears in the status payload.
    base_url: str = ""
    # The AI service Settings chose ("openai", "local", ...), when the
    # gateway sent one. Provenance only; the key is held by the store.
    llm_preset: str = ""
    status: str = "requested"
    branch: str = ""
    files: list[str] | None = None
    findings_file: str = ""
    # Provenance only — never the credential itself.
    authenticated: bool = False
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    started_monotonic: float = field(default_factory=time.monotonic)
    finished_at: str | None = None
    commit: str | None = None
    done: int | None = None
    total: int | None = None
    eta_seconds: int | None = None
    message: str = "queued"
    reused: int = 0
    attempts: int = 1
    error: str | None = None
    stats: dict[str, Any] | None = None
    report_path: str | None = None
    markdown_path: str | None = None
    prompt: dict[str, Any] | None = None
    cancel_requested: bool = False
    # A pause is a cancel that ends in "paused" instead of "cancelled".
    pause_requested: bool = False
    paused_at: str | None = None
    # A full commit SHA this run is pinned to (a resume pins the commit its
    # checkpoint was made at). Empty = the branch tip.
    commit_pin: str = ""
    # Re-review only this report's failed files and merge them back
    # in, rather than running the repository again.
    retry: bool = False
    # Live per-file timing, fed by the engine's progress messages and read
    # by the file-by-file progress view. Monotonic seconds, so meaningful
    # only inside the process running the review.
    current_file: str = ""
    current_file_started: float | None = None
    # When each file in flight was announced, so its duration is exact even
    # with REVIEW_PARALLEL > 1, where files overlap.
    file_started: dict[str, float] = field(default_factory=dict)
    # (path, seconds) for every file that finished during THIS run. Not the
    # checkpoint's list: after a resume, restored files took no time here,
    # and treating them as zero-second files would drag every estimate down.
    durations: list[tuple[str, float]] = field(default_factory=list)

    def elapsed(self) -> int:
        return int(time.monotonic() - self.started_monotonic)

    def public(self) -> dict[str, Any]:
        """Status payload (requirement 3): progress, ETA, and a printable line."""
        percent = None
        remaining = None
        if isinstance(self.done, int) and isinstance(self.total, int) and self.total:
            percent = round(100 * self.done / self.total)
            remaining = max(0, self.total - self.done)
        unit = "files" if self.mode == "deep" else "batches"
        if percent is not None:
            eta = (f", ~{self.eta_seconds // 60}m {self.eta_seconds % 60}s left"
                   if self.eta_seconds else "")
            restored = f" (+{self.reused} restored)" if self.reused else ""
            line = (f"{percent}% — {self.done}/{self.total} {unit} done, "
                    f"{remaining} left{eta} ({self.elapsed()}s elapsed)"
                    f"{restored}")
        else:
            line = f"{self.status} — {self.message}"
        payload = {
            "job_id": self.job_id,
            "review_id": self.review_id,
            "status": self.status,
            "repo_url": self.repo_url,
            "branch": self.branch or None,
            "mode": self.mode,
            "provider": self.provider,
            "endpoint": self.base_url or None,
            "ai_service": self.llm_preset or None,
            "model": self.model or None,
            "authenticated": self.authenticated,
            "private_repo": self.authenticated,
            "findings_file": self.findings_file or None,
            "files_scope": self.files,
            "done": self.done,
            "total": self.total,
            "remaining": remaining,
            "percent": percent,
            "elapsed_seconds": self.elapsed(),
            "eta_seconds": self.eta_seconds,
            "restored_units": self.reused,
            "attempts": self.attempts,
            "message": self.message,
            "progress": line,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "finished_at": self.finished_at,
            "commit": self.commit or self.commit_pin or None,
            "restartable": self.status in review_state.RESUMABLE,
            "resumable": self.status in review_state.RESUMABLE,
            "pausable": self.status in ACTIVE and not self.pause_requested,
            "pausing": self.status in ACTIVE and self.pause_requested,
            "paused_at": self.paused_at,
        }
        if self.error:
            payload["error"] = self.error
        if self.stats:
            payload["stats"] = self.stats
        if self.report_path:
            payload["report"] = {"json": self.report_path,
                                 "markdown": self.markdown_path}
        return payload


def pause_marker_fields(job: Job) -> dict[str, Any]:
    """What `<id>.paused.json` keeps for a resume. Never the token."""
    return {"repo_url": job.repo_url, "branch": job.branch, "mode": job.mode,
            "commit": job.commit or job.commit_pin or None,
            "model": job.model, "provider": job.provider,
            "ai_service": job.llm_preset or None,
            "done": job.done, "total": job.total, "reused": job.reused}


class JobStore:
    """Thread-safe job registry with a single-worker execution policy.

    One review runs at a time on purpose: the reviewing model is usually a
    single local LLM, so concurrent reviews would only queue against each
    other (and some local servers return empty responses under concurrency).
    """

    def __init__(self, cfg, max_history: int = 100) -> None:
        self.cfg = cfg
        self._jobs: dict[str, Job] = {}
        self._by_review_id: dict[str, str] = {}
        # Credentials live ONLY here, keyed by job id, and are deleted the
        # moment the clone is done. Never merged into Job.
        self._tokens: dict[str, str] = {}
        # The AI service's API key per job, when Settings chose a service
        # that needs one. Same rules as the clone token: memory only, never
        # serialized, forgotten when the job ends.
        self._llm_keys: dict[str, str] = {}
        self._lock = threading.RLock()
        self._run_lock = threading.Lock()
        self._max_history = max_history

    # ---------------- lookup ----------------

    def get(self, key: str) -> Job | None:
        """Find a job by job_id or by review_id."""
        with self._lock:
            job = self._jobs.get(key)
            if job:
                return job
            job_id = self._by_review_id.get(key)
            return self._jobs.get(job_id) if job_id else None

    def list(self, status: str | None = None, limit: int = 50) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at,
                          reverse=True)
        if status:
            jobs = [j for j in jobs if j.status == status]
        return jobs[:limit]

    def active(self) -> Job | None:
        with self._lock:
            for job in self._jobs.values():
                if job.status in ACTIVE:
                    return job
        return None

    # ---------------- creation ----------------

    def create(self, *, review_id: str, repo_url: str, mode: str,
               provider: str, model: str, system_prompt: str,
               prompt_info: dict[str, Any], branch: str = "",
               files: list[str] | None = None, findings_file: str = "",
               extensions: list[str] | None = None,
               access_token: str = "", base_url: str = "",
               commit: str = "", llm_preset: str = "",
               llm_api_key: str = "") -> Job:
        """Register and start a review. review_id is the idempotency key."""
        with self._lock:
            self._trim()
            job = Job(
                job_id=uuid.uuid4().hex[:12], review_id=review_id,
                repo_url=repo_url, mode=mode, provider=provider, model=model,
                base_url=base_url,
                branch=branch, files=files, findings_file=findings_file,
                authenticated=bool(access_token), prompt=prompt_info,
                commit_pin=commit, llm_preset=llm_preset,
            )
            self._jobs[job.job_id] = job
            self._by_review_id[review_id] = job.job_id
            if access_token:
                self._tokens[job.job_id] = access_token
            if llm_api_key:
                self._llm_keys[job.job_id] = llm_api_key
        self._spawn(job, system_prompt, extensions)
        return job

    def restart(self, job: Job, *, system_prompt: str,
                access_token: str = "",
                extensions: list[str] | None = None) -> Job:
        """Re-run a failed/cancelled review (requirement 4).

        The pipeline finds the checkpoint written before the failure and
        resumes: completed units are reused, only the rest are reviewed.
        """
        with self._lock:
            job.status = "requested"
            job.error = None
            job.message = "restarting — resuming from checkpoint if present"
            job.attempts += 1
            job.cancel_requested = False
            job.pause_requested = False
            job.paused_at = None
            job.done = job.total = job.eta_seconds = None
            job.reused = 0
            job.finished_at = None
            job.started_monotonic = time.monotonic()
            job.updated_at = _now()
            if access_token:
                self._tokens[job.job_id] = access_token
                job.authenticated = True
        self._spawn(job, system_prompt, extensions)
        return job

    def retry_failed(self, *, review_id: str, system_prompt: str,
                     provider: str, model: str = "", base_url: str = "",
                     access_token: str = "",
                     report: dict[str, Any] | None = None) -> Job:
        """Re-review the files a finished report lists as failed.

        Deliberately does NOT require a job in the registry. That registry is
        in memory, so every finished run loses its status record when the API
        restarts while its report survives on disk — and a report with
        failures in it is exactly the thing someone comes back to later.
        """
        report = report or {}
        with self._lock:
            self._trim()
            job = Job(
                job_id=uuid.uuid4().hex[:12], review_id=review_id,
                repo_url=report.get("repo_url", ""),
                mode=report.get("mode", "deep"),
                provider=provider, model=model, base_url=base_url,
                branch=report.get("branch") or "",
                authenticated=bool(access_token),
                retry=True,
                message="re-reviewing the files that failed",
            )
            self._jobs[job.job_id] = job
            self._by_review_id[review_id] = job.job_id
            if access_token:
                self._tokens[job.job_id] = access_token
        self._spawn(job, system_prompt, None)
        return job

    def cancel(self, job: Job) -> bool:
        """Request cancellation; honoured after the unit in flight finishes.

        Stopping between units means the checkpoint on disk is complete, so a
        cancelled review stays restartable.
        """
        with self._lock:
            if job.status not in ACTIVE:
                return False
            job.cancel_requested = True
            job.message = "cancellation requested — stopping after this unit"
            job.updated_at = _now()
        return True

    def pause(self, job: Job) -> bool:
        """Stop a running review so it can be resumed later, even days later.

        In this in-process store the stop lands between units, like cancel,
        so the checkpoint is complete; the status reads "paused" once the
        unit in flight finishes (`pausing` is true until then). A quick
        review has no units to stop between and runs to the end.
        """
        with self._lock:
            if job.status not in ACTIVE or job.pause_requested:
                return False
            job.pause_requested = True
            job.cancel_requested = True
            job.message = "pausing - stopping after this unit"
            job.updated_at = _now()
        return True

    # ---------------- execution ----------------

    def _spawn(self, job: Job, system_prompt: str,
               extensions: list[str] | None) -> None:
        threading.Thread(
            target=self._run, args=(job, system_prompt, extensions),
            daemon=True, name=f"review-{job.job_id}",
        ).start()

    def _update(self, job: Job, **fields) -> None:
        with self._lock:
            for key, value in fields.items():
                setattr(job, key, value)
            job.updated_at = _now()

    def _run(self, job: Job, system_prompt: str,
             extensions: list[str] | None) -> None:
        provider = self.cfg.provider(job.provider)
        token = self._tokens.get(job.job_id, "")
        # One review at a time; a queued one waits here rather than fighting
        # the same local model for tokens.
        with self._run_lock:
            saved = (settings.lm_base_url, settings.lm_api_key,
                     settings.lm_model, settings.max_tokens,
                     settings.temperature, settings.parallel)
            try:
                # Point the shared LLM client at the requested provider —
                # this is what makes cloud vs on-prem a per-request choice.
                # A per-review endpoint (validated in the route) wins, so a
                # caller can aim one run at a specific machine's address.
                settings.lm_base_url = job.base_url or provider.base_url
                settings.lm_api_key = (self._llm_keys.get(job.job_id)
                                       or provider.api_key)
                settings.lm_model = job.model or provider.default_model or ""
                if provider.max_tokens:
                    settings.max_tokens = provider.max_tokens
                if provider.temperature is not None:
                    settings.temperature = provider.temperature
                if provider.parallel:
                    settings.parallel = provider.parallel

                if job.retry:
                    report = retry_failed(
                        f"{job.review_id}.json", system_prompt,
                        github_token=token or None,
                        on_status=lambda status, **f: self._on_status(job, status, **f),
                        on_progress=lambda d, t, m, e: self._on_progress(job, d, t, m, e),
                        should_cancel=lambda: job.cancel_requested,
                    )
                else:
                    report = run_review(
                        job.repo_url, system_prompt, f"{job.review_id}.json",
                        branch=job.branch or None, extensions=extensions,
                        mode=job.mode, files=job.files,
                        findings_file=job.findings_file,
                        github_token=token or None,
                        on_status=lambda status, **f: self._on_status(job, status, **f),
                        on_progress=lambda d, t, m, e: self._on_progress(job, d, t, m, e),
                        should_cancel=lambda: job.cancel_requested,
                        commit=job.commit_pin or None,
                    )
                review_state.clear_paused(settings.output_dir, job.review_id)
                self._update(
                    job, status="completed", finished_at=_now(),
                    message="review complete",
                    stats=report.get("stats"),
                    report_path=report.get("_output_path"),
                    markdown_path=report.get("_markdown_path"),
                    model=settings.lm_model or llm.last_model_used or job.model,
                )
            except ReviewCancelled as exc:
                if job.pause_requested:
                    self._mark_paused(job)
                    return
                self._update(job, status="cancelled", finished_at=_now(),
                             message=str(exc),
                             error="Cancelled by request. Restart to resume "
                                   "from the checkpoint.")
            except RetryError as exc:
                self._update(job, status="failed", finished_at=_now(),
                             message="retry not possible", error=str(exc))
            except (IngestError, LLMUnavailableError, FindingsError) as exc:
                self._update(job, status="failed", finished_at=_now(),
                             message="review failed", error=str(exc))
            except Exception as exc:  # noqa: BLE001 - always end terminal
                self._update(job, status="failed", finished_at=_now(),
                             message="review failed",
                             error=f"unexpected: {exc}")
            finally:
                # Drop the credential the instant the review ends.
                self._tokens.pop(job.job_id, None)
                self._llm_keys.pop(job.job_id, None)
                (settings.lm_base_url, settings.lm_api_key, settings.lm_model,
                 settings.max_tokens, settings.temperature,
                 settings.parallel) = saved

    def _mark_paused(self, job: Job) -> None:
        paused_at = _now()
        self._update(job, status="paused", paused_at=paused_at,
                     finished_at=paused_at,
                     message="paused - resume any time", error=None)
        review_state.write_paused(settings.output_dir, job.review_id,
                                  pause_marker_fields(job))

    def _on_status(self, job: Job, status: str, **fields) -> None:
        updates: dict[str, Any] = {"status": status}
        if status == "cloning":
            updates["message"] = "cloning repository"
        elif status == "reviewing":
            updates["message"] = "reviewing"
        if "commit" in fields:
            updates["commit"] = fields["commit"]
        if "reused" in fields:
            updates["reused"] = fields["reused"]
        self._update(job, **updates)

    def _on_progress(self, job: Job, done: int, total: int | None,
                     message: str, eta: int | None) -> None:
        fields: dict[str, Any] = dict(done=done, total=total,
                                      message=message, eta_seconds=eta)
        now = time.monotonic()
        started = _ACTIVE_FILE.match(message or "")
        finished = _FINISHED_FILE.match(message or "")
        with self._lock:
            if started:
                # Heartbeats for the same file keep its original start time.
                job.file_started.setdefault(started["path"], now)
                if started["path"] != job.current_file:
                    fields.update(current_file=started["path"],
                                  current_file_started=now)
            if finished:
                # Only files this run saw start get a duration. Trivial files
                # (never sent to the model) and restored ones do not.
                began = job.file_started.pop(finished["path"], None)
                if began is not None:
                    job.durations.append((finished["path"], now - began))
        self._update(job, **fields)

    def forget(self, review_id: str) -> bool:
        """Drop a finished or paused review from the registry (it was
        deleted). A running one is refused: stop it first."""
        with self._lock:
            job_id = self._by_review_id.get(review_id)
            job = self._jobs.get(job_id) if job_id else None
            if job is not None and job.status in ACTIVE:
                return False
            self._by_review_id.pop(review_id, None)
            if job_id:
                self._jobs.pop(job_id, None)
                self._tokens.pop(job_id, None)
                self._llm_keys.pop(job_id, None)
            return True

    def _trim(self) -> None:
        """Forget the oldest finished jobs so the registry stays bounded."""
        if len(self._jobs) < self._max_history:
            return
        finished = sorted(
            (j for j in self._jobs.values() if j.status in TERMINAL),
            key=lambda j: j.created_at,
        )
        for job in finished[: max(1, len(self._jobs) - self._max_history + 1)]:
            self._jobs.pop(job.job_id, None)
            if self._by_review_id.get(job.review_id) == job.job_id:
                self._by_review_id.pop(job.review_id, None)
            self._tokens.pop(job.job_id, None)
            self._llm_keys.pop(job.job_id, None)
