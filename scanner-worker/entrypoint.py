"""scanner-worker — one review, run to completion as a Kubernetes Job.

A thin wrapper around `code_review_mcp.pipeline.run_review()`. Everything a
review does (clone, deterministic scan, AI enrichment, checkpoint + resume,
writing the reports) already lives there; this file only turns the Job's
environment into arguments and the outcome into an exit code.

The interface is docs/job-container-contract.md:

  in   REPO_URL, REVIEW_ID, MODE, LMSTUDIO_BASE_URL, SYSTEM_PROMPT (required)
       BRANCH, GITHUB_TOKEN (or GITHUB_TOKEN_FILE), LMSTUDIO_MODEL,
       COMMIT (optional; v3 - pins a resumed review to its checkpoint's commit)
       LLM_API_KEY (optional; v4 - the AI service's key from Settings)
  out  /reports/<REVIEW_ID>.json / .md / .partial.json / .findings.json
       /reports/<REVIEW_ID>.error.json     why an attempt failed
       /reports/<REVIEW_ID>.progress.json  liveness in every mode, plus
                                           per-file timing in deep mode
  exit 0  the pipeline completed (findings in the code are a SUCCESS)
       1  technical failure worth retrying: LLM unreachable, network,
          timeout, anything unexpected
       2  permanent failure a retry cannot fix: bad input, bad URL, no
          access (wrong or missing token), branch not found

The reason for a non-zero exit is also written as one line to
/dev/termination-log, where Kubernetes copies it into the Pod status
(`kubectl get pod -o jsonpath='{..terminated.message}'`), so review-api
can show WHY without reading logs — for a human with kubectl. review-api
reads the same line from <REVIEW_ID>.error.json on the PVC instead, because
reading Pod status would need `list` on pods, which RBAC cannot narrow to
our Jobs' Pods (contract v2, "error.json").

The token is never logged: it is removed from the environment before the
engine is imported (so no child process — Semgrep, Trivy, Gitleaks — ever
inherits it), handed to run_review() as an argument, and scrubbed from
every log line and error message this process writes.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

EXIT_OK = 0
EXIT_RETRYABLE = 1
EXIT_PERMANENT = 2

MODES = ("quick", "brief", "deep")

# REVIEW_ID names files on a shared volume, so it must be a plain file name:
# no slashes, no leading dot, nothing a shell or a path join could misread.
# review-api's _sanitize_id already produces ids of this shape.
_REVIEW_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")

# COMMIT is a full SHA or nothing - the engine refuses anything else too,
# but bad input is a permanent failure and is cheapest to report up front.
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Kubernetes reads at most 4096 bytes from the termination log.
_TERMINATION_LIMIT = 4000

# git's own words for "this will never work, however often you retry".
# Checked AFTER the transient markers below, because a timeout message can
# quote output that happens to contain one of these.
_PERMANENT_MARKERS = (
    "not a valid github repository url",
    "ssh urls are not supported",
    "do not put credentials in the repository url",
    "no reviewable code files",
    "repository not found",
    "remote branch",                 # "Remote branch X not found in upstream"
    "authentication failed",
    "invalid username",
    "could not read username",
    "could not read password",
    "terminal prompts disabled",
    "403",
)
# ...and for "the network or the other side had a bad moment".
_TRANSIENT_MARKERS = (
    "timed out",
    "could not resolve host",
    "failed to connect",
    "connection reset",
    "connection refused",
    "early eof",
    "rpc failed",
    "502", "503", "504",
)

# The engine's per-file progress messages (deep mode): "<path>: reviewing"
# as a file starts, heartbeats "<path>: thinking|answering (...)", and
# "<path> done (n/N)" when it finishes. The SAME patterns as review_api's
# jobs.py uses in process, so a file is timed identically in both modes —
# tests/test_worker_progress.py fails if the two drift apart.
_ACTIVE_FILE = re.compile(r"^(?P<path>.+?): (?:reviewing|thinking|answering)\b")
_FINISHED_FILE = re.compile(r"^(?P<path>.+) done \(\d+/\d+\)$")

# Between file starts and finishes, progress.json is still rewritten at
# most this often while the review keeps making progress (any status change,
# any streamed-token heartbeat). Its `updated_at` is how review-api tells a
# slow review from a stuck one (contract v2, "stuck detection"), so it must
# move in quick and brief modes too, where no file ever "starts". Throttled
# so a long review writes to the PVC once a minute, not every 3 seconds.
HEARTBEAT_WRITE_SECONDS = float(
    os.getenv("REVIEW_PROGRESS_HEARTBEAT_SECONDS", "60"))

# Phases that report no progress of their own but are each bounded by a
# timeout: the clone (git is killed after 300 s, repo_ingest._run_git) and
# the deterministic scanners (900 s EACH, run one after another, so up to
# 45 minutes). With stuck detection at 15 minutes of silence, a large repo
# whose scan legitimately ran longer was killed as stuck on every attempt
# and could never get past scanning. While the review is in one of these
# phases a ticker keeps `updated_at` moving - safe precisely because each
# step has its own limit, so "alive" here cannot mean "alive forever".
#
# Deliberately NOT the AI phase. There every streamed token already
# refreshes the file, and a model that stops answering MUST be allowed to go
# stale: that is exactly the hang stuck detection exists to catch.
BOUNDED_SILENT_PHASES = frozenset({"cloning", "scanning"})

log = logging.getLogger("scanner-worker")


def write_json_atomic(path: Path, data: dict) -> None:
    """Temp file + rename, like the checkpoint: a reader never sees half a
    file. The temp name ends in .tmp, so no *.json listing ever picks it up."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


class ProgressFile:
    """<REVIEW_ID>.progress.json: which file is running, and how long each
    finished one took — the live timing review-api cannot get from a Pod.

    Since contract v3 it also carries the review's phase (cloning, scanning,
    reviewing), its unit counts (done/total, plus units restored from the
    checkpoint) and the commit being reviewed. In kubernetes mode this file
    is the ONLY way review-api learns any of that, so the progress bar and
    a later resume (which pins this commit) depend on it.

    Written when a file STARTS and when it FINISHES, and otherwise at most
    every HEARTBEAT_WRITE_SECONDS while anything happens (`touch`), so that
    `updated_at` proves the review is alive in every mode. Wall-clock epoch
    seconds, because a monotonic clock does not carry between Pods. `durations` holds only files finished in THIS attempt: a
    retry is a new process and starts empty, so files restored from the
    checkpoint never enter the estimate. Paths and seconds only.

    Best effort: losing a progress aid must never cost a review, so a
    failed write is logged and the review goes on.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.current = ""
        self.current_started: float | None = None
        self.started: dict[str, float] = {}      # files in flight
        self.durations: list[list] = []
        self.phase = "starting"
        self.done: int | None = None
        self.total: int | None = None
        self.reused = 0
        self.commit: str | None = None
        self.eta: int | None = None
        self.last_write = 0.0
        # The keep-alive ticker writes from its own thread, and every write
        # goes through the same temp file name: unguarded, one writer could
        # rename the other's half-written temp file into place.
        self._lock = threading.Lock()
        self.write()

    def on_message(self, message: str) -> None:
        now = time.time()
        started = _ACTIVE_FILE.match(message or "")
        finished = _FINISHED_FILE.match(message or "")
        wrote = False
        if started and started["path"] not in self.started:
            # First sight of this file; its heartbeats change nothing.
            self.started[started["path"]] = now
            self.current, self.current_started = started["path"], now
            self.write()
            wrote = True
        if finished:
            began = self.started.pop(finished["path"], None)
            if began is not None:   # trivial and restored files never started
                self.durations.append([finished["path"],
                                       round(now - began, 3)])
                self.write()
                wrote = True
        if not wrote:
            # A heartbeat, a batch, a phase: nothing new to record, but the
            # review is demonstrably moving.
            self.touch(now)

    def on_status(self, status: str, **fields) -> None:
        """A phase change from the pipeline. Written at once: phases change
        a handful of times per review, and each one moves the progress bar."""
        changed = status != self.phase
        self.phase = status
        if fields.get("commit"):
            changed = changed or fields["commit"] != self.commit
            self.commit = str(fields["commit"])
        if isinstance(fields.get("reused"), int):
            changed = changed or fields["reused"] != self.reused
            self.reused = fields["reused"]
        if changed:
            self.write()
        else:
            self.touch()

    def on_counts(self, done: int | None, total: int | None,
                  eta: int | None) -> None:
        """Unit counts from the pipeline's progress callback. A finished unit
        (done moved) is written at once; anything else waits for the next
        write, so streamed-token heartbeats do not rewrite the file."""
        moved = done != self.done or total != self.total
        self.done, self.total, self.eta = done, total, eta
        if moved:
            self.write()

    def touch(self, now: float | None = None) -> None:
        """Refresh `updated_at` if the last write is older than the
        heartbeat interval. Called on every sign of life."""
        now = time.time() if now is None else now
        if now - self.last_write >= HEARTBEAT_WRITE_SECONDS:
            self.write()

    def write(self) -> None:
        with self._lock:
            self.last_write = updated_at = time.time()
            try:
                write_json_atomic(self.path, {
                    "current_file": self.current,
                    "current_started_at": self.current_started,
                    "durations": list(self.durations),
                    "phase": self.phase,
                    "done": self.done,
                    "total": self.total,
                    "reused": self.reused,
                    "commit": self.commit,
                    "eta_seconds": self.eta,
                    "updated_at": updated_at,
                })
            except OSError as exc:
                log.warning("could not write %s: %s", self.path.name, exc)


class PhaseKeepAlive:
    """Keeps progress.json fresh through BOUNDED_SILENT_PHASES only.

    Started by the status that enters such a phase, stopped by the first
    status that leaves it (or when the review ends). One daemon thread,
    touching the file every `interval` seconds.
    """

    def __init__(self, progress: "ProgressFile",
                 interval: float | None = None) -> None:
        self._progress = progress
        # Read at construction, not as a default argument - a default is
        # evaluated once, at import, and would ignore the setting after it.
        self._interval = HEARTBEAT_WRITE_SECONDS if interval is None else interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def on_status(self, status: str) -> None:
        if status in BOUNDED_SILENT_PHASES:
            self._start()
        else:
            self.stop()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _start(self) -> None:
        if self.running:
            return  # cloning -> scanning: one ticker covers both
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="progress-keepalive")
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            self._progress.touch()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


class InputError(ValueError):
    """The Job was given inputs no retry can fix."""


class Terminated(BaseException):
    """SIGTERM: the Pod is being deleted or hit activeDeadlineSeconds.

    BaseException, like KeyboardInterrupt, on purpose: the engine catches
    `Exception` in places where one unit failing must not stop the rest
    (the scanner hook, per-file reviews). A shutdown must not be one of
    the things those handlers swallow and carry on after.
    """


@dataclass
class Inputs:
    repo_url: str
    review_id: str
    mode: str
    branch: str | None
    system_prompt: str
    lmstudio_base_url: str
    token: str
    commit: str | None = None


def take_token(env: dict[str, str]) -> str:
    """Read the clone token and REMOVE it from `env`.

    Removed rather than read: the engine's settings read GITHUB_TOKEN at
    import time, and every scanner is a child process that inherits the
    environment. Taking it out here means the only copy is the one this
    function returns, which goes to run_review() and nowhere else.

    GITHUB_TOKEN_FILE is the form review-api uses (contract v5): removing a
    variable from os.environ does NOT remove it from /proc/self/environ,
    which keeps the environment the process started with and which anything
    running as this user can read. A file read and then deleted leaves no
    copy behind. GITHUB_TOKEN still works for a plain `docker run`.
    GH_TOKEN is dropped too, for the same reason.
    """
    token = (env.pop("GITHUB_TOKEN", "") or "").strip()
    env.pop("GH_TOKEN", None)
    from_file = _take_secret_file(env, "GITHUB_TOKEN_FILE")
    return token or from_file


def take_llm_key(env: dict[str, str]) -> str:
    """Read the AI service's API key (contract v4) and REMOVE it from `env`,
    for the same reason as the clone token: no scanner child process may
    inherit it. LLM_API_KEY_FILE is the file form, read and deleted like
    GITHUB_TOKEN_FILE. LMSTUDIO_API_KEY is left alone; it is the server
    default the engine falls back to when Settings chose no key."""
    key = (env.pop("LLM_API_KEY", "") or "").strip()
    from_file = _take_secret_file(env, "LLM_API_KEY_FILE")
    return key or from_file


def _take_secret_file(env: dict[str, str], name: str) -> str:
    """The secret in the file `env[name]` names; the variable is removed and
    the file deleted once read, so nothing started after this (Semgrep,
    Trivy, Gitleaks, anything in the repository they run) can read it.

    The file lives on an in-memory emptyDir the Job copies the Secret into
    (k8s_jobs.build_job_manifest). A file that cannot be deleted - a Secret
    mounted read-only, say - is still used, with a warning.
    """
    path = env.pop(name, "")
    if not path:
        return ""
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        # Names the file, never its content.
        raise InputError(f"{name} is set but unreadable: "
                         f"{path} ({exc.strerror})") from None
    try:
        Path(path).unlink()
    except OSError as exc:
        log.warning("%s could not be deleted after reading: %s (%s)",
                    name, path, exc.strerror)
    return value


def read_inputs(env: dict[str, str], token: str) -> Inputs:
    """Validate the contract's inputs; report EVERY problem at once."""
    get = lambda name: (env.get(name) or "").strip()  # noqa: E731
    problems = [f"{name} is required" for name in
                ("REPO_URL", "REVIEW_ID", "MODE", "LMSTUDIO_BASE_URL",
                 "SYSTEM_PROMPT") if not get(name)]
    review_id, mode = get("REVIEW_ID"), get("MODE").lower()
    if review_id and not _REVIEW_ID_RE.match(review_id):
        problems.append(f"REVIEW_ID {review_id!r} is not a plain file name "
                        "(letters, digits, '_', '.', '-'; max 128)")
    if mode and mode not in MODES:
        problems.append(f"MODE {mode!r} is not one of {', '.join(MODES)}")
    commit = get("COMMIT")
    if commit and not _COMMIT_RE.match(commit):
        problems.append(f"COMMIT {commit!r} is not a full 40-character SHA")
    if problems:
        raise InputError("; ".join(problems))
    return Inputs(
        repo_url=get("REPO_URL"),
        review_id=review_id,
        mode=mode,
        branch=get("BRANCH") or None,
        # Not stripped: a prompt is text, and its whitespace is the author's.
        system_prompt=env["SYSTEM_PROMPT"],
        lmstudio_base_url=get("LMSTUDIO_BASE_URL"),
        token=token,
        commit=commit.lower() or None,
    )


def prepare_dirs(env: dict[str, str]) -> Path:
    """Create the writable directories on the mounted volumes.

    The root filesystem is read-only, so HOME, TMPDIR and the scanners'
    caches all point into /workspace (an emptyDir that starts EMPTY on
    every Pod — which is why they are created here and not in the image).
    Returns the reports directory, checked writable: a missing or
    read-only PVC should fail in the first second, not after the review.
    """
    for name in ("TMPDIR", "HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
                 "TRIVY_CACHE_DIR"):
        if env.get(name):
            try:
                Path(env[name]).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise InputError(f"{name}={env[name]} is not writable "
                                 f"({exc.strerror}). Is /workspace mounted "
                                 "as a writable emptyDir?") from None
    reports = Path(env.get("REVIEW_OUTPUT_DIR") or "/reports")
    probe = reports / f".write-probe-{os.getpid()}"
    try:
        reports.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        raise InputError(f"reports directory {reports} is not writable "
                         f"({exc.strerror}). Is the reports PVC mounted?"
                         ) from None
    return reports


def classify(exc: BaseException) -> int:
    """Exit code for a failure: 2 when retrying cannot help, else 1.

    Unknown means retryable. The backend caps retries (5 attempts), so a
    wrong guess in that direction costs a few wasted attempts; a wrong
    guess the other way abandons a review that would have succeeded.
    """
    if isinstance(exc, InputError):
        return EXIT_PERMANENT
    # Imported here, not at module top: see main() for why the engine must
    # not be imported before the token has left the environment.
    try:
        from code_review_mcp.repo_ingest import IngestError
    except ImportError:              # a broken image: rebuilding may fix it
        return EXIT_RETRYABLE
    if isinstance(exc, IngestError):
        text = str(exc).lower()
        if any(m in text for m in _TRANSIENT_MARKERS):
            return EXIT_RETRYABLE
        if any(m in text for m in _PERMANENT_MARKERS):
            return EXIT_PERMANENT
    return EXIT_RETRYABLE


def redact(text: str, *secrets: str) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


class _RedactFilter(logging.Filter):
    """Last line of defence: no log record leaves with the token in it."""

    def __init__(self, *secrets: str) -> None:
        super().__init__()
        self.secrets = [s for s in secrets if s]

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if any(secret in message for secret in self.secrets):
            record.msg, record.args = redact(message, *self.secrets), None
        return True


def one_line(message: str) -> str:
    """The failure reason as the ONE line both the Pod status and
    <REVIEW_ID>.error.json carry: git's multi-line output collapsed, and
    capped at what Kubernetes reads from a termination log."""
    return " ".join(message.split())[:_TERMINATION_LIMIT]


def write_termination(line: str) -> None:
    """One line for the Pod status. Best effort: outside Kubernetes the
    file does not exist and /dev is not writable, which is fine."""
    path = os.getenv("TERMINATION_LOG", "/dev/termination-log")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def _on_sigterm(signum, frame):  # noqa: ARG001 - signal handler signature
    raise Terminated("received SIGTERM (Pod deleted or deadline reached)")


def main(env: dict[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGTERM, _on_sigterm)

    token = llm_key = ""
    error_file: Path | None = None       # known once inputs are valid
    progress_file: Path | None = None
    try:
        # FIRST, before anything imports the engine: its settings object
        # reads GITHUB_TOKEN from the environment at import time.
        token = take_token(env)
        llm_key = take_llm_key(env)
        # The filter goes on the root HANDLERS, not a logger: filters on a
        # logger do not apply to records propagated from child loggers.
        for handler in logging.getLogger().handlers:
            handler.addFilter(_RedactFilter(token, llm_key))
        inputs = read_inputs(env, token)
        reports = prepare_dirs(env)
        env.setdefault("REVIEW_OUTPUT_DIR", str(reports))
        # A previous attempt's error must not outlive this attempt: if this
        # one dies without writing its own (an OOM kill), review-api would
        # otherwise read the old reason and maybe stop a retryable review.
        error_file = reports / f"{inputs.review_id}.error.json"
        error_file.unlink(missing_ok=True)
        progress_file = reports / f"{inputs.review_id}.progress.json"
        progress = ProgressFile(progress_file)

        from code_review_mcp.pipeline import run_review
        if llm_key:
            from code_review_mcp.config import settings as engine_settings
            engine_settings.lm_api_key = llm_key

        log.info("review %s: %s (mode %s, branch %s, commit %s, token %s)",
                 inputs.review_id, inputs.repo_url, inputs.mode,
                 inputs.branch or "default", inputs.commit or "tip",
                 "supplied" if token else "none")
        if llm_key:
            log.info("AI service key: supplied")

        keepalive = PhaseKeepAlive(progress)

        def on_status(status, **fields):
            log.info("status: %s %s", status,
                     " ".join(f"{k}={v}" for k, v in fields.items()))
            progress.on_status(status, **fields)
            keepalive.on_status(status)

        def on_progress(done, total, message, eta):
            log.info("progress %s/%s eta=%ss %s", done, total or "?",
                     eta if eta is not None else "?", message)
            progress.on_counts(done, total, eta)
            progress.on_message(message)

        try:
            report = run_review(
                inputs.repo_url, inputs.system_prompt,
                f"{inputs.review_id}.json",
                branch=inputs.branch, mode=inputs.mode,
                github_token=token or None,
                on_status=on_status, on_progress=on_progress,
                commit=inputs.commit,
            )
        finally:
            # Whatever ends the review - success, error, SIGTERM - the ticker
            # must not outlive it and keep a finished attempt looking alive.
            keepalive.stop()
        out = Path(report.get("_output_path")
                   or reports / f"{inputs.review_id}.json")
        if not out.is_file():
            # review-api treats a missing report after exit 0 as a failure
            # anyway; say so here, where the reason is still known.
            raise RuntimeError(f"run_review returned but {out} is missing")
        # Done: the report replaces both, as it replaces the checkpoint.
        progress_file.unlink(missing_ok=True)
        error_file.unlink(missing_ok=True)
        failures = len(report.get("failures") or [])
        log.info("review %s completed: %s (%d unit(s) failed inside the "
                 "review)", inputs.review_id, out, failures)
        return EXIT_OK
    except (Exception, Terminated, KeyboardInterrupt) as exc:  # noqa: BLE001
        # Every path out of this process must be exit 0, 1 or 2.
        code = (EXIT_RETRYABLE if isinstance(exc, (Terminated,
                                                   KeyboardInterrupt))
                else classify(exc))
        kind = "permanent" if code == EXIT_PERMANENT else "retryable"
        message = redact(f"{kind}: {type(exc).__name__}: {exc}", token, llm_key)
        if _is_expected(exc):
            log.error("%s", message)
        else:
            # A surprise deserves its stack trace in the Pod log. Formatted
            # and redacted here, because the handler filter only sees the
            # message, not the traceback text logging appends to it.
            log.error("%s\n%s", message,
                      redact(traceback.format_exc(), token, llm_key))
        line = one_line(message)
        write_termination(line)
        if error_file is not None:
            try:
                write_json_atomic(error_file, {
                    "permanent": code == EXIT_PERMANENT, "error": line})
            except OSError as err:
                log.warning("could not write %s: %s", error_file.name, err)
        return code


def _is_expected(exc: BaseException) -> bool:
    """Failures whose message already says everything; no traceback."""
    if isinstance(exc, (InputError, Terminated, KeyboardInterrupt)):
        return True
    try:
        from code_review_mcp.llm import LLMUnavailableError
        from code_review_mcp.repo_ingest import IngestError
    except ImportError:
        return False
    return isinstance(exc, (IngestError, LLMUnavailableError))


if __name__ == "__main__":
    sys.exit(main())
