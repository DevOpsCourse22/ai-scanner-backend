"""The review runner shared by every front end.

`run_review` owns everything between "a review was requested" and "the
report is on disk": findings intake, clone, file filtering, checkpoint
discovery and resume, progress/ETA, the review itself, fold-in of restored
units, and writing `<name>.json` + `<name>.md`.

Both front ends call it, so the crash-recovery logic exists exactly once:
  - `server.py`   — the MCP tools (LM Studio / Claude Code)
  - `review_api/` — the Flask HTTP control plane

Front ends differ only in how they surface status and progress, which they
supply as callbacks.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from .config import settings
from .findings import load_findings_file, match_to_manifest
from .repo_ingest import IngestError, ingest_repository, validate_repo_url
from .review import (_build_report, merge_retry, render_markdown,
                     review_manifest)

logger = logging.getLogger(__name__)


def _clone_head(clone_dir: Path) -> str:
    """The commit a clone is at, or '' if git cannot say."""
    try:
        out = subprocess.run(["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30,
                             check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _reusable_scan(findings_out: Path, repo_url: str, commit: str) -> str | None:
    """When an earlier run of THIS review already scanned this exact commit,
    the time it did so; otherwise None.

    The deterministic scanners read only the code, so the same commit gives
    the same findings: a resumed review (paused, crashed, restarted) need
    not spend minutes re-running Semgrep, Gitleaks and Trivy. The check is
    strict on purpose — a findings file without the stamp, from another
    repository or from any other commit is scanned again.
    """
    if not commit or not findings_out.is_file():
        return None
    try:
        doc = json.loads(findings_out.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    ctx = doc.get("scan_context") if isinstance(doc, dict) else None
    if (isinstance(ctx, dict) and ctx.get("commit") == commit
            and ctx.get("repo_url") == repo_url):
        return str(ctx.get("scanned_at") or "an earlier run")
    return None


def _scanner_hook(findings_out: Path, meta: dict[str, Any],
                  status: Callable[..., None],
                  repo_url: str = "") -> Callable[[Path], None] | None:
    """Callback that runs the deterministic scanner tier over the clone.

    Returns None when scanning is off or the scanner is not installed, so
    this component keeps working standalone — `repo_scanner` is a separate
    package (the Track 3 scanner tier) and is an optional dependency, not a
    hard one.

    Running it HERE rather than in a caller is deliberate: the repository is
    already cloned at this point, so scanning it costs no second clone and
    puts nobody else's code on disk twice (ADR-001, ephemeral processing).
    """
    if not settings.run_scanner:
        meta["reason"] = "disabled (REVIEW_RUN_SCANNER=0)"
        return None
    try:
        from repo_scanner import scan_repository, write_findings_file
    except ImportError:
        meta["reason"] = ("repo_scanner is not installed "
                          "(pip install ./scanner)")
        return None

    def hook(clone_dir: Path) -> None:
        head = _clone_head(clone_dir)
        scanned_at = _reusable_scan(findings_out, repo_url, head)
        if scanned_at is not None:
            logger.info("reusing the deterministic scan of %s from %s",
                        head[:8], scanned_at)
            status("scanning", scan_reused=True)
            meta["ran"] = True
            meta["reused_from"] = scanned_at
            meta["findings_file"] = findings_out.name
            return
        status("scanning")
        logger.info("scanning %s with the deterministic tier", clone_dir)
        try:
            doc = scan_repository(str(clone_dir))
            if isinstance(doc, dict) and head:
                # Stamped so a resume of this review can tell the scan is
                # for the commit it is about to review (_reusable_scan).
                doc["scan_context"] = {
                    "repo_url": repo_url, "commit": head,
                    "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime())}
            write_findings_file(doc, findings_out)
        except Exception as exc:  # noqa: BLE001 - a scanner must not be fatal
            # The AI review is still worth running without deterministic
            # findings. Recorded, not swallowed: the report says the scan
            # was attempted and why it produced nothing.
            logger.warning("deterministic scan failed: %s", exc)
            meta["reason"] = f"scan failed: {exc}"
            return
        meta["ran"] = True
        meta["findings_file"] = findings_out.name

    return hook


# on_status(status, **fields) — coarse lifecycle transitions.
StatusFn = Callable[..., None]
# on_progress(done, total, message, eta_seconds) — done counts COMPLETED units.
ProgressFn = Callable[[int, int | None, str, int | None], None]


def _write_plan(plan_path: Path, manifest: dict[str, Any], mode: str) -> None:
    """Record which files a review set out to cover, before it starts.

    Written once, never updated: it is the denominator a progress view
    subtracts finished and failed units from. Paths, languages, sizes and
    line counts only — no file contents, so this carries no more than the
    checkpoint already does. Failure here is logged and ignored; losing a
    progress aid must not cost a review that would otherwise have run.
    """
    try:
        data = {
            "plan_version": 1,
            "repo_url": manifest["repo_url"],
            "commit": manifest["commit"],
            "mode": mode,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # `size` (characters) feeds the time estimates; `lines` is for
            # people - "340 lines" is how a reader sizes up a code file. Both
            # are counts of the content, never the content itself.
            "files": [{"path": f["path"],
                       "language": f.get("language", "unknown"),
                       "size": len(f.get("content") or ""),
                       "lines": len((f.get("content") or "").splitlines())}
                      for f in manifest["files"]],
        }
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = plan_path.with_suffix(".plan.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(plan_path)  # atomic: never a half-written plan
    except OSError as exc:
        logger.warning("could not write review plan %s: %s", plan_path, exc)


def _resolve_output(path: str) -> Path:
    """Resolve output paths against REVIEW_OUTPUT_DIR.

    Inside the Docker image REVIEW_OUTPUT_DIR=/reports (the mounted volume),
    so callers can pass just "report.json" and find it on the host. Hosts on
    Windows often pass paths like "C:\\reports\\r.json"; inside a Linux
    container that is NOT absolute and would create a garbage filename, so
    Windows-style paths are reduced to their basename under the output dir.
    """
    raw = (path or "report.json").strip()
    if settings.output_dir:
        if re.match(r"^[A-Za-z]:[\\/]", raw) or "\\" in raw:
            raw = re.split(r"[\\/]+", raw)[-1] or "report.json"
        p = Path(raw)
        if not p.is_absolute():
            p = Path(settings.output_dir) / p
        return p
    return Path(raw)


def _match_files(manifest: dict, wanted: list[str]) -> dict:
    """Keep only manifest files matching the wanted paths/globs.

    A pattern matches on the full repo-relative path or the bare filename,
    so "views.py", "DjangoWebApp/src/voter/views.py" and "*/voter/*" all work.
    """
    kept = []
    for entry in manifest["files"]:
        path = entry["path"]
        name = path.rsplit("/", 1)[-1]
        if any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(name, pat)
               for pat in wanted):
            kept.append(entry)
    manifest = dict(manifest)
    manifest["files"] = kept
    manifest["file_count"] = len(kept)
    return manifest


def run_review(
    repo_url: str,
    system_prompt: str,
    output_path: str,
    *,
    branch: str | None = None,
    extensions: list[str] | None = None,
    mode: str = "brief",
    files: list[str] | None = None,
    findings_file: str = "",
    github_token: str | None = None,
    on_status: StatusFn | None = None,
    on_progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """Run one review to completion and return the finished report.

    Raises IngestError / LLMUnavailableError / FindingsError on failure; the
    caller decides how to record that. github_token authenticates a private
    clone for THIS review only and is never persisted or logged.

    commit pins the review to one exact commit (a resumed review passes the
    commit its checkpoint was made at, so the checkpoint still matches after
    the branch has moved on). None reviews the branch tip, as before.
    """
    status = on_status or (lambda *a, **k: None)
    job_start = time.monotonic()

    # Deterministic findings arrive from outside (the scanner component).
    # Load them first: a review asked to enrich findings must fail loudly if
    # they cannot be read, never silently run without them.
    static_map: dict[str, list[dict[str, Any]]] = {}
    findings_meta: dict[str, Any] | None = None
    if findings_file:
        static_map, findings_meta = load_findings_file(
            _resolve_output(findings_file))

    status("cloning")
    # Deterministic scan of the clone, while the clone exists. Skipped when
    # the caller supplied findings of their own: an explicit findings_file
    # is an override, not something to race with.
    scan_out = _resolve_output(output_path).with_suffix(".findings.json")
    scan_meta: dict[str, Any] = {}
    on_clone = (None if findings_file
                else _scanner_hook(scan_out, scan_meta, status,
                                 validate_repo_url(repo_url)))

    # Both kwargs are passed ALWAYS, even when None. Passing them only
    # sometimes is what let `token=` sit here for months against an
    # ingest_repository that had no such parameter: public reviews never
    # sent it, so nothing failed until a private one did.
    manifest = ingest_repository(
        repo_url, branch, extensions,
        token=github_token,
        on_clone=on_clone,
        commit=commit or None,
    )
    if scan_meta.get("ran") and scan_out.is_file():
        static_map, findings_meta = load_findings_file(scan_out)
    if files:
        all_paths = [f["path"] for f in manifest["files"]]
        manifest = _match_files(manifest, files)
        if manifest["file_count"] == 0:
            raise IngestError(
                f"No files matched {files!r}. Repo contains e.g.: "
                + ", ".join(all_paths[:20])
            )
    if manifest["file_count"] == 0:
        raise IngestError(
            "No reviewable code files found (check extensions filter).")
    if static_map:
        # Findings for paths outside the reviewed set are recorded in the
        # meta (never silently dropped); the rest feed the prompts.
        static_map = match_to_manifest(
            static_map, [f["path"] for f in manifest["files"]], findings_meta)

    # --- Self-healing: crash checkpoint + resume (deep + brief) ------------
    # Deep reviews checkpoint after every completed FILE, brief reviews after
    # every completed BATCH, both to <name>.partial.json. A crash (OOM kill,
    # host restart) loses at most the unit in flight. Re-running with the
    # same output name and mode resumes: units already in the checkpoint
    # (same repo+commit+mode) are not re-reviewed.
    out = _resolve_output(output_path)
    ckpt_path = out.with_suffix(".partial.json")
    preloaded: dict[str, dict] = {}
    brief_preloaded: dict = {}
    brief_total = None
    full_manifest = manifest

    # The set of files this review INTENDS to cover, written once up front.
    # The checkpoint only ever lists units already finished or failed, so
    # without this there is no way to name what is still pending while a
    # review runs — only to count it. Paths only, never file contents: this
    # exists to answer "what is left", not to be a second copy of the repo.
    # Best-effort by design: an unwritable plan file must never fail a review.
    _write_plan(out.with_suffix(".plan.json"), full_manifest, mode)
    if mode in ("deep", "brief") and ckpt_path.is_file():
        try:
            ckpt = json.loads(ckpt_path.read_text(encoding="utf-8"))
            if (ckpt.get("repo_url") == manifest["repo_url"]
                    and ckpt.get("commit") == manifest["commit"]
                    and ckpt.get("mode") == mode):
                if mode == "deep":
                    preloaded = {r["file"]: r for r in ckpt.get("reviews", [])}
                else:
                    brief_preloaded = ckpt.get("batch_results") or {}
                    brief_total = ckpt.get("progress", {}).get("total")
        except (json.JSONDecodeError, OSError):
            pass  # unreadable checkpoint: start fresh
    if preloaded:
        remaining_files = [f for f in manifest["files"]
                           if f["path"] not in preloaded]
        manifest = dict(manifest)
        manifest["files"] = remaining_files
        manifest["file_count"] = len(remaining_files)
        status("reviewing", reused=len(preloaded))
    if brief_preloaded:
        status("reviewing", reused=len(brief_preloaded))

    def merged_reviews(new_reviews: list) -> list:
        """Preloaded + new reviews, in original manifest order."""
        new_by_path = {r["file"]: r for r in new_reviews}
        return [preloaded.get(f["path"]) or new_by_path[f["path"]]
                for f in full_manifest["files"]
                if f["path"] in preloaded or f["path"] in new_by_path]

    def _write_ckpt(extra: dict) -> None:
        data = {
            "checkpoint_version": 1,
            "repo_url": full_manifest["repo_url"],
            "commit": full_manifest["commit"],
            "mode": mode,
            "system_prompt": system_prompt,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **extra,
        }
        ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = ckpt_path.with_suffix(".partial.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ckpt_path)  # atomic: never a half-written checkpoint

    def write_checkpoint(new_reviews: list, new_failures: list) -> None:
        _write_ckpt({
            "progress": {
                "done": len(preloaded) + len(new_reviews),
                "total": full_manifest["file_count"],
                "resume_hint": "start the same review_id/output_path and "
                               "mode again to continue",
            },
            "reviews": merged_reviews(new_reviews),
            "failures": new_failures,
        })
        if should_cancel and should_cancel():
            # Cancellation lands between units, so the checkpoint just
            # written is complete and the run stays resumable.
            raise ReviewCancelled("cancelled after a completed unit")

    def write_brief_checkpoint(batch_results: dict, total: int) -> None:
        _write_ckpt({
            "progress": {
                "done": len(batch_results),
                "total": total,
                "resume_hint": "start the same review_id/output_path and "
                               "mode brief again to continue",
            },
            "batch_results": batch_results,
        })
        if should_cancel and should_cancel():
            raise ReviewCancelled("cancelled after a completed batch")
    # ---------------------------------------------------------------------

    # total is left unset here: brief counts BATCHES, deep counts FILES, so
    # the real total arrives with the first progress callback.
    status("reviewing", commit=manifest["commit"])

    # Stable ETA: recompute only when the completed count actually advances,
    # so it holds steady instead of ballooning while one slow unit generates.
    eta_state: dict[str, Any] = {"done": 0, "eta": None}

    def progress(index: int, total: int, message: str) -> None:
        if on_progress is None:
            return
        if isinstance(index, int) and isinstance(total, int) and total > 0:
            if index > eta_state["done"]:
                eta_state["done"] = index
                elapsed = time.monotonic() - job_start
                remaining = max(0, total - index)
                eta_state["eta"] = (int(elapsed / index * remaining)
                                    if index > 0 and remaining > 0 else 0)
        on_progress(index, total, message, eta_state["eta"])

    ckpt_kwargs: dict[str, Any] = {}
    if mode == "deep":
        ckpt_kwargs["checkpoint_cb"] = write_checkpoint
    elif mode == "brief":
        ckpt_kwargs["brief_state"] = {
            "preloaded": brief_preloaded,
            "total": brief_total,
            "checkpoint": write_brief_checkpoint,
        }
    if static_map:
        ckpt_kwargs["static_map"] = static_map

    report = review_manifest(manifest, system_prompt, progress, mode,
                             **ckpt_kwargs)

    if preloaded:
        # Fold checkpointed reviews back in and recompute stats over the FULL
        # file set, so the final report looks like one clean run.
        combined = merged_reviews(report["reviews"])
        report = _build_report(full_manifest, combined, report["failures"])
        report["mode"] = mode
        report["resumed"] = True
        report["reused_reviews"] = len(preloaded)
    if findings_meta is not None:
        report["deterministic"] = findings_meta

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    markdown = out.with_suffix(".md")
    markdown.write_text(render_markdown(report), encoding="utf-8")
    ckpt_path.unlink(missing_ok=True)  # final report replaces the checkpoint
    # The plan is KEPT. It once looked redundant with the report, but it is
    # the only record of each file's size and line count: delete it and a
    # finished review's progress view loses them - which is the view people
    # actually look at. Deleted together with its report (DELETE
    # /api/v1/reports/<name>), never left orphaned.

    report["_output_path"] = str(out)
    report["_markdown_path"] = str(markdown)
    return report


class ReviewCancelled(RuntimeError):
    """Raised inside a checkpoint callback when a cancel was requested.

    Cancellation is only ever observed just after a unit completed and its
    checkpoint was written, so a cancelled review is always resumable.
    """


def _branch_of(report: dict[str, Any]) -> str | None:
    """The branch to re-clone, or None to take the repository's default."""
    branch = (report.get("branch") or "").strip()
    return None if branch in ("", "default") else branch


class RetryError(RuntimeError):
    """Raised when a retry cannot be attempted (no report, or nothing failed)."""


def retry_failed(
    output_path: str,
    system_prompt: str,
    *,
    github_token: str | None = None,
    on_status: StatusFn | None = None,
    on_progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Re-review only the files that failed, merged into the SAME report.

    `restart` resumes a run that failed; this tops up a run that COMPLETED
    with gaps — a different thing, and the common one. A deep run typically
    ends with a fraction of files carrying
    "Model failed to return valid JSON", which says nothing about the code
    and everything about the response format.

    The merged report replaces the original in place, so a consumer holding
    the review id keeps seeing one report rather than accumulating partials.
    Idempotent: a second call with nothing left to retry is a no-op that
    returns the report unchanged.
    """
    report_path = _resolve_output(output_path)
    if not report_path.is_file():
        raise RetryError(
            f"No report at {report_path.name} to retry. Run the review first."
        )
    existing = json.loads(report_path.read_text(encoding="utf-8"))
    failed = [f["file"] for f in existing.get("failures", []) if f.get("file")]
    if not failed:
        return existing                      # nothing to do, and that is fine

    status = on_status or (lambda *a, **k: None)
    status("retrying", files=len(failed))

    # Scoped re-review into a scratch report, so a crash mid-retry cannot
    # leave the original truncated. Only a successful run gets merged.
    scratch = f"{report_path.stem}.retry.json"
    retry_report = run_review(
        existing.get("repo_url", ""),
        system_prompt,
        scratch,
        # A report records branch as "default" when none was requested —
        # that is a label for humans, not a git ref, and handing it back to
        # git produces `Remote branch default not found in upstream origin`.
        branch=_branch_of(existing),
        mode=existing.get("mode", "deep"),
        files=failed,
        github_token=github_token,
        on_status=lambda *a, **k: None,      # the retry's own lifecycle is internal
        on_progress=on_progress,
        should_cancel=should_cancel,
    )

    merged = merge_retry(existing, retry_report)
    report_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    report_path.with_suffix(".md").write_text(render_markdown(merged),
                                              encoding="utf-8")
    # Everything the scratch run wrote, not just its report: its plan (kept
    # after a normal review, so run_review no longer removes it) and its
    # scanner findings would otherwise accumulate as orphans on the volume.
    scratch_out = _resolve_output(scratch)
    for suffix in ("", ".md", ".plan.json", ".findings.json"):
        (scratch_out.with_suffix(suffix) if suffix else scratch_out).unlink(
            missing_ok=True)
    status("completed", **merged["retried"])
    return merged
