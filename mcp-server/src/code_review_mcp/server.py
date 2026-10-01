"""Stage 4 + orchestration: the MCP server.

Tools exposed:
- start_review      : kick off a review in the background, returns a job id
                      immediately (built for hosts with short tool timeouts,
                      e.g. LM Studio's 60s default)
- get_review_status : poll a background job; fast, never times out
- review_repository : same pipeline as one blocking call (for hosts with
                      long/resettable timeouts, e.g. Claude Code)
- ingest_repository_only : stage 1 only, useful for testing without the LLM
- check_llm         : connectivity/sanity check against LM Studio

Runs over stdio, so any MCP host (LM Studio, Claude Code, Claude Desktop,
MCP Inspector) can launch it as a subprocess.
"""

from __future__ import annotations

import datetime
import time
import fnmatch
import json
import os
import re
import threading
import uuid
from pathlib import Path

import anyio
from mcp.server.fastmcp import Context, FastMCP

from .config import settings
from .findings import FindingsError
from .llm import LLMUnavailableError, extract_json, make_client, resolve_model
from .pipeline import _match_files, _resolve_output, run_review
from .repo_ingest import (
    IngestError, check_access, ingest_repository, save_manifest,
)
from .review import render_markdown, review_manifest

mcp = FastMCP(
    "code-review-mcp",
    instructions=(
        "AI code review of GitHub repositories using a local LLM. "
        "RECOMMENDED WORKFLOW: 1) start_review (mode 'brief' by default; "
        "'deep' for thorough reviews) — returns a job_id instantly. "
        "2) get_review_status(job_id) — it waits up to 40s server-side, so "
        "call it repeatedly until status is 'done' or 'error'. Each response "
        "carries a 'progress' line (e.g. '43% — reviewing 53/123 done, 70 "
        "left, ~4m left'); print that line to the user each cycle so they see "
        "completion. HONESTY RULE: you are only monitoring while you are "
        "actually calling get_review_status. If you stop calling it (long "
        "review, tool-call limit), SAY SO — the review keeps running "
        "server-side and can be checked any time later by job_id or report "
        "name. Interrupted deep reviews RESUME: call start_review again with "
        "the same review_id. 3) Consume results file-by-file to protect "
        "your context: get_report_entry(report, index) for one file, "
        "append_report_notes to save your rendering of it, next index, ... "
        "then read_report_notes and write the final repo summary. "
        "get_report gives a compact stats summary at any time. "
        "check_llm verifies the model endpoint before you start. "
        "PRIVATE repositories are supported: the server authenticates with "
        "its own GITHUB_TOKEN environment variable — never ask the user for "
        "a token and never pass one as a tool argument (no tool accepts "
        "one). Use check_repo_access to confirm access first; if it reports "
        "no access, tell the user to set GITHUB_TOKEN on the server."
    ),
)


# ---------------------------------------------------------------------------
# Background review jobs.
#
# Hosts like LM Studio abort tool calls after ~60s, far shorter than a real
# repo review. start_review therefore returns immediately and the pipeline
# runs in a daemon thread; get_review_status is a fast poll. One job runs at
# a time: the reviewing model is the same single local LLM, so concurrent
# jobs would only queue against each other.
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_MAX_JOB_HISTORY = 20


def _now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _job_update(job_id: str, **fields) -> None:
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(fields, updated_at=_now())


def _running_job() -> dict | None:
    with _jobs_lock:
        for job in _jobs.values():
            if job["status"] in ("starting", "cloning", "reviewing"):
                return dict(job)
    return None


def _run_review_job(
    job_id: str,
    repo_url: str,
    system_prompt: str,
    output_path: str,
    branch: str | None,
    extensions: list[str] | None,
    mode: str = "brief",
    model: str = "",
    files: list[str] | None = None,
    findings_file: str = "",
) -> None:
    """Adapter: run the shared pipeline, mirroring its callbacks into the
    in-memory job registry that get_review_status reads."""
    saved_model = settings.lm_model
    if model:
        # Per-job model routing (e.g. brief on a fast model, deep on a big
        # one). Safe as a global override because only one job runs at a time.
        settings.lm_model = model

    def on_status(status: str, **fields) -> None:
        if status == "reviewing" and "progress" not in fields:
            # brief counts BATCHES, deep counts FILES, so the real total
            # arrives with the first progress callback; until then the status
            # reads "preparing" rather than a misleading count.
            fields.setdefault("progress",
                              {"file": 0, "total": None, "message": "starting"})
        _job_update(job_id, status=status, **fields)

    def on_progress(done: int, total: int | None, message: str,
                    eta_seconds: int | None) -> None:
        fields: dict = {"file": done, "total": total, "message": message}
        if eta_seconds is not None:
            fields["eta_seconds"] = eta_seconds
        _job_update(job_id, progress=fields)

    try:
        report = run_review(
            repo_url, system_prompt, output_path,
            branch=branch, extensions=extensions, mode=mode, files=files,
            findings_file=findings_file,
            on_status=on_status, on_progress=on_progress,
        )
        _job_update(
            job_id, status="done", output_path=report["_output_path"],
            markdown_path=report["_markdown_path"],
            stats=report["stats"], failures=report["failures"],
        )
    except (IngestError, LLMUnavailableError, FindingsError) as exc:
        _job_update(job_id, status="error", error=str(exc))
    except Exception as exc:  # noqa: BLE001 - job must always end terminal
        _job_update(job_id, status="error", error=f"unexpected: {exc}")
    finally:
        settings.lm_model = saved_model


@mcp.tool()
def start_review(
    repo_url: str,
    system_prompt: str,
    output_path: str = "review-report.json",
    branch: str = "",
    extensions: list[str] | None = None,
    mode: str = "brief",
    model: str = "",
    review_id: str = "",
    files: list[str] | None = None,
    findings_file: str = "",
) -> str:
    """Start a code review in the background and return a job_id IMMEDIATELY.

    This is the recommended way to review a repository: it never times out,
    because the clone + per-file LLM review run inside the server while you
    poll get_review_status(job_id) for progress. Only one review runs at a
    time; starting a second one while a job is active returns the active job.

    Every review produces TWO files: <name>.json (machine-readable report)
    and <name>.md (human-readable review document).

    SELF-HEALING: deep reviews checkpoint after every completed file and
    brief reviews after every completed batch. If a review crashed or was
    interrupted, calling start_review again with the SAME review_id (or
    output_path) and mode resumes from the checkpoint instead of starting
    over.

    PRIVATE REPOSITORIES: work exactly like public ones — pass the normal
    https://github.com/owner/repo URL. The server authenticates using its
    own GITHUB_TOKEN environment variable; no tool takes a token argument.
    Check access first with check_repo_access if unsure.

    Args:
        repo_url: GitHub repository URL, e.g. https://github.com/owner/repo
            (public or private; private needs GITHUB_TOKEN on the server).
        system_prompt: Instructions for how the review should be done.
        output_path: Where the final JSON report is written ("report.json"
            lands in the mounted /reports folder when running in Docker).
            Ignored when review_id is given.
        branch: Optional branch name (default branch if empty).
        extensions: Optional file-extension filter, e.g. [".py", ".ts"].
        mode: "quick" = static surface checks on ALL files plus one small
            LLM overview (fastest). "brief" (default) = the whole repo
            reviewed in ONE fast LLM pass: repo summary, key issues,
            per-file one-liners. "deep" = one detailed LLM review per file
            (minutes; use after quick/brief triage, scoped via files).
        model: Optional LM Studio model id to review with (e.g. a fast small
            model for brief, a large one for deep). Empty = currently loaded.
        review_id: Optional id (e.g. a ticket or run number) used to NAME the
            output files: review_id "1234" -> 1234.json + 1234.md.
        files: Optional list of file paths or glob patterns to review ONLY
            those files, e.g. ["DjangoWebApp/src/voter/views.py", "*/admin.py"].
            Matches full repo paths or bare filenames. Combine with mode
            "deep" for a focused detailed review.
        findings_file: Optional path to a JSON file of deterministic scanner
            findings produced OUTSIDE this server (e.g. by the project's
            separate Semgrep/scanner component). Relative paths resolve
            against the reports directory. Shape: {"source": "semgrep",
            "findings": [{"file": "path/in/repo.py", "rule": "...",
            "severity": "high", "line": 12, "description": "...",
            "cwe": "..."}]} (or a bare list). The findings are fed to the
            reviewing model for verification and enrichment (explanation,
            impact, remediation) and attached to the report verbatim as
            static_findings with a confirmed_by_llm flag per finding.
    """
    mode = mode.strip().lower() or "brief"
    if mode not in ("quick", "brief", "deep"):
        return json.dumps({
            "status": "error",
            "error": f"mode must be 'quick', 'brief' or 'deep', not {mode!r}",
        })
    if review_id:
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", review_id.strip()).strip(".") or "review"
        output_path = f"{safe_id}.json"
    active = _running_job()
    if active:
        return json.dumps({
            "status": "already_running",
            "job_id": active["job_id"],
            "hint": "A review is already in progress; poll get_review_status "
                    "with this job_id.",
        })
    job_id = uuid.uuid4().hex[:8]
    with _jobs_lock:
        # Trim oldest finished jobs so the registry never grows unbounded.
        finished = [jid for jid, j in _jobs.items() if j["status"] in ("done", "error")]
        while len(_jobs) >= _MAX_JOB_HISTORY and finished:
            del _jobs[finished.pop(0)]
        _jobs[job_id] = {
            "job_id": job_id, "status": "starting", "repo_url": repo_url,
            "mode": mode, "output_path": output_path,
            "started_at": _now(), "updated_at": _now(),
            "started_monotonic": time.monotonic(),
        }
    # NON-daemon on purpose: if the MCP host disconnects mid-review, the
    # process lingers until the job finishes, writes the final report to the
    # mounted volume, and only then exits. A killed container still leaves
    # the .partial.json checkpoint for resume.
    threading.Thread(
        target=_run_review_job,
        args=(job_id, repo_url, system_prompt, output_path,
              branch or None, extensions, mode, model.strip(), files,
              findings_file.strip()),
        daemon=False,
    ).start()
    response = {
        "status": "started",
        "job_id": job_id,
        "mode": mode,
        "next_step": f"Call get_review_status with job_id '{job_id}' and "
                     "wait_seconds 40. It returns when the review finishes or "
                     "after 40s; repeat while status is 'reviewing'.",
    }
    if mode == "deep" and _resolve_output(output_path).with_suffix(
            ".partial.json").is_file():
        response["resuming"] = ("A checkpoint from an earlier run exists; "
                                "already-reviewed files will be reused if the "
                                "repository commit still matches.")
    return json.dumps(response)


@mcp.tool()
async def get_review_status(job_id: str, wait_seconds: int = 40) -> str:
    """Check a background review. Waits up to wait_seconds for completion
    before answering, so ONE call covers a long stretch of the review —
    call it in a loop WITHOUT other chatter to save your context window.

    Returns a compact one-line status:
    {"status": "reviewing", "file": 7, "total": 119} -> keep polling
    {"status": "done", "stats": {...}}               -> call get_report next
    {"status": "error", "error": "..."}              -> stop

    Args:
        job_id: The id returned by start_review.
        wait_seconds: How long to wait server-side before responding if the
            job is still running (0-45; default 40). Use the default unless
            your client's tool timeout is shorter.
    """
    deadline = time.monotonic() + max(0, min(int(wait_seconds), 45))
    while True:
        with _jobs_lock:
            job = dict(_jobs.get(job_id.strip(), {}))
        if not job:
            with _jobs_lock:
                known = list(_jobs)
            return json.dumps({
                "status": "unknown_job",
                "known_jobs": known,
                "resumable_checkpoints": _find_checkpoints(),
                "hint": "This job belongs to an earlier session. If a "
                        "checkpoint is listed, call start_review with the "
                        "same review_id and mode to RESUME it; also check "
                        "list_reports — the finished report may already exist.",
            })
        if job["status"] in ("done", "error") or time.monotonic() >= deadline:
            break
        await anyio.sleep(1)  # async: the event loop stays responsive

    # Compact answers: polling happens many times per review and every char
    # returned lands in the calling LLM's context window.
    if job["status"] == "done":
        return json.dumps({"status": "done", "stats": job.get("stats"),
                           "report": job.get("output_path"),
                           "markdown": job.get("markdown_path"),
                           "next": "get_report or get_report_entry"})
    if job["status"] == "error":
        return json.dumps({"status": "error", "error": job.get("error")})
    return json.dumps(_progress_payload(job))


def _find_checkpoints() -> list[dict]:
    """Resumable .partial.json checkpoints in the output directory."""
    base = Path(settings.output_dir or ".")
    found = []
    if base.is_dir():
        for p in sorted(base.glob("*.partial.json")):
            try:
                ck = json.loads(p.read_text(encoding="utf-8"))
                found.append({
                    "review": p.name.replace(".partial.json", ""),
                    "repo_url": ck.get("repo_url"),
                    "mode": ck.get("mode"),
                    "done": ck.get("progress", {}).get("done"),
                    "total": ck.get("progress", {}).get("total"),
                    "updated_at": ck.get("updated_at"),
                })
            except (json.JSONDecodeError, OSError):
                continue
    return found


def _progress_payload(job: dict) -> dict:
    """Compact progress snapshot for a running job: done / remaining / percent
    / elapsed / eta, plus a ready-to-print one-line summary for the chat."""
    progress = job.get("progress") or {}
    done = progress.get("file")
    total = progress.get("total")
    payload: dict = {"status": job["status"], "done": done, "total": total}

    elapsed = None
    if isinstance(job.get("started_monotonic"), (int, float)):
        elapsed = int(time.monotonic() - job["started_monotonic"])
        payload["elapsed_seconds"] = elapsed

    if isinstance(done, int) and isinstance(total, int) and total > 0:
        remaining = max(0, total - done)
        percent = round(100 * done / total)
        payload["remaining"] = remaining
        payload["percent"] = percent
        eta = progress.get("eta_seconds")  # stable, computed on each advance
        if eta is not None:
            payload["eta_seconds"] = eta
        unit = "files" if job["mode"] == "deep" else "batches"
        eta_txt = f", ~{eta // 60}m {eta % 60}s left" if eta else ""
        elapsed_txt = f" ({elapsed}s elapsed)" if elapsed is not None else ""
        restored = f" (+{job['reused']} restored)" if job.get("reused") else ""
        payload["progress"] = (
            f"{percent}% — {done}/{total} {unit} done, {remaining} left"
            f"{eta_txt}{elapsed_txt}{restored}"
        )
    else:
        payload["progress"] = f"{job['status']} (cloning / preparing)"
    # Anti-hallucination contract: the calling model must not pretend to
    # monitor. Either it calls again, or it tells the user it stopped.
    payload["do"] = (
        "Report this progress line, then either CALL get_review_status again "
        "or TELL the user you stopped polling (the review continues "
        "server-side; anyone can check later with this job_id or the report "
        "name). Never claim to be monitoring without calling this tool."
    )
    return payload


@mcp.tool()
def list_reports() -> str:
    """List all generated review reports stored on the server.

    Use this to find report filenames for get_report. Reports live in the
    server's output directory (/reports in Docker, mounted to the host).
    """
    base = Path(settings.output_dir or ".")
    reports = []
    if base.is_dir():
        for f in sorted(base.glob("*.json"), key=lambda p: p.stat().st_mtime,
                        reverse=True):
            if f.name.endswith(".partial.json"):
                continue  # listed separately below as resumable
            reports.append({
                "name": f.name,
                "size_bytes": f.stat().st_size,
                "modified": datetime.datetime.fromtimestamp(
                    f.stat().st_mtime, tz=datetime.timezone.utc
                ).isoformat(timespec="seconds").replace("+00:00", "Z"),
            })
    return json.dumps({
        "reports_dir": str(base),
        "reports": reports,
        "resumable_checkpoints": _find_checkpoints(),
    }, indent=2)


@mcp.tool()
def get_report(report: str, file: str = "", full: bool = False) -> str:
    """Fetch a finished review report THROUGH MCP, so results are never lost
    even if the container has no volume mounted.

    Args:
        report: A job_id from start_review, OR a report filename from
            list_reports (e.g. "review-report.json").
        file: Optional path of one reviewed file (as shown in the summary) to
            get its complete review entry.
        full: Set true to return the entire raw report JSON (can be large).
            Default false returns a compact summary: stats plus per-file
            scores and issue counts.
    """
    # A job_id? Follow it to its report path.
    with _jobs_lock:
        job = _jobs.get(report.strip())
    if job:
        if job["status"] != "done":
            return json.dumps({
                "status": job["status"],
                "error": "This job has not produced a report yet."
                if job["status"] != "error" else job.get("error", "job failed"),
            })
        target = Path(job["output_path"])
    else:
        target = _resolve_output(report)

    if not target.is_file():
        listing = json.loads(list_reports())
        return json.dumps({
            "status": "not_found",
            "error": f"No report at {target}.",
            "available": [r["name"] for r in listing["reports"]],
        })

    data = json.loads(target.read_text(encoding="utf-8"))

    if file:
        for entry in data.get("reviews", []):
            if entry.get("file") == file:
                return json.dumps(entry, indent=2, ensure_ascii=False)
        return json.dumps({
            "status": "not_found",
            "error": f"No review for {file!r} in this report.",
            "reviewed_files": [r.get("file") for r in data.get("reviews", [])],
        })

    if full:
        text = json.dumps(data, indent=2, ensure_ascii=False)
        if len(text) > 200_000:
            return json.dumps({
                "status": "too_large",
                "error": f"Full report is {len(text)} chars; fetch it per file "
                         "with the 'file' argument instead.",
                "reviewed_files": [r.get("file") for r in data.get("reviews", [])],
            })
        return text

    return json.dumps({
        "report": target.name,
        "repo_url": data.get("repo_url"),
        "commit": data.get("commit"),
        "model": data.get("model"),
        "generated_at": data.get("generated_at"),
        "stats": data.get("stats"),
        **({"deterministic": data["deterministic"]}
           if data.get("deterministic") else {}),
        "files": [
            {"file": r.get("file"), "score": r.get("score"),
             "issues": len(r.get("issues", []))
             + len(r.get("static_findings", []))}
            for r in data.get("reviews", [])
        ],
        "failures": data.get("failures", []),
        "hint": "Call get_report again with file=\"<path>\" for a file's "
                "complete review, or full=true for everything.",
    }, indent=2, ensure_ascii=False)


async def review_repository(  # registered conditionally below
    repo_url: str,
    system_prompt: str,
    output_path: str,
    branch: str = "",
    extensions: list[str] | None = None,
    ctx: Context = None,
) -> str:
    """Review a repo in ONE blocking tool call (minutes to hours!).

    Hidden unless REVIEW_ENABLE_BLOCKING=1: hosts with short tool timeouts
    (LM Studio: 60s) kill this call long before a real review finishes, and
    small models reliably chose it over the job flow because of its name.
    Prefer start_review + get_review_status + get_report.

    Args:
        repo_url: GitHub repository URL, e.g. https://github.com/owner/repo
        system_prompt: Instructions describing how the review should be done
            (focus areas, tone, standards). JSON output format is enforced
            automatically on top of this.
        output_path: Absolute path where the final JSON report is written.
        branch: Optional branch name (default branch if empty).
        extensions: Optional list of file extensions to review, e.g.
            [".py", ".ts"]. Defaults to a broad built-in set.
    """
    if ctx:
        await ctx.info(f"Cloning {repo_url} ...")
    try:
        # Worker thread keeps the event loop responsive (pings, cancellations).
        manifest = await anyio.to_thread.run_sync(
            lambda: ingest_repository(repo_url, branch or None, extensions)
        )
    except IngestError as exc:
        return json.dumps({"status": "error", "stage": "ingest", "error": str(exc)})

    if manifest["file_count"] == 0:
        return json.dumps({
            "status": "error",
            "stage": "ingest",
            "error": "No reviewable code files found (check extensions filter).",
            "skipped": manifest["skipped"],
            "excluded": manifest.get("excluded", {}),
        })

    if ctx:
        await ctx.info(
            f"Ingested {manifest['file_count']} files at {manifest['commit'][:8]}; "
            "starting per-file review..."
        )

    # Per-file progress -> MCP progress notifications. Hosts (e.g. Claude
    # Code) reset their request timeout when progress arrives, which keeps
    # multi-minute reviews alive. Called from the worker thread, so marshal
    # back onto the event loop with anyio.from_thread.
    def progress(index: int, total: int, path: str) -> None:
        if ctx:
            try:
                anyio.from_thread.run(
                    ctx.report_progress, index, total, f"[{index}/{total}] {path}"
                )
            except Exception:  # noqa: BLE001 - progress is best-effort
                pass

    try:
        report = await anyio.to_thread.run_sync(
            lambda: review_manifest(manifest, system_prompt, progress)
        )
    except LLMUnavailableError as exc:
        # Real error (endpoint down / stream stalled) -> stop with a clear
        # message. This is the only way a healthy in-progress review ends.
        return json.dumps({"status": "error", "stage": "review", "error": str(exc)})

    out = _resolve_output(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown = out.with_suffix(".md")
    markdown.write_text(render_markdown(report), encoding="utf-8")

    if ctx:
        await ctx.info(f"Report written to {out}")

    return json.dumps({
        "status": "ok",
        "output_path": str(out),
        "markdown_path": str(markdown),
        "stats": report["stats"],
        "failures": report["failures"],
    }, indent=2)


# The blocking tool is opt-in: with it in the catalog, small models (tested
# with Gemma 4) pick it by name over the job flow and then die on their
# host's 60s tool timeout. Long-timeout hosts can set REVIEW_ENABLE_BLOCKING=1.
if os.getenv("REVIEW_ENABLE_BLOCKING", "") == "1":
    mcp.tool()(review_repository)


def _load_report(report: str) -> tuple[Path, dict] | str:
    """Resolve a job_id or filename to (path, parsed report) or an error JSON."""
    with _jobs_lock:
        job = _jobs.get(report.strip())
    if job:
        if job["status"] != "done":
            return json.dumps({"status": job["status"],
                               "error": "This job has not produced a report yet."})
        target = Path(job["output_path"])
    else:
        target = _resolve_output(report)
    if not target.is_file():
        return json.dumps({"status": "not_found", "error": f"No report at {target}."})
    return target, json.loads(target.read_text(encoding="utf-8"))


def _notes_path(report_path: Path) -> Path:
    return report_path.with_suffix(".notes.md")


@mcp.tool()
def get_report_entry(report: str, index: int = 0) -> str:
    """Read ONE file's review from a finished report — the context-safe way
    to consume results file by file.

    Workflow for summarizing a whole repo without exhausting your context:
    1. get_report_entry(report, 0) -> first file's review
    2. Write your rendering of it with append_report_notes(report, "...")
    3. Continue with index 1, 2, ... until "remaining" is 0.
    4. read_report_notes(report) to reread everything you wrote and produce
       the final overall summary.

    Args:
        report: A job_id from start_review OR a report filename.
        index: 0-based position of the file review to fetch.
    """
    loaded = _load_report(report)
    if isinstance(loaded, str):
        return loaded
    _, data = loaded
    reviews = data.get("reviews", [])
    if not reviews:
        return json.dumps({"status": "empty", "error": "Report has no reviews."})
    if not 0 <= index < len(reviews):
        return json.dumps({"status": "out_of_range", "count": len(reviews)})
    return json.dumps({
        "index": index,
        "of": len(reviews),
        "remaining": len(reviews) - index - 1,
        "review": reviews[index],
        "next": (f"get_report_entry index {index + 1}"
                 if index + 1 < len(reviews)
                 else "all files read — read_report_notes for your notes"),
    }, ensure_ascii=False)


@mcp.tool()
def append_report_notes(report: str, text: str) -> str:
    """Append your rendered notes for a file to the report's notes document
    (<report>.notes.md, stored next to the report, out of your context).

    Write one file's rendition per call while iterating get_report_entry;
    at the end, read_report_notes returns the whole document.

    Args:
        report: The job_id or report filename the notes belong to.
        text: Markdown text to append (a heading + your rendering).
    """
    loaded = _load_report(report)
    if isinstance(loaded, str):
        return loaded
    report_path, _ = loaded
    notes = _notes_path(report_path)
    with notes.open("a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n\n")
    return json.dumps({"status": "ok", "notes_file": notes.name,
                       "notes_chars": notes.stat().st_size})


@mcp.tool()
def read_report_notes(report: str, offset: int = 0) -> str:
    """Read back the notes document written with append_report_notes, in
    pages that fit comfortably in context.

    Args:
        report: The job_id or report filename the notes belong to.
        offset: Character offset to continue from (use "next_offset" from the
            previous call; 0 starts at the beginning).
    """
    loaded = _load_report(report)
    if isinstance(loaded, str):
        return loaded
    report_path, _ = loaded
    notes = _notes_path(report_path)
    if not notes.is_file():
        return json.dumps({"status": "empty",
                           "error": "No notes written yet for this report."})
    text = notes.read_text(encoding="utf-8")
    page_size = 6000
    page = text[offset:offset + page_size]
    next_offset = offset + page_size if offset + page_size < len(text) else None
    return json.dumps({
        "total_chars": len(text),
        "offset": offset,
        "next_offset": next_offset,
        "text": page,
    }, ensure_ascii=False)


@mcp.tool()
async def ingest_repository_only(
    repo_url: str,
    output_path: str = "",
    branch: str = "",
    extensions: list[str] | None = None,
) -> str:
    """Clone a GitHub repo and convert its code to the pure JSON manifest,
    WITHOUT running the LLM review. Useful for testing stage 1 in isolation.

    Args:
        repo_url: GitHub repository URL.
        output_path: Optional path to save the manifest JSON. If empty, only
            a summary is returned (full file contents are not echoed back).
        branch: Optional branch name.
        extensions: Optional extension filter, e.g. [".py"].
    """
    try:
        manifest = await anyio.to_thread.run_sync(
            lambda: ingest_repository(repo_url, branch or None, extensions)
        )
    except IngestError as exc:
        return json.dumps({"status": "error", "error": str(exc)})

    saved = str(save_manifest(manifest, _resolve_output(output_path))) if output_path else None
    return json.dumps({
        "status": "ok",
        "repo_url": manifest["repo_url"],
        "commit": manifest["commit"],
        "authenticated": manifest.get("authenticated", False),
        "file_count": manifest["file_count"],
        "files": [f["path"] for f in manifest["files"]],
        "skipped": manifest["skipped"],
        "excluded": manifest.get("excluded", {}),
        "saved_to": saved,
    }, indent=2)


@mcp.tool()
async def check_repo_access(repo_url: str, branch: str = "") -> str:
    """Check whether the server can clone a repository — PUBLIC or PRIVATE.

    Fast (a git ls-remote, no clone, no LLM). Run this before a long review
    of a private repository so an unauthorized or expired token costs
    seconds instead of failing an hour into the run.

    Private repositories require a token in the server's GITHUB_TOKEN (or
    GH_TOKEN) environment variable. There is deliberately NO token argument
    on any tool: an argument would travel through the MCP protocol into the
    chat transcript and the host's logs. This tool reports only WHETHER a
    token is configured, never its value.

    Args:
        repo_url: GitHub repository URL, e.g. https://github.com/owner/repo
        branch: Optional branch to confirm exists.
    """
    try:
        result = await anyio.to_thread.run_sync(
            lambda: check_access(repo_url, branch or None)
        )
    except IngestError as exc:
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)
    except Exception as exc:  # noqa: BLE001 - report any connectivity issue
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
async def check_llm() -> str:
    """Verify LM Studio is reachable and the model can return pure JSON.

    Sends a trivial prompt and reports the endpoint, model, and whether the
    response parsed as JSON. Run this BEFORE starting a review; while a
    review job is active it reports 'busy' instead of querying the model.
    """
    active = _running_job()
    if active:
        # The single local model is generating review chunks right now; a
        # test prompt would queue behind that generation and could exceed
        # the host's tool timeout. The active job itself proves liveness.
        return json.dumps({
            "status": "busy",
            "note": "The model is currently reviewing (job "
                    f"{active['job_id']}, {active['status']}); it is alive. "
                    "Poll get_review_status instead.",
        }, indent=2)
    try:
        return await anyio.to_thread.run_sync(_check_llm_sync)
    except Exception as exc:  # noqa: BLE001 - report any connectivity issue
        return json.dumps({
            "status": "error",
            "base_url": settings.lm_base_url,
            "error": str(exc),
            "hint": "Is LM Studio running with the local server enabled (Developer tab)?",
        }, indent=2)


def _check_llm_sync() -> str:
    try:
        client = make_client()
        response = client.chat.completions.create(
            model=resolve_model(client),
            messages=[
                {"role": "system", "content": "Respond with only a JSON object, no other text."},
                {"role": "user", "content": 'Return exactly: {"pong": true}'},
            ],
            temperature=0,
            # Reasoning models (e.g. Gemma 4) spend tokens on hidden reasoning
            # before the answer; keep enough budget for the content itself.
            max_tokens=1000,
        )
        raw = response.choices[0].message.content or ""
        parsed = extract_json(raw)
        return json.dumps({
            "status": "ok",
            "base_url": settings.lm_base_url,
            "model": response.model,
            "json_roundtrip": parsed,
        }, indent=2)
    except Exception as exc:  # noqa: BLE001 - report any connectivity issue
        return json.dumps({
            "status": "error",
            "base_url": settings.lm_base_url,
            "error": str(exc),
            "hint": "Is LM Studio running with the local server enabled (Developer tab)?",
        }, indent=2)


def main() -> None:
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
        stream=__import__("sys").stderr,
    )
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
