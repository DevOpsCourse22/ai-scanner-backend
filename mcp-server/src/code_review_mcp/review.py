"""Stages 2+3: per-file chunked review and merging into a single report.

Report shape:
{
  "repo_url": "...",
  "commit": "...",
  "model": "...",
  "generated_at": "2026-07-02T12:00:00Z",
  "stats": {"files_reviewed": 10, "files_failed": 0, "issues_total": 7,
            "issues_by_severity": {"critical": 1, ...}, "average_score": 7.4},
  "reviews": [ <per-file JSON from the model> ],
  "failures": [{"file": "...", "error": "..."}]
}
"""

from __future__ import annotations

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from . import llm
from .config import settings
from .llm import (
    LINE_NUMBER_NOTE,
    LLMUnavailableError,
    clamp_issue_lines,
    make_client,
    number_lines,
    review_chunk,
    review_digest,
)
from .surface import surface_scan, surface_score

SEVERITIES = ("critical", "high", "medium", "low", "info")

# progress(current_file_index, total_files, message). Called at the start of
# each file AND repeatedly while the model streams tokens for it, so the MCP
# layer can prove liveness to its host for as long as the AI is working.
ProgressFn = Callable[[int, int, str], None]


def split_content_with_lines(
    content: str, max_chars: int
) -> list[tuple[int, str]]:
    """Split content on line boundaries into (start_line, chunk) pairs.

    start_line is the 1-based file line each chunk begins at, so a chunked
    file still reports absolute line numbers instead of restarting at 1 in
    every part.
    """
    if len(content) <= max_chars:
        return [(1, content)]
    chunks: list[tuple[int, str]] = []
    current: list[str] = []
    current_len = 0
    start_line = 1
    line_no = 1
    for line in content.splitlines(keepends=True):
        if current_len + len(line) > max_chars and current:
            chunks.append((start_line, "".join(current)))
            current, current_len = [], 0
            start_line = line_no
        # A line longer than the whole budget cannot be placed on a line
        # boundary. Minified code is exactly that — one line of half a
        # megabyte — and without this it produced ONE chunk ten times over
        # budget, which the model either chokes on or grinds through for
        # hours. Split it mid-line rather than send it whole; the line
        # number stays correct because it is all still the same line.
        while len(line) > max_chars:
            chunks.append((line_no, line[:max_chars]))
            line = line[max_chars:]
            start_line = line_no
        current.append(line)
        current_len += len(line)
        line_no += 1
    if current:
        chunks.append((start_line, "".join(current)))
    return chunks


def split_content(content: str, max_chars: int) -> list[str]:
    """Split file content on line boundaries into chunks under max_chars."""
    return [chunk for _, chunk in split_content_with_lines(content, max_chars)]


def merge_parts(file_path: str, parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine reviews of multiple chunks of one large file into one entry."""
    if len(parts) == 1:
        return parts[0]
    issues = [i for p in parts for i in p.get("issues", [])]
    positives = [pos for p in parts for pos in p.get("positives", [])]
    scores = [p["score"] for p in parts if isinstance(p.get("score"), (int, float))]
    return {
        "file": file_path,
        "summary": " ".join(p.get("summary", "") for p in parts).strip(),
        "issues": issues,
        "positives": positives,
        "score": round(sum(scores) / len(scores)) if scores else None,
        "chunked": len(parts),
    }


def _attach_static_findings(
    review: dict[str, Any], findings: list[dict[str, Any]] | None
) -> None:
    """Attach deterministic scanner findings to a completed review entry.

    The findings are attached VERBATIM (identity-preserving — the model can
    never remove, downgrade, or rewrite them). Each is marked
    confirmed_by_llm when the model independently reported an issue within
    2 lines of it: found-by-both is the highest-confidence tier.
    """
    if not findings:
        return
    issue_lines = [i.get("line") for i in review.get("issues", [])
                   if isinstance(i.get("line"), int)]
    review["static_findings"] = [
        {**f, "confirmed_by_llm": isinstance(f.get("line"), int)
         and any(abs(f["line"] - line) <= 2 for line in issue_lines)}
        for f in findings
    ]


def _static_flags(findings: list[dict[str, Any]]) -> list[str]:
    """Compact one-line renditions of scanner findings for brief batches."""
    return [
        f"L{f.get('line', '?')} {f.get('severity', 'info')}: "
        f"{f.get('rule', '')} — {f.get('description', '')[:80]}"
        for f in findings[:5]
    ]


def _trivial_review(path: str, content: str) -> dict[str, Any] | None:
    """Boilerplate/empty files get a canned review with no LLM round-trip."""
    stripped = "".join(content.split())
    if len(stripped) >= settings.trivial_file_chars:
        return None
    return {
        "file": path,
        "summary": "Trivial file (empty or near-empty); no review needed.",
        "issues": [],
        "score": None,
        "trivial": True,
    }


def _head_by_lines(text: str, max_chars: int) -> tuple[str, bool]:
    """Head of `text` under max_chars, cut on a line boundary.

    Returns (head, was_truncated). Cutting mid-line would hand the model a
    half-written statement — and, once the text is numbered, a line number
    with no line beside it.
    """
    if len(text) <= max_chars:
        return text, False
    kept: list[str] = []
    used = 0
    for line in text.splitlines(keepends=True):
        if used + len(line) > max_chars and kept:
            break
        kept.append(line)
        used += len(line)
    return "".join(kept), True


def pack_digest_batches(
    files: list[dict[str, Any]],
    static_map: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[list[list[dict[str, Any]]], list[dict[str, Any]]]:
    """Split ALL non-trivial files into digest batches for brief mode.

    Every file appears in exactly one batch (head-truncated to
    brief_file_cap chars); each batch stays under brief_pack_chars, so the
    number of LLM calls scales with repo size instead of files being
    silently dropped. Files with deterministic findings carry compact
    static_flags lines (counted against the batch budget).
    Returns (batches, trivial_review_entries).
    """
    batches: list[list[dict[str, Any]]] = []
    trivial_entries: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    used = 0
    for entry in files:
        trivial = _trivial_review(entry["path"], entry["content"])
        if trivial is not None:
            trivial_entries.append(trivial)
            continue
        # The cap applies to the NUMBERED text, because that is what is
        # actually sent. Numbering a file of short lines adds ~40%, so
        # budgeting on the raw head would quietly blow both the per-file
        # cap and the batch budget built from it.
        raw_head = entry["content"][: settings.brief_file_cap]
        numbered, cut = _head_by_lines(number_lines(raw_head),
                                       settings.brief_file_cap)
        flags = _static_flags(static_map.get(entry["path"], [])) if static_map else []
        cost = len(numbered) + sum(len(f) for f in flags)
        if current and used + cost > settings.brief_pack_chars:
            batches.append(current)
            current, used = [], 0
        packed = {
            "file": entry["path"],
            "truncated": cut or len(raw_head) < len(entry["content"]),
            "lines_shown": f"1-{max(len(numbered.splitlines()), 1)}",
            "code": numbered,
        }
        if flags:
            packed["static_flags"] = flags
        current.append(packed)
        used += cost
    if current:
        batches.append(current)
    return batches, trivial_entries


def _brief_report(
    manifest: dict[str, Any],
    system_prompt: str,
    progress: ProgressFn | None,
    brief_state: dict[str, Any] | None = None,
    static_map: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Brief mode: the WHOLE repo in digest batches, one LLM call per batch,
    plus a small merge call for the overall verdict when there are several.

    brief_state (optional) carries crash-recovery hooks from the server:
    "checkpoint" — called with ({batch_index: result}, total) after every
    completed batch; "preloaded" — batch results recovered from an earlier
    run's checkpoint (skipped, not re-reviewed); "total" — the batch count
    recorded in that checkpoint (a mismatch means packing changed, so the
    preloaded results are discarded).
    """
    client = make_client()
    files = manifest.get("files", [])
    batches, trivial_entries = pack_digest_batches(files, static_map)
    total = len(batches)

    checkpoint_cb = (brief_state or {}).get("checkpoint")
    preloaded: dict[int, dict[str, Any]] = {}
    if brief_state and brief_state.get("preloaded"):
        if brief_state.get("total") in (None, total):
            # JSON round-trips dict keys as strings; normalize and bound-check.
            preloaded = {int(k): v for k, v in brief_state["preloaded"].items()
                         if 0 <= int(k) < total}

    key_issues: list[dict[str, Any]] = []
    noted: dict[str, dict[str, Any]] = {}
    batch_scores: list[float] = []
    done_count = len(preloaded)
    count_lock = threading.Lock()
    if preloaded and progress:
        progress(done_count, total,
                 f"resumed {len(preloaded)}/{total} batches from checkpoint")

    def run_batch(index: int, batch: list[dict[str, Any]]) -> dict[str, Any]:
        # Heartbeats report the COMPLETED batch count (not this batch's
        # index), so "done" only advances when a batch actually finishes.
        def heartbeat(msg: str) -> None:
            with count_lock:
                completed = done_count
            progress(completed, total, f"batch {index}/{total}: {msg}")
        heartbeat = heartbeat if progress else None
        note = (f"Batch {index} of {total}; other batches cover the rest "
                "of the repository.")
        if any("static_flags" in f for f in batch):
            note += (" Some files carry static_flags from deterministic "
                     "scanners: treat them as strong hints — confirm or "
                     "dismiss each, and cite the flagged lines in "
                     "key_issues when they are real.")
        digest = {
            "task": "brief_repository_review",
            "note": note,
            "line_numbers": LINE_NUMBER_NOTE,
            "files": batch,
        }
        result = review_digest(client, system_prompt, digest, heartbeat)
        if progress:
            nonlocal done_count
            with count_lock:
                done_count += 1
                done = done_count
            progress(done, total, f"batch finished ({done}/{total})")
        return result

    # Up to settings.parallel batches in flight at once. Results are merged
    # in batch order so reports stay deterministic. Serial mode runs inline:
    # no new threads, so a review keeps working even if the MCP host
    # disconnected and the interpreter is already shutting down.
    results: list[dict[str, Any] | None] = [None] * total
    for i, result in preloaded.items():
        results[i] = result

    def record(index: int, result: dict[str, Any]) -> None:
        results[index] = result
        if checkpoint_cb:
            checkpoint_cb({i: r for i, r in enumerate(results)
                           if r is not None}, total)

    pending = [i for i in range(total) if results[i] is None]
    workers = max(1, min(settings.parallel, len(pending) or 1))
    if workers == 1:
        for i in pending:
            record(i, run_batch(i + 1, batches[i]))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(run_batch, i + 1, batches[i]): i
                for i in pending
            }
            try:
                for future in as_completed(futures):
                    with count_lock:
                        record(futures[future], future.result())
            except BaseException:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

    # Brief mode shows only the head of each file, so a line beyond that (or
    # attributed to a file that was never packed) is one the model invented.
    # Taken from the batches themselves — the record of what was really sent.
    visible_lines = {
        packed["file"]: max(len(packed["code"].splitlines()), 1)
        for batch in batches for packed in batch
    }

    batch_summaries: list[str] = []
    for result in results:
        if result is None:
            continue
        for issue in result.get("key_issues", []) or []:
            if isinstance(issue, dict):
                clamp_issue_lines(
                    [issue], 1, visible_lines.get(issue.get("file"), 0))
        key_issues += result.get("key_issues", []) or []
        if result.get("summary"):
            batch_summaries.append(result["summary"])
        if isinstance(result.get("score"), (int, float)):
            batch_scores.append(result["score"])
        for note in result.get("files", []) or []:
            path = note.get("file", "unknown")
            noted[path] = {"summary": note.get("note", ""),
                           "score": note.get("score")}

    # Overall verdict: single batch speaks for itself; several get merged
    # by one more small LLM call over the batch summaries.
    if total <= 1:
        overall_summary = batch_summaries[0] if batch_summaries else ""
        overall_score = batch_scores[0] if batch_scores else None
    else:
        if progress:
            progress(total, total, "merging batch verdicts")
        merge = review_digest(client, system_prompt, {
            "task": "merge_brief_batches",
            "note": "These are your own summaries of successive batches of "
                    "one repository. Produce ONE overall summary and score "
                    "for the whole repository.",
            "batch_summaries": batch_summaries,
            "key_issues": [i.get("title") for i in key_issues][:20],
        }, None)
        overall_summary = merge.get("summary", " ".join(batch_summaries))
        overall_score = merge.get("score")
        if overall_score is None and batch_scores:
            overall_score = round(sum(batch_scores) / len(batch_scores))

    # reviews[] covers EVERY file: model-noted ones carry their note; the
    # rest are recorded as seen-but-unremarkable so nothing is invisible.
    reviews: list[dict[str, Any]] = []
    for entry in files:
        path = entry["path"]
        if any(t["file"] == path for t in trivial_entries):
            continue
        note = noted.get(path)
        review = {
            "file": path,
            "summary": note["summary"] if note else "",
            "issues": [i for i in key_issues if i.get("file") == path],
            "score": note.get("score") if note else None,
            "noted": bool(note),
        }
        if static_map:
            _attach_static_findings(review, static_map.get(path))
        reviews.append(review)
    reviews += trivial_entries

    report = _build_report(manifest, reviews, failures=[])
    report["mode"] = "brief"
    if preloaded:
        report["resumed"] = True
        report["reused_batches"] = len(preloaded)
    report["overall"] = {
        "summary": overall_summary,
        "score": overall_score,
        "key_issues": key_issues,
        "files_packed": len(files) - len(trivial_entries),
        "batches": total,
        "files_not_shown": [],
    }
    by_severity = {sev: 0 for sev in SEVERITIES}
    for issue in key_issues:
        sev = str(issue.get("severity", "info")).lower()
        by_severity[sev if sev in by_severity else "info"] += 1
    report["stats"]["issues_total"] = len(key_issues)
    report["stats"]["issues_by_severity"] = by_severity
    return report


_SEVERITY_MARKS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵",
                   "info": "⚪"}


def render_markdown(report: dict[str, Any]) -> str:
    """Render a report as a human-readable markdown review document."""
    stats = report.get("stats", {})
    overall = report.get("overall") or {}
    lines = [
        f"# Code Review: {report.get('repo_url', 'unknown')}",
        "",
        f"- **Mode:** {report.get('mode', 'deep')}  ",
        f"- **Model:** {report.get('model', 'unknown')}  ",
        f"- **Commit:** `{str(report.get('commit', ''))[:12]}`  ",
        f"- **Generated:** {report.get('generated_at', '')}  ",
        f"- **Files reviewed:** {stats.get('files_reviewed', 0)} "
        f"(failed: {stats.get('files_failed', 0)}, "
        f"skipped: {stats.get('files_skipped', 0)})",
        "",
    ]
    # State the limits of coverage next to the verdict, not in a footnote:
    # a reader who does not know a Kubernetes repo was reviewed without its
    # manifests will read this document as a clean bill of health.
    # A file the walk gave up on — too large, not UTF-8, generated — is
    # named with its reason, not reduced to a number in the header. Someone
    # reading this has to be able to see that the bundle they care about
    # was never opened.
    dropped = report.get("skipped") or []
    if dropped:
        lines += [f"> ⚠️ **{len(dropped)} file(s) were skipped** and not "
                  "reviewed:", ""]
        for item in dropped[:10]:
            lines.append(f"> - `{item.get('path', '?')}` — "
                         f"{item.get('reason', 'no reason recorded')}")
        if len(dropped) > 10:
            lines.append(f"> - …and {len(dropped) - 10} more")
        lines.append("")

    excluded = report.get("excluded") or {}
    if excluded.get("count"):
        by_type = ", ".join(f"`{ext}` ×{n}"
                            for ext, n in list(excluded["by_type"].items())[:8])
        lines += [
            f"> ⚠️ **{excluded['count']} file(s) were not reviewed** because "
            f"their type is not in the review set: {by_type}. "
            "Pass `extensions` to include them.",
            "",
        ]
    score = overall.get("score", stats.get("average_score"))
    if score is not None:
        lines += [f"## Verdict: {score}/10", ""]
    if overall.get("summary"):
        lines += [overall["summary"], ""]

    key_issues = overall.get("key_issues") or [
        {**issue, "file": review.get("file")}
        for review in report.get("reviews", [])
        for issue in review.get("issues", [])
    ]
    # Deterministic findings join the key-issues list so both the scanner's
    # results and the AI's are visible up front, not only per-file.
    static_issues = [
        {**finding, "file": review.get("file")}
        for review in report.get("reviews", [])
        for finding in review.get("static_findings", [])
    ]
    if key_issues or static_issues:
        lines += ["## Key issues", ""]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for issue in sorted(key_issues,
                            key=lambda i: order.get(str(i.get("severity", "info")).lower(), 4)):
            sev = str(issue.get("severity", "info")).lower()
            mark = _SEVERITY_MARKS.get(sev, "⚪")
            line = f" (line {issue['line']})" if issue.get("line") else ""
            lines.append(f"- {mark} **{sev}** `{issue.get('file', '?')}`{line} — "
                         f"{issue.get('title', issue.get('description', ''))}")
        for finding in sorted(static_issues,
                              key=lambda f: order.get(str(f.get("severity", "info")).lower(), 4)):
            sev = str(finding.get("severity", "info")).lower()
            mark = _SEVERITY_MARKS.get(sev, "⚪")
            line = f" (line {finding['line']})" if finding.get("line") else ""
            confirmed = (" ✓ confirmed by AI review"
                         if finding.get("confirmed_by_llm") else "")
            lines.append(f"- {mark} **{sev}** ⚙ `{finding.get('file', '?')}`{line} — "
                         f"{finding.get('source', 'static')} {finding.get('rule', '')}: "
                         f"{finding.get('description', '')[:110]}{confirmed}")
        lines.append("")

    reviews = report.get("reviews", [])
    # Unremarkable brief-pass files and trivial files get a coverage line,
    # not a section each — keeps the document readable on big repos.
    skipped_stubs = [r for r in reviews
                    if r.get("trivial")
                    or (r.get("noted") is False and not r.get("issues")
                        and not r.get("static_findings"))]
    reviews = [r for r in reviews if r not in skipped_stubs]
    if reviews:
        lines += ["## Files", ""]
        for review in reviews:
            score_txt = f"{review['score']}/10" if review.get("score") is not None else "—"
            lines.append(f"### `{review.get('file', '?')}` — {score_txt}")
            if review.get("summary"):
                lines.append(review["summary"])
            for issue in review.get("issues", []):
                sev = str(issue.get("severity", "info")).lower()
                mark = _SEVERITY_MARKS.get(sev, "⚪")
                line = f" (line {issue['line']})" if issue.get("line") else ""
                lines.append(f"- {mark} {issue.get('title', '')}{line}"
                             + (f": {issue['description']}" if issue.get("description") else ""))
                if issue.get("suggestion"):
                    lines.append(f"  - *Fix:* {issue['suggestion']}")
            for finding in review.get("static_findings", []):
                sev = str(finding.get("severity", "info")).lower()
                mark = _SEVERITY_MARKS.get(sev, "⚪")
                line = f" (line {finding['line']})" if finding.get("line") else ""
                confirmed = (" — ✓ confirmed by AI review"
                             if finding.get("confirmed_by_llm") else "")
                lines.append(f"- {mark} ⚙ {finding.get('source', 'static')} "
                             f"`{finding.get('rule', '')}`{line}: "
                             f"{finding.get('description', '')}{confirmed}")
            lines.append("")

    if skipped_stubs:
        lines += [f"*{len(skipped_stubs)} further file(s) were reviewed and "
                  "found unremarkable (or trivial).*", ""]
    if overall.get("batches"):
        lines += [f"*Reviewed in {overall['batches']} batch(es) covering "
                  f"{overall.get('files_packed', '?')} files.*", ""]
    if overall.get("files_not_shown"):
        lines += [f"*{len(overall['files_not_shown'])} file(s) were not shown to "
                  "the model in this brief pass.*", ""]
    if report.get("failures"):
        lines += ["## Review failures", ""]
        lines += [f"- `{f['file']}`: {f['error']}" for f in report["failures"]]
        lines.append("")
    return "\n".join(lines)


def _quick_report(
    manifest: dict[str, Any],
    system_prompt: str,
    progress: ProgressFn | None,
    static_map: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Quick mode: static surface scan of EVERY file (no LLM, milliseconds),
    then ONE small LLM call over the findings table for the overview.
    Supplied deterministic findings merge straight into each file's issues."""
    files = manifest.get("files", [])
    reviews: list[dict[str, Any]] = []
    tally: list[dict[str, Any]] = []
    for entry in files:
        path, content = entry["path"], entry["content"]
        trivial = _trivial_review(path, content)
        if trivial is not None:
            reviews.append(trivial)
            continue
        issues = surface_scan(path, content)
        if static_map:
            issues += [dict(f) for f in static_map.get(path, [])]
        reviews.append({
            "file": path,
            "summary": f"Surface scan: {len(issues)} finding(s).",
            "issues": issues,
            "score": surface_score(issues),
        })
        if issues:
            tally.append({
                "file": path,
                "lines": content.count("\n") + 1,
                "flags": "; ".join(i["title"] for i in issues)[:150],
            })
    clean_count = len(files) - len(tally)

    if progress:
        progress(1, 1, f"surface-scanned {len(files)} files "
                       f"({len(tally)} flagged); asking model for overview")
    heartbeat = (
        (lambda msg: progress(1, 1, f"overview: {msg}")) if progress else None
    )
    digest = {
        "task": "quick_surface_review",
        "note": "The flags below come from static analysis of EVERY file in "
                "the repository; you are not shown source code. Give a quick "
                "surface-level verdict of the repo.",
        "flagged_files": tally[:200],
        "clean_files": clean_count,
        "total_files": len(files),
    }
    result = review_digest(make_client(), system_prompt, digest, heartbeat)

    report = _build_report(manifest, reviews, failures=[])
    report["mode"] = "quick"
    report["overall"] = {
        "summary": result.get("summary", ""),
        "score": result.get("score"),
        "key_issues": result.get("key_issues", []) or [],
        "files_packed": len(files),
        "files_not_shown": [],
    }
    return report


# Called after every COMPLETED unit with (reviews_so_far, failures_so_far),
# both in manifest order. Used to persist crash-recovery checkpoints.
CheckpointFn = Callable[[list[dict[str, Any]], list[dict[str, str]]], None]


def review_manifest(
    manifest: dict[str, Any],
    system_prompt: str,
    progress: ProgressFn | None = None,
    mode: str = "deep",
    checkpoint_cb: CheckpointFn | None = None,
    brief_state: dict[str, Any] | None = None,
    static_map: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Review an ingest manifest.

    mode "quick": static surface checks on ALL files + one tiny LLM overview
    call (fastest). mode "brief": one LLM call over a packed code digest
    (fast triage). mode "deep": one detailed LLM review per file (thorough);
    checkpoint_cb (if given) is invoked after each completed file so partial
    progress survives a crash.

    static_map ({path: [finding, ...]}, optional) carries deterministic
    scanner findings supplied from OUTSIDE the MCP (the platform hand-off):
    they are fed into the LLM prompts for verification/enrichment and
    attached to the report — the MCP itself never runs a scanner.
    """
    if mode == "quick":
        return _quick_report(manifest, system_prompt, progress, static_map)
    if mode == "brief":
        return _brief_report(manifest, system_prompt, progress, brief_state,
                             static_map)
    client = make_client()
    files = manifest.get("files", [])
    total = len(files)
    done_count = 0
    count_lock = threading.Lock()

    def review_one(index: int, entry: dict[str, Any]) -> dict[str, Any]:
        """Review one file (all its chunks sequentially); returns the merged
        review. Raises LLMUnavailableError (fatal) or others (per-file)."""
        nonlocal done_count
        path, content = entry["path"], entry["content"]
        language = entry.get("language", "unknown")
        trivial = _trivial_review(path, content)
        if trivial is not None:
            review = trivial
        else:
            # Heartbeats report the COMPLETED file count so "done" only
            # advances when a file's review actually finishes.
            def heartbeat(msg: str, p: str = path) -> None:
                with count_lock:
                    completed = done_count
                progress(completed, total, f"{p}: {msg}")
            heartbeat = heartbeat if progress else None
            # Announce the file as it starts, not only once a heartbeat
            # interval has passed. Otherwise the latest status names the file
            # that just FINISHED ("<path> done (n/N)") for the first seconds
            # of every file - and for the whole of any file quicker than one
            # heartbeat - so a progress view cannot tell which file is
            # actually being reviewed. The completed count is unchanged, so
            # this does not move "done" or the ETA.
            if heartbeat:
                heartbeat("reviewing")
            file_findings = (static_map or {}).get(path, [])
            chunks = split_content_with_lines(content, settings.max_chunk_chars)
            parts: list[dict[str, Any]] = []
            for chunk_index, (start_line, chunk) in enumerate(chunks, start=1):
                part = (chunk_index, len(chunks)) if len(chunks) > 1 else None
                parts.append(
                    review_chunk(
                        client, system_prompt, path, chunk, language, part,
                        heartbeat,
                        # Only pass when present so fakes and findings-less
                        # runs see the plain signature.
                        **({"static_findings": file_findings}
                           if file_findings else {}),
                        # Likewise: only chunked files need an offset, so an
                        # unchunked review keeps the plain call signature.
                        **({"start_line": start_line} if start_line > 1 else {}),
                    )
                )
            review = merge_parts(path, parts)
            _attach_static_findings(review, file_findings)
        if progress:
            with count_lock:
                done_count += 1
                done = done_count
            progress(done, total, f"{path} done ({done}/{total})")
        return review

    # Up to settings.parallel files in flight at once; results keep manifest
    # order regardless of completion order. Serial mode runs inline: no new
    # threads, so a review keeps working even if the MCP host disconnected
    # and the interpreter is already shutting down.
    reviews_by_index: dict[int, dict[str, Any]] = {}
    failures_by_index: dict[int, dict[str, str]] = {}

    def record(index: int, path: str, get_result) -> None:
        try:
            reviews_by_index[index] = get_result()
        except LLMUnavailableError:
            # Endpoint down or stream stalled: every remaining file would
            # fail the same way — abort the whole run.
            raise
        except Exception as exc:  # noqa: BLE001 - per-file failure
            failures_by_index[index] = {"file": path, "error": str(exc)}
        if checkpoint_cb:
            checkpoint_cb(
                [reviews_by_index[i] for i in sorted(reviews_by_index)],
                [failures_by_index[i] for i in sorted(failures_by_index)],
            )

    workers = max(1, min(settings.parallel, total or 1))
    if workers == 1:
        for i, entry in enumerate(files):
            record(i, entry["path"],
                   lambda i=i, e=entry: review_one(i + 1, e))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(review_one, i + 1, entry): (i, entry["path"])
                for i, entry in enumerate(files)
            }
            try:
                for future in as_completed(futures):
                    index, path = futures[future]
                    record(index, path, future.result)
            except BaseException:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

    reviews = [reviews_by_index[i] for i in sorted(reviews_by_index)]
    failures = [failures_by_index[i] for i in sorted(failures_by_index)]
    report = _build_report(manifest, reviews, failures)
    report["mode"] = mode
    return report


def compute_stats(
    reviews: list[dict[str, Any]],
    failures: list[dict[str, str]],
    skipped_count: int = 0,
    excluded_count: int = 0,
) -> dict[str, Any]:
    """Derive the stats block from the review entries themselves.

    Kept separate so a report built from scratch and one rebuilt after a
    retry merge cannot drift apart: both count the same way, from the same
    data, in one place.
    """
    by_severity = {sev: 0 for sev in SEVERITIES}
    for review in reviews:
        for issue in review.get("issues", []):
            sev = str(issue.get("severity", "info")).lower()
            by_severity[sev if sev in by_severity else "info"] += 1
    scores = [r["score"] for r in reviews if isinstance(r.get("score"), (int, float))]

    stats: dict[str, Any] = {
        "files_reviewed": len(reviews),
        "files_failed": len(failures),
        "files_skipped": skipped_count,
        "issues_total": sum(by_severity.values()),
        "issues_by_severity": by_severity,
        "average_score": round(sum(scores) / len(scores), 2) if scores else None,
    }
    # Deterministic findings ride inside the review entries, so recomputing
    # stats from reviews (e.g. after a checkpoint resume) keeps this count.
    static_total = sum(len(r.get("static_findings") or []) for r in reviews)
    if static_total:
        stats["static_findings"] = static_total
    # Files whose type is not reviewed at all. Carried into stats so a
    # report can never imply full coverage of a repository it only partly
    # read — "reviewed 2, skipped 0" of 57 files was exactly that.
    stats["files_excluded"] = excluded_count
    return stats


def merge_retry(existing: dict[str, Any],
                retry: dict[str, Any]) -> dict[str, Any]:
    """Fold a retry of previously-failed files into the report it belongs to.

    A deep run ends with files reviewed, skipped, or FAILED, and the
    failures are overwhelmingly "the model did not return valid JSON" —
    a response-format problem, not a verdict on the code. Measured on a real
    run (DEEP-001, 123 files): 19 failures spread across every file-size
    band, 7% of the smallest and 9% of the largest, so they are
    non-deterministic rather than a size limit. That is precisely the case a
    second attempt recovers.

    IDEMPOTENT: entries are keyed by file and REPLACED, never appended, so
    running a retry twice cannot duplicate a review or resurrect a fixed
    failure.
    """
    reviews = {r.get("file"): r for r in existing.get("reviews", [])}
    for entry in retry.get("reviews", []):
        reviews[entry.get("file")] = entry

    recovered = {r.get("file") for r in retry.get("reviews", [])}
    still_failing = {f.get("file"): f for f in retry.get("failures", [])}
    failures = [
        # A file that failed again carries its NEW error, not the stale one.
        still_failing.get(f.get("file"), f)
        for f in existing.get("failures", [])
        if f.get("file") not in recovered
    ]

    merged = dict(existing)
    merged["reviews"] = list(reviews.values())
    merged["failures"] = failures
    merged["stats"] = compute_stats(
        merged["reviews"], failures,
        skipped_count=len(existing.get("skipped") or []),
        excluded_count=(existing.get("excluded") or {}).get("count", 0),
    )
    merged["retried"] = {
        "attempted": len(retry.get("reviews", [])) + len(retry.get("failures", [])),
        "recovered": len(recovered),
        "still_failing": len(failures),
        "at": retry.get("generated_at"),
    }
    return merged


def _build_report(
    manifest: dict[str, Any],
    reviews: list[dict[str, Any]],
    failures: list[dict[str, str]],
) -> dict[str, Any]:
    stats = compute_stats(
        reviews, failures,
        skipped_count=len(manifest.get("skipped", [])),
        excluded_count=(manifest.get("excluded") or {}).get("count", 0),
    )
    excluded = manifest.get("excluded") or {}
    # What ANSWERED wins over what was asked for. A server configured with a
    # default model serves that one whatever the request named, so trusting
    # the request would attribute a review to a model that never saw the
    # code - and in a security report, which model produced a finding is
    # part of the finding. `last_model_used` is read from the responses
    # themselves; the requested name is only the fallback for when the
    # endpoint does not name one.
    served = llm.last_model_used
    requested = settings.lm_model
    report = {
        "repo_url": manifest.get("repo_url", "unknown"),
        "branch": manifest.get("branch", "default"),
        "commit": manifest.get("commit", "unknown"),
        "model": served or requested or "lm-studio-loaded-model",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "stats": stats,
        "reviews": reviews,
        "failures": failures,
        "skipped": manifest.get("skipped", []),
        "excluded": excluded,
    }
    if served and requested and served != requested:
        # Recorded rather than quietly resolved: a mismatch means the
        # endpoint is not serving what this deployment thinks it asked for,
        # which is worth seeing in the report instead of discovering later.
        report["model_requested"] = requested
    return report
