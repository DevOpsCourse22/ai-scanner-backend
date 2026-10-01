"""What the reports volume says about a review, without the job registry.

Both job stores keep their registry in memory, so a review-api restart (a
Pod rescheduled, the K3s server rebooting overnight) forgets every review.
The files on the reports volume do not forget, and between them they tell
the whole story:

    <id>.json            the finished report       -> completed
    <id>.paused.json     a user paused it          -> paused
    <id>.progress.json   a worker is still writing -> running, detached
                         (fresh updated_at)            from this process
    <id>.partial.json    work was checkpointed     -> interrupted (resumable)
    <id>.plan.json / .error.json  it started and stopped -> interrupted

`<id>.paused.json` is the one file this module adds. It is written when a
review is paused and removed when it is resumed or completes, and it holds
what a resume needs that the checkpoint does not: the branch, the model and
the provider. No credential is ever written to it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

PAUSED_SUFFIX = ".paused.json"

# Statuses a person can resume from. "interrupted" exists only on disk: the
# registry lost the review while a checkpoint survived it.
RESUMABLE = ("paused", "failed", "cancelled", "interrupted")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _path(output_dir: str | Path, review_id: str, suffix: str) -> Path:
    return Path(output_dir) / f"{review_id}{suffix}"


def write_paused(output_dir: str | Path, review_id: str,
                 fields: dict[str, Any]) -> None:
    """Record that a review is paused. Atomic, like every sidecar.

    Best effort: the in-memory status already says "paused", and losing the
    marker only matters if review-api also restarts before the resume.
    """
    data = {"paused_version": 1, "review_id": review_id,
            "paused_at": _now_iso(), **fields}
    data.pop("access_token", None)          # never, whatever a caller passes
    path = _path(output_dir, review_id, PAUSED_SUFFIX)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def read_paused(output_dir: str | Path, review_id: str) -> dict[str, Any] | None:
    return _read(_path(output_dir, review_id, PAUSED_SUFFIX))


def clear_paused(output_dir: str | Path, review_id: str) -> None:
    try:
        _path(output_dir, review_id, PAUSED_SUFFIX).unlink(missing_ok=True)
    except OSError:
        pass


def read_checkpoint(output_dir: str | Path, review_id: str) -> dict[str, Any] | None:
    return _read(_path(output_dir, review_id, ".partial.json"))


def read_progress(output_dir: str | Path, review_id: str) -> dict[str, Any] | None:
    return _read(_path(output_dir, review_id, ".progress.json"))


def checkpoint_units(ckpt: dict[str, Any] | None) -> int:
    """How many units a resume would reuse: reviewed files (deep) or
    finished batches (brief). 0 without a checkpoint."""
    if not ckpt:
        return 0
    if ckpt.get("mode") == "brief":
        return len(ckpt.get("batch_results") or {})
    return len(ckpt.get("reviews") or [])


def _percent(done: Any, total: Any) -> int | None:
    if isinstance(done, int) and isinstance(total, int) and total > 0:
        return round(100 * done / total)
    return None


def disk_status(output_dir: str | Path, review_id: str, *,
                stale_seconds: float) -> dict[str, Any] | None:
    """A status payload built from the reports volume alone, or None when
    nothing on it belongs to this review.

    Shaped like `Job.public()` for the fields a client reads, plus
    `"source": "disk"` so nobody mistakes it for live tracking.
    """
    base: dict[str, Any] = {"review_id": review_id, "source": "disk",
                            "pausable": False, "restored_units": 0}

    report = _read(_path(output_dir, review_id, ".json"))
    if report is not None:
        stats = report.get("stats") or {}
        return {**base, "status": "completed", "message": "review complete",
                "repo_url": report.get("repo_url"),
                "mode": report.get("mode"), "commit": report.get("commit"),
                "model": report.get("model"),
                "finished_at": report.get("generated_at"),
                "stats": stats or None, "percent": 100,
                "restartable": False, "resumable": False}

    ckpt = read_checkpoint(output_dir, review_id)
    progress = ckpt.get("progress") if ckpt else None
    done = (progress or {}).get("done")
    total = (progress or {}).get("total")
    counts = {"done": done, "total": total, "percent": _percent(done, total)}

    marker = read_paused(output_dir, review_id)
    if marker is not None:
        return {**base, **counts, "status": "paused",
                "message": "paused - resume any time",
                "repo_url": marker.get("repo_url"),
                "branch": marker.get("branch") or None,
                "mode": marker.get("mode"),
                "commit": marker.get("commit") or (ckpt or {}).get("commit"),
                "model": marker.get("model") or None,
                "paused_at": marker.get("paused_at"),
                "restartable": True, "resumable": True}

    live = read_progress(output_dir, review_id)
    updated = (live or {}).get("updated_at")
    if isinstance(updated, (int, float)) and time.time() - updated < stale_seconds:
        # A Job this process no longer tracks (review-api restarted while
        # it ran) is still writing. Resuming now would start a second
        # worker on the same checkpoint, so it is shown running instead.
        live_done, live_total = live.get("done"), live.get("total")
        return {**base, "status": live.get("phase") or "reviewing",
                "detached": True,
                "message": "running in a job this server no longer tracks "
                           "(it restarted); the result still lands here",
                "commit": live.get("commit"),
                "done": live_done, "total": live_total,
                "percent": _percent(live_done, live_total),
                "restored_units": live.get("reused") or 0,
                "restartable": False, "resumable": False}

    error = _read(_path(output_dir, review_id, ".error.json"))
    plan = _read(_path(output_dir, review_id, ".plan.json"))
    if ckpt or plan or error:
        source = ckpt or plan or {}
        return {**base, **counts, "status": "interrupted",
                "message": "stopped before it finished; resume continues "
                           "from the last checkpoint",
                "repo_url": source.get("repo_url"),
                "mode": source.get("mode"), "commit": source.get("commit"),
                "error": (error or {}).get("error"),
                "restartable": True, "resumable": True}
    return None
