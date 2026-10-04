"""The two v2 sidecars: <REVIEW_ID>.error.json and <REVIEW_ID>.progress.json.

error.json is how review-api learns WHY a Job failed without reading Pod
status (contract v2). progress.json is the live per-file timing a Job pod
cannot otherwise hand to review-api. Both are checked here through main(),
the progress file also through the real pipeline (clone and LLM faked).
"""

from __future__ import annotations

import json
import time

import pytest

import entrypoint
from code_review_mcp import pipeline
from code_review_mcp.llm import LLMUnavailableError
from code_review_mcp.repo_ingest import IngestError
from test_worker_entrypoint import (fake_run_review, job_env,  # noqa: F401
                                    output_dir)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------- error.json ----------------

@pytest.mark.parametrize("exc,permanent", [
    # Multi-line, as git's output is: both outputs must carry ONE line.
    (IngestError("warning: Could not find remote branch nope\nfatal: "
                 "Remote branch nope not found in upstream origin"),
     True),
    (LLMUnavailableError("cannot reach the model"), False),
    (RuntimeError("something nobody expected"), False),
])
def test_every_detected_failure_writes_error_json(monkeypatch, job_env,
                                                  output_dir, exc, permanent):
    monkeypatch.setattr(pipeline, "run_review",
                        fake_run_review([], raises=exc))
    code = entrypoint.main()
    error = read(output_dir / "rev-001.error.json")
    assert error["permanent"] is permanent
    assert (code == entrypoint.EXIT_PERMANENT) is permanent
    # The same line the termination log carries, and nothing else.
    assert set(error) == {"permanent", "error"}
    assert (job_env / "termination-log").read_text("utf-8").strip() \
        == error["error"]


def test_error_json_never_carries_the_token(monkeypatch, job_env, output_dir):
    from test_worker_entrypoint import TOKEN
    monkeypatch.setattr(pipeline, "run_review", fake_run_review(
        [], raises=RuntimeError(f"echoed {TOKEN}")))
    entrypoint.main()
    assert TOKEN not in (output_dir / "rev-001.error.json").read_text("utf-8")


def test_a_stale_error_from_an_earlier_attempt_is_removed_at_start(
        monkeypatch, job_env, output_dir):
    """Otherwise an attempt that dies without writing its own (OOM kill)
    would be judged by the previous attempt's reason."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stale = output_dir / "rev-001.error.json"
    stale.write_text('{"permanent": true, "error": "old"}', "utf-8")
    seen = []

    def run(*args, **kwargs):
        seen.append(stale.exists())
        return fake_run_review([])(*args, **kwargs)

    monkeypatch.setattr(pipeline, "run_review", run)
    assert entrypoint.main() == entrypoint.EXIT_OK
    assert seen == [False]
    assert not stale.exists()


def test_no_error_json_without_a_valid_review_id(monkeypatch, job_env,
                                                 output_dir):
    """No id, no file name to write to. review-api always sends a sanitized
    id, so this is a hand-written Job's problem, and the termination log
    still says what is wrong."""
    monkeypatch.setenv("REVIEW_ID", "../escape")
    assert entrypoint.main() == entrypoint.EXIT_PERMANENT
    assert not list(output_dir.glob("*.error.json"))
    assert "REVIEW_ID" in (job_env / "termination-log").read_text("utf-8")


# ---------------- progress.json: the tracker ----------------

def test_the_file_patterns_match_the_in_process_view():
    """One file, timed the same way in both modes. If jobs.py changes how it
    recognises a file starting or finishing, this must change with it."""
    jobs = pytest.importorskip("review_api.jobs")
    assert entrypoint._ACTIVE_FILE.pattern == jobs._ACTIVE_FILE.pattern
    assert entrypoint._FINISHED_FILE.pattern == jobs._FINISHED_FILE.pattern


def test_written_fresh_at_start(tmp_path):
    progress = entrypoint.ProgressFile(tmp_path / "r.progress.json")
    data = read(progress.path)
    assert data["current_file"] == "" and data["current_started_at"] is None
    assert data["durations"] == []
    assert abs(data["updated_at"] - time.time()) < 60   # epoch, not monotonic


def test_start_and_finish_are_written_heartbeats_are_not(tmp_path,
                                                         monkeypatch):
    clock = iter([1000.0, 1000.0, 1005.0, 1005.0, 1041.5, 1041.5])
    monkeypatch.setattr(entrypoint.time, "time", lambda: next(clock))
    progress = entrypoint.ProgressFile(tmp_path / "r.progress.json")
    writes = []
    original = progress.write
    progress.write = lambda: (writes.append(1), original())

    progress.on_message("src/a.py: reviewing")                 # t=1000
    assert read(progress.path)["current_file"] == "src/a.py"
    assert read(progress.path)["current_started_at"] == 1000.0
    progress.on_message("src/a.py: thinking (120 tokens streamed)")
    progress.on_message("src/a.py done (1/3)")                 # t=1041.5
    data = read(progress.path)
    assert data["durations"] == [["src/a.py", 41.5]]
    assert len(writes) == 2          # the start and the finish, no heartbeat


def test_heartbeats_refresh_updated_at_at_most_once_a_minute(tmp_path,
                                                             monkeypatch):
    """updated_at is review-api's stuck signal, so it must move while a
    review works — in quick and brief too, where no file ever starts — but
    without a PVC write for every 3-second token heartbeat."""
    now = {"t": 1000.0}
    monkeypatch.setattr(entrypoint.time, "time", lambda: now["t"])
    progress = entrypoint.ProgressFile(tmp_path / "r.progress.json")
    # Quick mode's one unit. Its first message counts as the unit starting
    # (written); the heartbeats after it are throttled.
    for t in (1010.0, 1030.0, 1069.0):
        now["t"] = t
        progress.on_message("overview: thinking (40 tokens streamed)")
    assert read(progress.path)["updated_at"] == 1010.0      # throttled
    now["t"] = 1071.0
    progress.on_message("overview: answering (900 tokens streamed)")
    assert read(progress.path)["updated_at"] == 1071.0
    now["t"] = 1200.0
    progress.touch()                                        # a status change
    data = read(progress.path)
    assert data["updated_at"] == 1200.0 and data["durations"] == []


def test_files_that_never_started_get_no_duration(tmp_path):
    """Trivial files (never sent to the model) and files restored from the
    checkpoint are reported done without starting; zero-second entries
    would drag every estimate down."""
    progress = entrypoint.ProgressFile(tmp_path / "r.progress.json")
    progress.on_message("app/__init__.py done (1/6)")
    progress.on_message("batch finished (2/10)")
    assert read(progress.path)["durations"] == []


def test_overlapping_files_are_each_timed_from_their_own_start(tmp_path,
                                                               monkeypatch):
    """REVIEW_PARALLEL > 1: files overlap; each duration is still exact."""
    now = {"t": 0.0}
    monkeypatch.setattr(entrypoint.time, "time", lambda: now["t"])
    progress = entrypoint.ProgressFile(tmp_path / "r.progress.json")
    now["t"] = 10.0
    progress.on_message("a.py: reviewing")
    now["t"] = 12.0
    progress.on_message("b.py: reviewing")
    now["t"] = 20.0
    progress.on_message("a.py done (1/2)")
    now["t"] = 30.0
    progress.on_message("b.py done (2/2)")
    assert read(progress.path)["durations"] == [["a.py", 10.0],
                                                ["b.py", 18.0]]


def test_a_failed_write_never_costs_the_review(tmp_path):
    progress = entrypoint.ProgressFile(tmp_path / "missing-dir" / "p.json")
    progress.on_message("a.py: reviewing")        # must not raise


# ---------------- progress.json: through the real pipeline ----------------

def test_deep_review_reports_the_running_file_then_cleans_up(
        monkeypatch, job_env, output_dir):
    from code_review_mcp import review as review_mod
    from test_dummy_repo import dummy_manifest

    monkeypatch.setenv("MODE", "deep")
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    progress_path = output_dir / "rev-001.progress.json"
    seen = []

    def llm(client, prompt, path, *args, **kwargs):
        # What review-api would read from the PVC while this file runs.
        seen.append((path, read(progress_path)))
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", llm)
    assert entrypoint.main() == entrypoint.EXIT_OK

    assert [s[0] for s in seen] == [s[1]["current_file"] for s in seen]
    # Each file sees the ones before it as finished, with durations.
    last_path, last = seen[-1]
    assert [d[0] for d in last["durations"]] == [s[0] for s in seen[:-1]]
    assert not progress_path.exists()               # deleted with the checkpoint
    assert not (output_dir / "rev-001.partial.json").exists()
    assert not (output_dir / "rev-001.error.json").exists()


def test_progress_carries_phase_counts_and_commit(
        monkeypatch, job_env, output_dir):
    """v3: in kubernetes mode progress.json is all review-api knows about a
    running review - the progress bar and a later pinned resume read it."""
    from code_review_mcp import review as review_mod
    from test_dummy_repo import dummy_manifest

    monkeypatch.setenv("MODE", "deep")
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    manifest = dummy_manifest()
    monkeypatch.setattr(pipeline, "ingest_repository", lambda *a, **k: manifest)
    seen = []

    def llm(client, prompt, path, *args, **kwargs):
        seen.append(read(output_dir / "rev-001.progress.json"))
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", llm)
    assert entrypoint.main() == entrypoint.EXIT_OK

    assert all(s["phase"] == "reviewing" for s in seen)
    assert all(s["commit"] == manifest["commit"] for s in seen)
    # Trivial files are never sent to the model, so total may exceed the
    # calls seen; done only moves forward and is never ahead of the total.
    assert seen[-1]["total"] >= len(seen)
    dones = [s["done"] or 0 for s in seen]
    assert dones == sorted(dones) and dones[-1] < seen[-1]["total"]
    assert all(s["reused"] == 0 for s in seen)


def test_a_crashed_attempt_leaves_error_json_and_the_retry_clears_it(
        monkeypatch, job_env, output_dir):
    from code_review_mcp import review as review_mod
    from test_dummy_repo import dummy_manifest

    monkeypatch.setenv("MODE", "deep")
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    calls = []

    def dying(client, prompt, path, *args, **kwargs):
        calls.append(path)
        if len(calls) == 3:
            raise LLMUnavailableError("model crashed mid-run")
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", dying)
    assert entrypoint.main() == entrypoint.EXIT_RETRYABLE
    assert read(output_dir / "rev-001.error.json")["permanent"] is False
    before = read(output_dir / "rev-001.progress.json")
    assert len(before["durations"]) == 2

    # The retry: a new process. Its durations start empty, so the files
    # restored from the checkpoint never enter the estimate.
    seen = []

    def healthy(client, prompt, path, *args, **kwargs):
        seen.append(read(output_dir / "rev-001.progress.json"))
        return {"file": path, "summary": "ok", "issues": [], "score": 9}

    monkeypatch.setattr(review_mod, "review_chunk", healthy)
    assert entrypoint.main() == entrypoint.EXIT_OK
    assert seen[0]["durations"] == []
    assert not (output_dir / "rev-001.error.json").exists()
    assert not (output_dir / "rev-001.progress.json").exists()


# ---------------- keep-alive through bounded silent phases ----------------
#
# Stuck detection (review-api) kills a Job whose progress.json has not moved
# for 15 minutes. The clone and the scanners report no progress of their own,
# and the scanners alone may run up to 3 x 900 s - so a large repo's scan was
# killed as stuck on every attempt. These phases are each bounded by a
# timeout, so keeping the file alive through them is safe. The AI phase is
# not kept alive: a model that stops answering must go stale.

FAST = 0.05


def _progress(tmp_path, monkeypatch):
    monkeypatch.setattr(entrypoint, "HEARTBEAT_WRITE_SECONDS", FAST)
    return entrypoint.ProgressFile(tmp_path / "r.progress.json")


def _updated_at(tmp_path):
    return read(tmp_path / "r.progress.json")["updated_at"]


@pytest.mark.parametrize("phase", ["cloning", "scanning"])
def test_a_bounded_silent_phase_keeps_progress_fresh(tmp_path, monkeypatch,
                                                     phase):
    progress = _progress(tmp_path, monkeypatch)
    first = _updated_at(tmp_path)
    keepalive = entrypoint.PhaseKeepAlive(progress, interval=FAST)
    try:
        keepalive.on_status(phase)
        time.sleep(FAST * 6)
        assert _updated_at(tmp_path) > first
    finally:
        keepalive.stop()


def test_the_ai_phase_is_never_kept_alive(tmp_path, monkeypatch):
    """A model that stops answering must be allowed to look stuck."""
    progress = _progress(tmp_path, monkeypatch)
    keepalive = entrypoint.PhaseKeepAlive(progress, interval=FAST)
    keepalive.on_status("reviewing")
    first = _updated_at(tmp_path)
    time.sleep(FAST * 6)
    assert not keepalive.running
    assert _updated_at(tmp_path) == first


def test_entering_the_ai_phase_stops_the_ticker(tmp_path, monkeypatch):
    progress = _progress(tmp_path, monkeypatch)
    keepalive = entrypoint.PhaseKeepAlive(progress, interval=FAST)
    keepalive.on_status("cloning")
    keepalive.on_status("scanning")
    keepalive.on_status("reviewing")
    assert not keepalive.running
    frozen = _updated_at(tmp_path)
    time.sleep(FAST * 6)
    assert _updated_at(tmp_path) == frozen


def test_cloning_then_scanning_share_one_ticker(tmp_path, monkeypatch):
    progress = _progress(tmp_path, monkeypatch)
    keepalive = entrypoint.PhaseKeepAlive(progress, interval=FAST)
    try:
        keepalive.on_status("cloning")
        ticker = keepalive._thread
        keepalive.on_status("scanning")
        assert keepalive._thread is ticker and keepalive.running
    finally:
        keepalive.stop()


def test_main_keeps_progress_alive_through_a_long_scan(monkeypatch, job_env,
                                                        output_dir):
    """End to end through main(): a scan that is silent for many heartbeat
    intervals still refreshes progress.json, and no ticker survives the
    review."""
    import threading

    monkeypatch.setattr(entrypoint, "HEARTBEAT_WRITE_SECONDS", FAST)
    writes = []
    real_write = entrypoint.write_json_atomic

    def counting_write(path, data):
        if path.name.endswith(".progress.json"):
            writes.append(time.monotonic())
        real_write(path, data)

    monkeypatch.setattr(entrypoint, "write_json_atomic", counting_write)
    window = {}

    def long_silent_scan(repo_url, prompt, output_path, **kwargs):
        kwargs["on_status"]("cloning")
        kwargs["on_status"]("scanning")
        window["start"] = time.monotonic()
        time.sleep(FAST * 8)            # a long, silent, bounded step
        window["end"] = time.monotonic()
        kwargs["on_status"]("reviewing")
        out = pipeline._resolve_output(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("{}", encoding="utf-8")
        return {"_output_path": str(out)}

    monkeypatch.setattr(pipeline, "run_review", long_silent_scan)

    assert entrypoint.main() == entrypoint.EXIT_OK
    during = [t for t in writes if window["start"] < t <= window["end"]]
    assert len(during) >= 3, f"only {len(during)} writes during the scan"
    assert not any(t.name == "progress-keepalive" and t.is_alive()
                   for t in threading.enumerate())
