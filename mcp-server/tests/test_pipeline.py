"""Unit tests for the non-LLM parts of the pipeline (no network needed)."""

import json

import pytest

from code_review_mcp.llm import LLMUnavailableError, extract_json
from code_review_mcp.repo_ingest import IngestError, collect_files, validate_repo_url
from code_review_mcp.review import (
    merge_parts,
    render_markdown,
    review_manifest,
    split_content,
    _build_report,
)


# ---------- URL validation ----------

def test_valid_github_url():
    assert validate_repo_url("https://github.com/owner/repo") == "https://github.com/owner/repo"
    assert validate_repo_url("https://github.com/owner/repo.git/") == "https://github.com/owner/repo.git"


@pytest.mark.parametrize("url", [
    "http://gitlab.com/owner/repo",
    "github.com/owner/repo",
    "https://github.com/owner",
    "not a url",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(IngestError):
        validate_repo_url(url)


# ---------- JSON extraction ----------

def test_extract_plain_json():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_fenced_json():
    assert extract_json('Here you go:\n```json\n{"a": 1}\n```\nDone!') == {"a": 1}


def test_extract_json_with_preamble():
    assert extract_json('Sure! {"a": 1} Hope that helps.') == {"a": 1}


def test_extract_garbage_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json("no json here at all")


# ---------- file collection ----------

def test_collect_files_filters(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    (tmp_path / "readme.md").write_text("# docs", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("x", encoding="utf-8")
    (tmp_path / "data.bin").write_bytes(b"\x00\xff\x00\xff")

    result = collect_files(tmp_path)
    paths = [f["path"] for f in result["files"]]
    assert paths == ["app.py"]
    assert result["files"][0]["language"] == "python"


def test_collect_files_skips_non_utf8(tmp_path):
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00\x00garbage")
    result = collect_files(tmp_path)
    assert result["files"] == []
    assert result["skipped"][0]["reason"].startswith("not valid UTF-8")


def test_collect_files_reviews_infrastructure_as_code(tmp_path):
    """A Kubernetes repo is mostly YAML. Reviewing only its .js files reads
    the app and ignores everything that deploys it — which is how a review
    of kubernetes-exercises covered 2 of 57 files."""
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "02-secrets.yaml").write_text("kind: Secret",
                                                      encoding="utf-8")
    (tmp_path / "k8s" / "deploy.yml").write_text("kind: Deployment",
                                                 encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}',
                                      encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER root",
                                         encoding="utf-8")
    (tmp_path / "Dockerfile.prod").write_text("FROM alpine", encoding="utf-8")
    (tmp_path / "server.js").write_text("const a = 1;", encoding="utf-8")

    result = collect_files(tmp_path)
    by_path = {f["path"]: f["language"] for f in result["files"]}
    assert by_path == {
        "Dockerfile": "dockerfile",
        "Dockerfile.prod": "dockerfile",
        "k8s/02-secrets.yaml": "yaml",
        "k8s/deploy.yml": "yaml",
        "main.tf": "terraform",
        "server.js": "javascript",
    }


def test_collect_files_counts_what_it_excluded(tmp_path):
    """Unreviewable files are counted, not dropped in silence: a report that
    says "reviewed 2, skipped 0" of 57 files reads as full coverage."""
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    (tmp_path / "notes.md").write_text("# hi", encoding="utf-8")
    (tmp_path / "other.md").write_text("# ho", encoding="utf-8")

    excluded = collect_files(tmp_path)["excluded"]
    assert excluded["count"] == 3
    assert excluded["by_type"] == {".md": 2, ".png": 1}
    assert sorted(excluded["examples"]) == ["logo.png", "notes.md", "other.md"]


def test_an_explicit_extension_filter_is_taken_literally(tmp_path):
    """Asking for .py must not also hand back a Dockerfile: the name-based
    match is a default convenience, not an override of what was requested."""
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM alpine", encoding="utf-8")

    result = collect_files(tmp_path, {".py"})
    assert [f["path"] for f in result["files"]] == ["app.py"]
    assert result["excluded"]["by_type"] == {"dockerfile": 1}


def test_dotenv_is_never_collected_by_default(tmp_path):
    """A .env exists to hold credentials; sending one to a model would put
    live secrets in its context for no review value."""
    (tmp_path / ".env").write_text("AWS_SECRET_ACCESS_KEY=hunter2",
                                   encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")

    result = collect_files(tmp_path)
    assert [f["path"] for f in result["files"]] == ["app.py"]


def test_report_states_the_coverage_it_did_not_have():
    report = _build_report(
        {"repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
         "excluded": {"count": 55, "by_type": {".yaml": 30, ".md": 25},
                      "examples": ["k8s/01-namespace.yaml"]}},
        [{"file": "server.js", "issues": [], "score": 5}], failures=[])

    assert report["stats"]["files_excluded"] == 55
    markdown = render_markdown(report)
    assert "55 file(s) were not reviewed" in markdown
    assert "`.yaml` ×30" in markdown


def test_full_coverage_says_nothing_about_exclusions():
    report = _build_report(
        {"repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
         "excluded": {"count": 0, "by_type": {}, "examples": []}},
        [{"file": "server.js", "issues": [], "score": 5}], failures=[])

    assert "were not reviewed" not in render_markdown(report)


# ---------- chunking ----------

def test_split_small_content_single_chunk():
    assert split_content("short", 100) == ["short"]


def test_split_respects_line_boundaries():
    content = "\n".join(f"line {i}" for i in range(100)) + "\n"
    chunks = split_content(content, 200)
    assert len(chunks) > 1
    assert all(len(c) <= 200 for c in chunks)
    assert "".join(chunks) == content  # lossless


# ---------- merging ----------

def test_merge_single_part_passthrough():
    part = {"file": "a.py", "summary": "ok", "issues": [], "score": 8}
    assert merge_parts("a.py", [part]) is part


def test_merge_multiple_parts():
    parts = [
        {"file": "a.py", "summary": "first half", "issues": [{"severity": "high"}],
         "positives": ["clean"], "score": 6},
        {"file": "a.py", "summary": "second half", "issues": [{"severity": "low"}],
         "positives": [], "score": 8},
    ]
    merged = merge_parts("a.py", parts)
    assert merged["file"] == "a.py"
    assert len(merged["issues"]) == 2
    assert merged["score"] == 7
    assert merged["chunked"] == 2


# ---------- error semantics ----------

def test_unavailable_llm_aborts_run(monkeypatch):
    """Endpoint-down / stall errors must abort the run, not fill failures."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)

    def dead_llm(*args, **kwargs):
        raise LLMUnavailableError("endpoint unreachable")

    monkeypatch.setattr(review_mod, "review_chunk", dead_llm)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": "a.py", "content": "x = 1\n" * 50, "language": "python"}],
    }
    with pytest.raises(LLMUnavailableError):
        review_manifest(manifest, "review this")


def test_parse_failure_is_per_file_not_fatal(monkeypatch):
    """Ordinary per-file errors go to failures and the run continues."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    calls = []

    def flaky_llm(client, prompt, path, *args, **kwargs):
        calls.append(path)
        if path == "bad.py":
            raise ValueError("unparseable json")
        return {"file": path, "summary": "ok", "issues": [], "score": 9}

    monkeypatch.setattr(review_mod, "review_chunk", flaky_llm)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "bad.py", "content": "x = 1\n" * 50, "language": "python"},
            {"path": "good.py", "content": "y = 2\n" * 50, "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review this")
    assert calls == ["bad.py", "good.py"]  # run continued past the failure
    assert report["stats"]["files_failed"] == 1
    assert report["stats"]["files_reviewed"] == 1


def test_heartbeat_reaches_progress(monkeypatch):
    """Heartbeat messages from streaming surface through the progress fn."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)

    def streaming_llm(client, prompt, path, content, language, part=None,
                      heartbeat=None, mode="deep", **kwargs):
        heartbeat("answering (42 tokens streamed)")
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", streaming_llm)
    seen = []
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": "a.py", "content": "x = 1\n" * 50, "language": "python"}],
    }
    review_manifest(manifest, "review this", lambda i, t, msg: seen.append(msg))
    assert any("a.py done" in m for m in seen)  # completion notification
    assert any("42 tokens streamed" in m for m in seen)  # streaming heartbeat


# ---------- background review jobs ----------

def test_job_lifecycle(monkeypatch, tmp_path):
    """start_review returns instantly; get_review_status tracks to 'done'."""
    import asyncio

    from code_review_mcp import pipeline, server

    def fake_ingest(repo_url, branch, extensions, **kwargs):
        return {"repo_url": repo_url, "commit": "abc123", "file_count": 1,
                "files": [{"path": "a.py", "content": "x", "language": "python"}],
                "skipped": []}

    def fake_review(manifest, prompt, progress=None, mode="brief", checkpoint_cb=None, **_):
        if progress:
            progress(1, 1, "a.py")
        return {"stats": {"files_reviewed": 1, "files_failed": 0}, "failures": [],
                "reviews": [], "skipped": [], "mode": mode}

    monkeypatch.setattr(pipeline, "ingest_repository", fake_ingest)
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()

    out = tmp_path / "job-report.json"
    started = json.loads(server.start_review(
        "https://github.com/o/r", "review", str(out)))
    assert started["status"] == "started"

    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "done", status
    assert status["stats"]["files_reviewed"] == 1
    assert out.exists()


def test_second_job_rejected_while_running(monkeypatch, tmp_path):
    import time as time_mod

    from code_review_mcp import pipeline, server

    release = {"go": False}

    def slow_ingest(repo_url, branch, extensions, **kwargs):
        while not release["go"]:
            time_mod.sleep(0.02)
        return {"repo_url": repo_url, "commit": "abc", "file_count": 0,
                "files": [], "skipped": []}

    monkeypatch.setattr(pipeline, "ingest_repository", slow_ingest)
    server._jobs.clear()

    first = json.loads(server.start_review("https://github.com/o/r", "p",
                                           str(tmp_path / "r.json")))
    second = json.loads(server.start_review("https://github.com/o/r2", "p",
                                            str(tmp_path / "r2.json")))
    release["go"] = True
    assert first["status"] == "started"
    assert second["status"] == "already_running"
    assert second["job_id"] == first["job_id"]


def test_unknown_job_id():
    import asyncio

    from code_review_mcp import pipeline, server

    status = json.loads(asyncio.run(server.get_review_status("nope1234")))
    assert status["status"] == "unknown_job"


# ---------- brief mode (one-shot digest) & trivial files ----------

def test_trivial_file_skips_llm_in_deep_mode(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    llm_calls = []

    def spy_llm(client, prompt, path, *args, **kwargs):
        llm_calls.append(path)
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", spy_llm)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "__init__.py", "content": "", "language": "python"},
            {"path": "real.py", "content": "x = 1\n" * 50, "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review", mode="deep")
    assert llm_calls == ["real.py"]  # empty file never reached the LLM
    trivial = next(r for r in report["reviews"] if r["file"] == "__init__.py")
    assert trivial.get("trivial") is True


def test_pack_digest_batches_cover_every_file(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 3000)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 2000)
    files = [
        {"path": "small.py", "content": "y = 2\n" * 20},      # 120 chars
        {"path": "big.py", "content": "x = 1\n" * 1000},      # capped 2000
        {"path": "huge.py", "content": "z = 3\n" * 2000},     # capped 2000
        {"path": "__init__.py", "content": ""},               # trivial
    ]
    batches, trivial = review_mod.pack_digest_batches(files)
    packed = [f["file"] for batch in batches for f in batch]
    # EVERY non-trivial file lands in exactly one batch — nothing dropped.
    assert sorted(packed) == ["big.py", "huge.py", "small.py"]
    assert all(sum(len(f["code"]) for f in b) <= 3000 for b in batches)
    assert len(batches) == 2                       # 120+2000, then 2000
    assert [t["file"] for t in trivial] == ["__init__.py"]
    big = next(f for b in batches for f in b if f["file"] == "big.py")
    # The cap applies to the NUMBERED text that is actually sent, and the
    # cut lands on a line boundary — so it reaches the cap without exceeding
    # it, and never leaves a line number with half a line beside it.
    assert big["truncated"]
    assert 1900 <= len(big["code"]) <= 2000
    assert big["code"].endswith("x = 1\n")


def test_brief_multi_batch_merges(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)
    calls = []

    def fake_digest_review(client, prompt, digest, heartbeat=None):
        calls.append(digest["task"])
        if digest["task"] == "merge_brief_batches":
            return {"summary": "Merged verdict.", "score": 6, "key_issues": [],
                    "files": []}
        batch_file = digest["files"][0]["file"]
        return {"summary": f"batch with {batch_file}", "score": 6,
                "key_issues": [{"severity": "high", "file": batch_file,
                                "title": "issue"}],
                "files": [{"file": batch_file, "note": "seen", "score": 6}]}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest_review)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "a.py", "content": "x" * 250, "language": "python"},
            {"path": "b.py", "content": "y" * 250, "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review", mode="brief")
    assert calls == ["brief_repository_review", "brief_repository_review",
                     "merge_brief_batches"]
    assert report["overall"]["summary"] == "Merged verdict."
    assert report["overall"]["batches"] == 2
    # both files present in reviews[], both noted
    assert {r["file"] for r in report["reviews"]} == {"a.py", "b.py"}
    assert report["stats"]["issues_by_severity"]["high"] == 2


def test_brief_mode_single_llm_call(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    calls = []

    def fake_digest_review(client, prompt, digest, heartbeat=None):
        calls.append(digest)
        return {
            "summary": "Small demo repo, decent quality.",
            "score": 7,
            "key_issues": [
                {"severity": "high", "file": "app.py", "line": 3,
                 "title": "SQL injection"},
            ],
            "files": [
                {"file": "app.py", "note": "entry point, one bad query", "score": 5},
            ],
        }

    monkeypatch.setattr(review_mod, "review_digest", fake_digest_review)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "app.py", "content": "q = f'select {x}'\n" * 20,
             "language": "python"},
            {"path": "util.py", "content": "def f():\n    return 1\n" * 20,
             "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review", mode="brief")
    assert len(calls) == 1                       # exactly ONE LLM call
    assert report["mode"] == "brief"
    assert report["overall"]["score"] == 7
    assert report["stats"]["issues_by_severity"]["high"] == 1
    entry = report["reviews"][0]
    assert entry["file"] == "app.py"
    assert entry["issues"][0]["title"] == "SQL injection"


# ---------- long-poll status ----------

def test_status_long_poll_returns_when_job_finishes(monkeypatch, tmp_path):
    import asyncio
    import time as time_mod

    from code_review_mcp import pipeline, server

    def fake_ingest(repo_url, branch, extensions, **kwargs):
        time_mod.sleep(0.3)  # keep the job briefly busy
        return {"repo_url": repo_url, "commit": "abc", "file_count": 1,
                "files": [{"path": "a.py", "content": "x", "language": "python"}],
                "skipped": []}

    def fake_review(manifest, prompt, progress=None, mode="brief", checkpoint_cb=None, **_):
        return {"stats": {"files_reviewed": 1, "files_failed": 0}, "failures": [],
                "reviews": [], "skipped": [], "mode": mode}

    monkeypatch.setattr(pipeline, "ingest_repository", fake_ingest)
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", str(tmp_path / "r.json")))
    start_time = time_mod.monotonic()
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    elapsed = time_mod.monotonic() - start_time
    assert status["status"] == "done"          # waited through to completion
    assert elapsed < 8                          # returned early, not full 10s
    assert set(status) <= {"status", "stats", "report", "markdown", "next"}  # compact


def test_status_progress_fields_while_running(monkeypatch):
    import asyncio
    import time as time_mod

    from code_review_mcp import pipeline, server

    server._jobs.clear()
    server._jobs["j1"] = {
        "job_id": "j1", "status": "reviewing", "mode": "deep",
        "started_monotonic": time_mod.monotonic() - 60,  # 60s elapsed
        # eta_seconds is precomputed on advance by the job's progress fn
        "progress": {"file": 30, "total": 120, "message": "...",
                     "eta_seconds": 180},
    }
    status = json.loads(asyncio.run(server.get_review_status("j1", wait_seconds=0)))
    assert status["status"] == "reviewing"
    assert status["done"] == 30 and status["total"] == 120
    assert status["remaining"] == 90
    assert status["percent"] == 25
    assert status["elapsed_seconds"] >= 59
    assert status["eta_seconds"] == 180
    assert "25%" in status["progress"] and "90 left" in status["progress"]
    assert "files done" in status["progress"]


def test_progress_done_counts_only_completed_units(monkeypatch, tmp_path):
    """During a brief batch, heartbeats must report COMPLETED batches (not the
    in-progress index), and 'done' advances only when a batch finishes."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)

    seen_done = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        if digest["task"] == "merge_brief_batches":
            return {"summary": "m", "score": 5, "key_issues": [], "files": []}
        if heartbeat:
            heartbeat("answering (10 tokens)")  # mid-batch heartbeat
        return {"summary": "s", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)

    def progress(done, total, message):
        seen_done.append(done)

    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": f"f{i}.py", "content": "x" * 250,
                   "language": "python"} for i in range(3)],
    }
    review_mod.review_manifest(manifest, "p", progress, mode="brief")
    # Heartbeat during batch 1 must report 0 completed, not 1.
    assert seen_done[0] == 0
    # done is non-decreasing and ends at the batch count.
    assert seen_done == sorted(seen_done)
    assert max(seen_done) == 3


def test_status_progress_before_first_file(monkeypatch):
    import asyncio

    from code_review_mcp import pipeline, server

    server._jobs.clear()
    server._jobs["j2"] = {"job_id": "j2", "status": "cloning", "mode": "brief",
                          "started_monotonic": None}
    status = json.loads(asyncio.run(server.get_review_status("j2", wait_seconds=0)))
    assert status["status"] == "cloning"
    assert "cloning / preparing" in status["progress"]


def test_start_review_rejects_bad_mode(tmp_path):
    from code_review_mcp import pipeline, server

    server._jobs.clear()
    result = json.loads(server.start_review(
        "https://github.com/o/r", "p", str(tmp_path / "r.json"), mode="turbo"))
    assert result["status"] == "error"


# ---------- context-safe report iteration ----------

def test_report_entry_iteration_and_notes(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    server._jobs.clear()
    (tmp_path / "r1.json").write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")

    first = json.loads(server.get_report_entry("r1.json", 0))
    assert first["review"]["file"] == "a.py"
    assert first["remaining"] == 1

    last = json.loads(server.get_report_entry("r1.json", 1))
    assert last["review"]["file"] == "b.py"
    assert last["remaining"] == 0
    assert "read_report_notes" in last["next"]

    out_of_range = json.loads(server.get_report_entry("r1.json", 5))
    assert out_of_range["status"] == "out_of_range"

    json.loads(server.append_report_notes("r1.json", "## a.py\nLooks fine."))
    json.loads(server.append_report_notes("r1.json", "## b.py\nOne high issue."))
    notes = json.loads(server.read_report_notes("r1.json"))
    assert "## a.py" in notes["text"] and "## b.py" in notes["text"]
    assert notes["next_offset"] is None


def test_read_report_notes_paging(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    server._jobs.clear()
    (tmp_path / "r1.json").write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
    server.append_report_notes("r1.json", "x" * 9000)

    page1 = json.loads(server.read_report_notes("r1.json", 0))
    assert len(page1["text"]) == 6000
    assert page1["next_offset"] == 6000
    page2 = json.loads(server.read_report_notes("r1.json", page1["next_offset"]))
    assert page2["next_offset"] is None
    assert page1["text"] + page2["text"] == "x" * 9000 + "\n\n"


# ---------- parallel dispatch ----------

def _concurrency_probe():
    """Returns (tracker_fn, state) — tracker records max simultaneous calls."""
    import threading as th
    import time as time_mod

    state = {"active": 0, "max_active": 0}
    lock = th.Lock()

    def track():
        with lock:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        time_mod.sleep(0.15)  # hold the slot so overlap is observable
        with lock:
            state["active"] -= 1

    return track, state


def test_deep_reviews_run_in_parallel(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "parallel", 4)
    track, state = _concurrency_probe()

    def slow_llm(client, prompt, path, *args, **kwargs):
        track()
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", slow_llm)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": f"f{i}.py", "content": "x = 1\n" * 50,
                   "language": "python"} for i in range(4)],
    }
    report = review_manifest(manifest, "review", mode="deep")
    assert state["max_active"] >= 2, "no overlap — reviews ran serially"
    # order stability: reviews follow manifest order despite parallelism
    assert [r["file"] for r in report["reviews"]] == [f"f{i}.py" for i in range(4)]


def test_brief_batches_run_in_parallel(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "parallel", 4)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)
    track, state = _concurrency_probe()

    def slow_digest(client, prompt, digest, heartbeat=None):
        if digest["task"] != "merge_brief_batches":
            track()
        return {"summary": "s", "score": 7, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", slow_digest)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": f"f{i}.py", "content": "x" * 250,
                   "language": "python"} for i in range(4)],
    }
    report = review_manifest(manifest, "review", mode="brief")
    assert report["overall"]["batches"] == 4
    assert state["max_active"] >= 2, "no overlap — batches ran serially"


def test_parallel_deep_failure_isolation(monkeypatch):
    """One bad file must not kill parallel siblings; unavailable LLM must."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "parallel", 4)

    def flaky_llm(client, prompt, path, *args, **kwargs):
        if path == "bad.py":
            raise ValueError("garbage json")
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", flaky_llm)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "bad.py", "content": "x" * 100, "language": "python"},
            {"path": "good.py", "content": "y" * 100, "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review", mode="deep")
    assert report["stats"]["files_failed"] == 1
    assert report["stats"]["files_reviewed"] == 1


# ---------- quick mode (surface scan) ----------

def test_surface_scan_finds_issues():
    from code_review_mcp.surface import surface_scan, surface_score

    code = (
        'password = "hunter2secret"\n'
        "import pickle\n"
        "data = pickle.loads(blob)\n"
        "try:\n    pass\nexcept:\n    pass\n"
        "# TODO fix this\n"
    )
    issues = surface_scan("app.py", code)
    titles = [i["title"] for i in issues]
    assert any("hardcoded secret" in t.lower() for t in titles)
    assert any("pickle" in t.lower() for t in titles)
    assert any("bare except" in t.lower() for t in titles)
    assert any("TODO" in t for t in titles)
    assert issues[0]["line"] == 1  # secret on line 1
    assert surface_score(issues) < surface_score([])


def test_surface_scan_clean_file():
    from code_review_mcp.surface import surface_scan

    assert surface_scan("clean.py", "def add(a, b):\n    return a + b\n") == []


def test_asserts_ignored_in_test_files():
    from code_review_mcp.surface import surface_scan

    code = "assert 1 == 1\n"
    assert any("Assert" in i["title"] for i in surface_scan("app.py", code))
    assert not any("Assert" in i["title"] for i in surface_scan("tests/test_app.py", code))


def test_quick_mode_scans_all_files_one_llm_call(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    llm_calls = []

    def fake_digest_review(client, prompt, digest, heartbeat=None):
        llm_calls.append(digest)
        return {"summary": "Surface issues in one file.", "score": 6,
                "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest_review)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [
            {"path": "bad.py", "content": 'password = "hunter2secret"\n' * 10,
             "language": "python"},
            {"path": "ok.py", "content": "def f():\n    return 1\n" * 20,
             "language": "python"},
        ],
    }
    report = review_manifest(manifest, "review", mode="quick")
    assert len(llm_calls) == 1                    # exactly one LLM call
    assert report["mode"] == "quick"
    assert report["stats"]["files_reviewed"] == 2  # ALL files covered
    digest = llm_calls[0]
    assert [f["file"] for f in digest["flagged_files"]] == ["bad.py"]
    assert digest["clean_files"] == 1
    bad = next(r for r in report["reviews"] if r["file"] == "bad.py")
    assert any("secret" in i["title"].lower() for i in bad["issues"])


# ---------- files filter ----------

def test_match_files_paths_and_globs():
    from code_review_mcp.server import _match_files

    manifest = {"files": [
        {"path": "DjangoWebApp/src/voter/views.py"},
        {"path": "DjangoWebApp/src/candidate/admin.py"},
        {"path": "SMPC/rsa.cpp"},
    ], "file_count": 3}

    exact = _match_files(manifest, ["DjangoWebApp/src/voter/views.py"])
    assert [f["path"] for f in exact["files"]] == ["DjangoWebApp/src/voter/views.py"]

    by_name = _match_files(manifest, ["admin.py"])
    assert [f["path"] for f in by_name["files"]] == ["DjangoWebApp/src/candidate/admin.py"]

    by_glob = _match_files(manifest, ["DjangoWebApp/*"])
    assert by_glob["file_count"] == 2

    nothing = _match_files(manifest, ["nope.py"])
    assert nothing["file_count"] == 0


def test_job_with_files_filter(monkeypatch, tmp_path):
    import asyncio

    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))

    def fake_ingest(repo_url, branch, extensions, **kwargs):
        return {"repo_url": repo_url, "commit": "abc", "file_count": 2,
                "files": [
                    {"path": "a/keep.py", "content": "x" * 100, "language": "python"},
                    {"path": "b/drop.py", "content": "y" * 100, "language": "python"},
                ], "skipped": []}

    seen_files = []

    def fake_review(manifest, prompt, progress=None, mode="brief", checkpoint_cb=None, **_):
        seen_files.extend(f["path"] for f in manifest["files"])
        return {"repo_url": manifest["repo_url"], "commit": "abc", "model": "m",
                "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": manifest["file_count"],
                          "files_failed": 0, "files_skipped": 0},
                "reviews": [], "failures": [], "skipped": []}

    monkeypatch.setattr(pipeline, "ingest_repository", fake_ingest)
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", review_id="scoped", files=["keep.py"]))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "done"
    assert seen_files == ["a/keep.py"]  # only the requested file was reviewed

    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", files=["missing.py"]))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "error"
    assert "No files matched" in status["error"]


# ---------- self-healing: checkpoints & resume ----------

def _healing_manifest(commit="abc"):
    return {"repo_url": "https://github.com/o/r", "commit": commit,
            "file_count": 3, "skipped": [],
            "files": [{"path": f"f{i}.py", "content": "x = 1\n" * 50,
                       "language": "python"} for i in range(3)]}


def test_checkpoint_cb_called_per_completed_file(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "parallel", 1)
    monkeypatch.setattr(
        review_mod, "review_chunk",
        lambda c, p, path, *a, **k: {"file": path, "summary": "ok",
                                     "issues": [], "score": 8})
    snapshots = []
    review_manifest(_healing_manifest(), "p", mode="deep",
                    checkpoint_cb=lambda r, f: snapshots.append(len(r)))
    assert snapshots == [1, 2, 3]  # cumulative after each completed file


def test_deep_job_resumes_from_checkpoint(monkeypatch, tmp_path):
    import asyncio

    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: _healing_manifest())

    # Simulate a crashed earlier run: 2 of 3 files already checkpointed.
    ckpt = {"checkpoint_version": 1, "repo_url": "https://github.com/o/r",
            "commit": "abc", "mode": "deep", "updated_at": "earlier",
            "progress": {"done": 2, "total": 3},
            "reviews": [
                {"file": "f0.py", "summary": "from ckpt", "issues": [], "score": 7},
                {"file": "f1.py", "summary": "from ckpt", "issues": [], "score": 7},
            ], "failures": []}
    (tmp_path / "HEAL-01.partial.json").write_text(json.dumps(ckpt),
                                                   encoding="utf-8")

    reviewed = []

    def fake_review(manifest, prompt, progress=None, mode="deep",
                    checkpoint_cb=None):
        reviewed.extend(f["path"] for f in manifest["files"])
        return {"repo_url": manifest["repo_url"], "commit": "abc", "model": "m",
                "generated_at": "now", "mode": mode,
                "stats": {}, "failures": [], "skipped": [],
                "reviews": [{"file": f["path"], "summary": "new", "issues": [],
                             "score": 9} for f in manifest["files"]]}

    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", review_id="HEAL-01", mode="deep"))
    assert "resuming" in started  # checkpoint noticed up front
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "done"

    assert reviewed == ["f2.py"]  # only the missing file was re-reviewed
    report = json.loads((tmp_path / "HEAL-01.json").read_text(encoding="utf-8"))
    assert report["resumed"] is True and report["reused_reviews"] == 2
    assert [r["summary"] for r in report["reviews"]] == ["from ckpt",
                                                         "from ckpt", "new"]
    assert not (tmp_path / "HEAL-01.partial.json").exists()  # cleaned up


def test_checkpoint_ignored_on_commit_mismatch(monkeypatch, tmp_path):
    import asyncio

    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: _healing_manifest(commit="NEW"))
    ckpt = {"repo_url": "https://github.com/o/r", "commit": "OLD",
            "mode": "deep", "progress": {"done": 2, "total": 3},
            "reviews": [{"file": "f0.py", "summary": "stale", "issues": [],
                         "score": 1}], "failures": []}
    (tmp_path / "HEAL-02.partial.json").write_text(json.dumps(ckpt),
                                                   encoding="utf-8")
    reviewed = []

    def fake_review(manifest, prompt, progress=None, mode="deep",
                    checkpoint_cb=None):
        reviewed.extend(f["path"] for f in manifest["files"])
        return {"repo_url": manifest["repo_url"], "commit": "NEW", "model": "m",
                "generated_at": "now", "mode": mode, "stats": {},
                "failures": [], "skipped": [], "reviews": []}

    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", review_id="HEAL-02", mode="deep"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "done"
    assert reviewed == ["f0.py", "f1.py", "f2.py"]  # full re-review, no stale reuse
    report = json.loads((tmp_path / "HEAL-02.json").read_text(encoding="utf-8"))
    assert "resumed" not in report


def test_unknown_job_lists_resumable_checkpoints(monkeypatch, tmp_path):
    import asyncio

    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    ckpt = {"repo_url": "https://github.com/o/r", "commit": "abc",
            "mode": "deep", "updated_at": "2026-07-08T00:00:00Z",
            "progress": {"done": 71, "total": 123}, "reviews": [],
            "failures": []}
    (tmp_path / "DEEP-01.partial.json").write_text(json.dumps(ckpt),
                                                   encoding="utf-8")
    server._jobs.clear()
    status = json.loads(asyncio.run(server.get_review_status("a239662a")))
    assert status["status"] == "unknown_job"
    assert status["resumable_checkpoints"][0]["review"] == "DEEP-01"
    assert status["resumable_checkpoints"][0]["done"] == 71
    assert "start_review" in status["hint"]


def test_status_carries_anti_hallucination_contract(monkeypatch):
    import asyncio

    from code_review_mcp import pipeline, server

    server._jobs.clear()
    server._jobs["j9"] = {"job_id": "j9", "status": "reviewing", "mode": "deep",
                          "started_monotonic": None,
                          "progress": {"file": 1, "total": 3}}
    status = json.loads(asyncio.run(server.get_review_status("j9",
                                                             wait_seconds=0)))
    assert "Never claim to be monitoring" in status["do"]


# ---------- markdown rendering & dual output ----------

def test_render_markdown_brief_shape():
    from code_review_mcp.review import render_markdown

    report = {
        "repo_url": "https://github.com/o/r", "commit": "abcdef123456",
        "model": "m", "generated_at": "2026-07-03T00:00:00Z", "mode": "brief",
        "stats": {"files_reviewed": 2, "files_failed": 0, "files_skipped": 1},
        "overall": {"summary": "Solid little repo.", "score": 7,
                    "key_issues": [{"severity": "critical", "file": "a.py",
                                    "line": 3, "title": "SQL injection"}],
                    "files_not_shown": ["big.bin"]},
        "reviews": [{"file": "a.py", "summary": "entry point", "score": 5,
                     "issues": [{"severity": "critical", "line": 3,
                                 "title": "SQL injection"}]}],
        "failures": [],
    }
    md = render_markdown(report)
    assert "# Code Review: https://github.com/o/r" in md
    assert "## Verdict: 7/10" in md
    assert "Solid little repo." in md
    assert "🔴 **critical** `a.py` (line 3) — SQL injection" in md
    assert "### `a.py` — 5/10" in md
    assert "1 file(s) were not shown" in md


def test_job_writes_json_and_markdown(monkeypatch, tmp_path):
    import asyncio

    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))

    def fake_ingest(repo_url, branch, extensions, **kwargs):
        return {"repo_url": repo_url, "commit": "abc", "file_count": 1,
                "files": [{"path": "a.py", "content": "x", "language": "python"}],
                "skipped": []}

    def fake_review(manifest, prompt, progress=None, mode="brief", checkpoint_cb=None, **_):
        return {"repo_url": manifest["repo_url"], "commit": "abc", "model": "m",
                "generated_at": "now", "mode": mode,
                "stats": {"files_reviewed": 1, "files_failed": 0,
                          "files_skipped": 0},
                "overall": {"summary": "Fine.", "score": 8, "key_issues": []},
                "reviews": [{"file": "a.py", "summary": "ok", "issues": [],
                             "score": 8}],
                "failures": [], "skipped": []}

    monkeypatch.setattr(pipeline, "ingest_repository", fake_ingest)
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    server._jobs.clear()

    # review_id names both files (and is sanitized).
    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", review_id="TICKET 42/a"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "done"
    assert (tmp_path / "TICKET_42_a.json").exists()
    assert (tmp_path / "TICKET_42_a.md").exists()
    assert status["markdown"].endswith("TICKET_42_a.md")
    md = (tmp_path / "TICKET_42_a.md").read_text(encoding="utf-8")
    assert "## Verdict: 8/10" in md and "Fine." in md


# ---------- report retrieval ----------

SAMPLE_REPORT = {
    "repo_url": "https://github.com/o/r", "commit": "abc", "model": "m",
    "generated_at": "2026-07-02T00:00:00Z",
    "stats": {"files_reviewed": 2, "files_failed": 0},
    "reviews": [
        {"file": "a.py", "score": 9, "issues": []},
        {"file": "b.py", "score": 4,
         "issues": [{"severity": "high", "title": "bug"}]},
    ],
    "failures": [],
}


def _output_dir(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, server
    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    return server


def test_windows_path_sanitized_in_container(monkeypatch, tmp_path):
    server = _output_dir(monkeypatch, tmp_path)
    resolved = server._resolve_output(r"C:\reports\evoting.json")
    assert resolved == tmp_path / "evoting.json"  # basename under output dir


def test_list_and_get_report_summary(monkeypatch, tmp_path):
    server = _output_dir(monkeypatch, tmp_path)
    (tmp_path / "r1.json").write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")

    listing = json.loads(server.list_reports())
    assert [r["name"] for r in listing["reports"]] == ["r1.json"]

    summary = json.loads(server.get_report("r1.json"))
    assert summary["stats"]["files_reviewed"] == 2
    assert {"file": "b.py", "score": 4, "issues": 1} in summary["files"]


def test_get_report_single_file_and_full(monkeypatch, tmp_path):
    server = _output_dir(monkeypatch, tmp_path)
    (tmp_path / "r1.json").write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")

    entry = json.loads(server.get_report("r1.json", file="b.py"))
    assert entry["issues"][0]["title"] == "bug"

    full = json.loads(server.get_report("r1.json", full=True))
    assert full == SAMPLE_REPORT


def test_get_report_by_job_id(monkeypatch, tmp_path):
    server = _output_dir(monkeypatch, tmp_path)
    path = tmp_path / "jobreport.json"
    path.write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
    server._jobs.clear()
    server._jobs["deadbeef"] = {"job_id": "deadbeef", "status": "done",
                                "output_path": str(path)}
    summary = json.loads(server.get_report("deadbeef"))
    assert summary["report"] == "jobreport.json"


def test_get_report_missing(monkeypatch, tmp_path):
    server = _output_dir(monkeypatch, tmp_path)
    server._jobs.clear()
    result = json.loads(server.get_report("nothere.json"))
    assert result["status"] == "not_found"


# ---------- report building ----------

def test_build_report_stats():
    manifest = {"repo_url": "https://github.com/o/r", "commit": "abc", "skipped": []}
    reviews = [
        {"file": "a.py", "issues": [{"severity": "critical"}, {"severity": "weird"}],
         "score": 5},
        {"file": "b.py", "issues": [], "score": 9},
    ]
    report = _build_report(manifest, reviews, failures=[{"file": "c.py", "error": "boom"}])
    stats = report["stats"]
    assert stats["files_reviewed"] == 2
    assert stats["files_failed"] == 1
    assert stats["issues_total"] == 2
    assert stats["issues_by_severity"]["critical"] == 1
    assert stats["issues_by_severity"]["info"] == 1  # unknown severity folded into info
    assert stats["average_score"] == 7.0


# ---------- brief checkpoint + resume ----------

def _brief_manifest(n_files=4):
    return {"repo_url": "https://github.com/o/r", "commit": "abc",
            "skipped": [],
            "files": [{"path": f"f{i}.py", "language": "python",
                       "content": f"x{i} = {i}\n" * 40} for i in range(n_files)]}


def _small_batches(monkeypatch, review_mod):
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)


def _batch_result(tag):
    return {"summary": f"batch {tag}", "score": 6, "key_issues": [],
            "files": []}


def test_brief_checkpoint_written_after_every_batch(monkeypatch):
    from code_review_mcp import review as review_mod

    _small_batches(monkeypatch, review_mod)
    monkeypatch.setattr(
        review_mod, "review_digest",
        lambda client, prompt, digest, heartbeat=None: _batch_result("x"))
    checkpoints = []
    review_manifest(
        _brief_manifest(), "prompt", mode="brief",
        brief_state={"checkpoint":
                     lambda results, total: checkpoints.append((dict(results), total))})

    total = checkpoints[-1][1]
    assert total > 1                                  # multi-batch run
    assert len(checkpoints) == total                  # one write per batch
    assert sorted(checkpoints[-1][0]) == list(range(total))  # all batches saved


def test_brief_resume_skips_preloaded_batches(monkeypatch):
    from code_review_mcp import review as review_mod

    _small_batches(monkeypatch, review_mod)
    llm_calls = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        llm_calls.append(digest.get("task"))
        return _batch_result("new")

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)
    # First run to learn the batch count.
    full = review_manifest(_brief_manifest(), "prompt", mode="brief")
    total = full["overall"]["batches"]
    assert total > 1

    # Resume with batch 0 preloaded (string key, as JSON round-trips it).
    llm_calls.clear()
    report = review_manifest(
        _brief_manifest(), "prompt", mode="brief",
        brief_state={"preloaded": {"0": _batch_result("old")}, "total": total})
    review_calls = [c for c in llm_calls if c == "brief_repository_review"]
    assert len(review_calls) == total - 1             # batch 0 not re-reviewed
    assert report["resumed"] is True
    assert report["reused_batches"] == 1
    assert report["overall"]["batches"] == total


def test_brief_resume_discards_stale_batch_count(monkeypatch):
    from code_review_mcp import review as review_mod

    _small_batches(monkeypatch, review_mod)
    llm_calls = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        llm_calls.append(digest.get("task"))
        return _batch_result("new")

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)
    report = review_manifest(
        _brief_manifest(), "prompt", mode="brief",
        brief_state={"preloaded": {"0": _batch_result("old")}, "total": 99})
    total = report["overall"]["batches"]
    review_calls = [c for c in llm_calls if c == "brief_repository_review"]
    assert len(review_calls) == total                 # everything re-reviewed
    assert "resumed" not in report


def test_brief_job_resumes_from_checkpoint_file(monkeypatch, tmp_path):
    """Server-level: a brief .partial.json from a killed container is loaded,
    completed batches are reused, and the checkpoint is deleted on success."""
    import asyncio

    from code_review_mcp import pipeline, review as review_mod, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    _small_batches(monkeypatch, review_mod)
    manifest = _brief_manifest()
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda repo_url, branch, extensions, **k: dict(
                            manifest, file_count=len(manifest["files"])))
    llm_calls = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        llm_calls.append(digest.get("task"))
        return _batch_result("new")

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)

    # Learn the batch count with a throwaway run.
    total = review_manifest(manifest, "p", mode="brief")["overall"]["batches"]
    llm_calls.clear()

    ckpt = {"checkpoint_version": 1, "repo_url": manifest["repo_url"],
            "commit": "abc", "mode": "brief", "system_prompt": "p",
            "progress": {"done": 1, "total": total},
            "batch_results": {"0": _batch_result("old")}}
    (tmp_path / "BRIEF-X.partial.json").write_text(json.dumps(ckpt),
                                                   encoding="utf-8")

    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/o/r", "p", review_id="BRIEF-X", mode="brief"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "done", status

    review_calls = [c for c in llm_calls if c == "brief_repository_review"]
    assert len(review_calls) == total - 1             # batch 0 reused
    report = json.loads((tmp_path / "BRIEF-X.json").read_text(encoding="utf-8"))
    assert report["resumed"] is True and report["reused_batches"] == 1
    assert not (tmp_path / "BRIEF-X.partial.json").exists()  # replaced by report
