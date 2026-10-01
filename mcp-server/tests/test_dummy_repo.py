"""Pipeline tests over the dummy vulnerable repo fixture.

`tests/fixtures/dummy_repo` plants exactly one instance of each surface-check
class (hardcoded secrets, eval, shell=True, pickle, bare except, DEBUG=True,
weak RNG, innerHTML, TODO) plus a clean file, a trivial file, and a
non-reviewable .txt. That lets the whole pipeline be exercised offline:
manifest building, quick-mode scanning, brief batching, and the full
crash -> checkpoint -> resume disaster-recovery cycle. No network, no LLM.
"""

import asyncio
import json
from pathlib import Path

from code_review_mcp.llm import LLMUnavailableError
from code_review_mcp.repo_ingest import collect_files
from code_review_mcp.review import review_manifest

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dummy_repo"


def dummy_manifest():
    """Build a fresh ingest-shaped manifest from the fixture tree."""
    collected = collect_files(FIXTURE_ROOT)
    return {
        "repo_url": "https://github.com/dummy/dummy-repo",
        "branch": "default",
        "commit": "f1x7ure0",
        "file_count": len(collected["files"]),
        "files": collected["files"],
        "skipped": collected["skipped"],
    }


# ---------- fixture integrity / manifest building ----------

def test_fixture_manifest_contents():
    manifest = dummy_manifest()
    paths = [f["path"] for f in manifest["files"]]
    assert paths == [
        "app/__init__.py", "app/clean.py", "app/config_settings.py",
        "app/main.py", "app/storage.py", "web/login.js",
    ]
    assert "notes.txt" not in paths          # extension allowlist enforced
    by_path = {f["path"]: f for f in manifest["files"]}
    assert by_path["app/main.py"]["language"] == "python"
    assert by_path["web/login.js"]["language"] == "javascript"


# ---------- quick mode over the fixture ----------

def test_quick_mode_finds_planted_issues(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(
        review_mod, "review_digest",
        lambda client, prompt, digest, heartbeat=None:
        {"summary": "Planted issues everywhere.", "score": 3,
         "key_issues": [], "files": []})

    report = review_manifest(dummy_manifest(), "review", mode="quick")
    by_path = {r["file"]: r for r in report["reviews"]}

    def titles(path):
        return [i["title"] for i in by_path[path].get("issues", [])]

    # Every planted issue class is detected in its file.
    assert any("hardcoded secret" in t.lower()
               for t in titles("app/config_settings.py"))
    assert any("Debug mode" in t for t in titles("app/config_settings.py"))
    assert any("randomness" in t.lower()
               for t in titles("app/config_settings.py"))
    assert any("eval" in t.lower() for t in titles("app/main.py"))
    assert any("Shell command" in t for t in titles("app/main.py"))
    assert any("TODO" in t for t in titles("app/main.py"))
    assert any("pickle" in t.lower() for t in titles("app/storage.py"))
    assert any("Bare except" in t for t in titles("app/storage.py"))
    assert any("innerHTML" in t for t in titles("web/login.js"))

    # The clean file stays clean; the empty file is trivial.
    assert titles("app/clean.py") == []
    assert by_path["app/clean.py"]["score"] == 9
    assert by_path["app/__init__.py"].get("trivial") is True


# ---------- brief mode over the fixture ----------

def test_brief_mode_covers_all_fixture_files(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 600)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 400)
    packed_files = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            packed_files.extend(f["file"] for f in digest["files"])
        return {"summary": "ok", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)
    report = review_manifest(dummy_manifest(), "review", mode="brief")

    # Every non-trivial file lands in exactly one batch.
    assert sorted(packed_files) == [
        "app/clean.py", "app/config_settings.py", "app/main.py",
        "app/storage.py", "web/login.js",
    ]
    assert report["overall"]["batches"] > 1
    assert report["stats"]["files_reviewed"] == 6


# ---------- disaster recovery: deep crash -> checkpoint -> resume ----------

def test_deep_crash_checkpoints_then_resume_completes(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, review as review_mod, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())

    llm_calls = []

    def dying_llm(client, prompt, path, *args, **kwargs):
        llm_calls.append(path)
        if len(llm_calls) == 3:               # dies reviewing app/main.py
            raise LLMUnavailableError("model crashed mid-run")
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", dying_llm)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p",
        review_id="DR-DEEP", mode="deep"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "error"
    assert "crashed" in status["error"]

    # The crash left a valid checkpoint: trivial __init__ + 2 reviewed files.
    ckpt_path = tmp_path / "DR-DEEP.partial.json"
    assert ckpt_path.is_file()
    ckpt = json.loads(ckpt_path.read_text(encoding="utf-8"))
    assert ckpt["progress"]["done"] == 3
    assert ckpt["progress"]["total"] == 6
    assert ckpt["commit"] == "f1x7ure0"

    # Second run, healthy model: resume must reuse the checkpointed reviews.
    monkeypatch.setattr(
        review_mod, "review_chunk",
        lambda client, prompt, path, *a, **k:
        {"file": path, "summary": "recovered", "issues": [], "score": 9})
    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p",
        review_id="DR-DEEP", mode="deep"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "done", status

    report = json.loads((tmp_path / "DR-DEEP.json").read_text(encoding="utf-8"))
    assert report["resumed"] is True
    assert report["reused_reviews"] == 3
    assert len(report["reviews"]) == 6        # full coverage after resume
    recovered = [r["file"] for r in report["reviews"]
                 if r.get("summary") == "recovered"]
    assert recovered == ["app/main.py", "app/storage.py", "web/login.js"]
    assert not ckpt_path.exists()             # final report replaced it


# ---------- disaster recovery: brief crash -> checkpoint -> resume ----------

def test_brief_crash_checkpoints_then_resume_completes(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, review as review_mod, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "brief_pack_chars", 300)
    monkeypatch.setattr(review_mod.settings, "brief_file_cap", 250)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())

    review_calls = []

    def dying_digest(client, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            review_calls.append(1)
            if len(review_calls) == 2:        # dies during batch 2
                raise LLMUnavailableError("model crashed mid-batch")
        return {"summary": "ok", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", dying_digest)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p",
        review_id="DR-BRIEF", mode="brief"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "error"

    ckpt_path = tmp_path / "DR-BRIEF.partial.json"
    assert ckpt_path.is_file()
    ckpt = json.loads(ckpt_path.read_text(encoding="utf-8"))
    assert ckpt["progress"]["done"] == 1      # batch 1 survived the crash
    assert list(ckpt["batch_results"]) == ["0"]
    total = ckpt["progress"]["total"]
    assert total > 2

    # Healthy model: resume reuses batch 1 and reviews only the rest.
    healthy_calls = []

    def healthy_digest(client, prompt, digest, heartbeat=None):
        if digest["task"] == "brief_repository_review":
            healthy_calls.append(1)
        return {"summary": "ok", "score": 6, "key_issues": [], "files": []}

    monkeypatch.setattr(review_mod, "review_digest", healthy_digest)
    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p",
        review_id="DR-BRIEF", mode="brief"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "done", status

    assert len(healthy_calls) == total - 1    # batch 0 was NOT re-reviewed
    report = json.loads((tmp_path / "DR-BRIEF.json").read_text(encoding="utf-8"))
    assert report["resumed"] is True
    assert report["reused_batches"] == 1
    assert not ckpt_path.exists()


# ---------- review plan: what a run set out to cover ----------

def test_plan_names_every_file_up_front_and_outlives_the_review(
        monkeypatch, tmp_path):
    """The checkpoint only ever lists FINISHED units, so a progress view has
    no way to name what is still pending. The plan is that denominator:
    written once, before any file is reviewed. Unlike the checkpoint it is
    kept when the review ends, because it is the only record of each file's
    size and line count - which the finished review's view still shows."""
    from code_review_mcp import pipeline, review as review_mod, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())

    plan_path = tmp_path / "DR-PLAN.plan.json"
    seen: dict = {}

    def capture_plan_then_review(client, prompt, path, *args, **kwargs):
        # Read on the first LLM call: the plan must already be complete
        # while the review is still running, not written at the end.
        seen.setdefault("plan", json.loads(
            plan_path.read_text(encoding="utf-8")))
        return {"file": path, "summary": "ok", "issues": [], "score": 8}

    monkeypatch.setattr(review_mod, "review_chunk", capture_plan_then_review)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p",
        review_id="DR-PLAN", mode="deep"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "done", status

    plan = seen["plan"]
    manifest_paths = [f["path"] for f in dummy_manifest()["files"]]
    assert [f["path"] for f in plan["files"]] == manifest_paths
    assert plan["commit"] == "f1x7ure0"
    assert plan["mode"] == "deep"
    assert plan_path.exists()  # kept beside the report, for its sizes


def test_plan_records_paths_only_never_file_contents(monkeypatch, tmp_path):
    """A repository's source is the most sensitive thing this system
    touches. The plan exists to answer "what is left" and "how long", so it
    carries paths, languages and sizes — never the code itself."""
    from code_review_mcp import pipeline

    manifest = dummy_manifest()
    plan_path = tmp_path / "P.plan.json"
    pipeline._write_plan(plan_path, manifest, "deep")

    raw = plan_path.read_text(encoding="utf-8")
    for entry in manifest["files"]:
        assert entry["path"] in raw
        if entry["content"]:  # the fixture has an empty __init__.py
            assert entry["content"] not in raw
    plan = json.loads(raw)
    assert set(plan["files"][0]) == {"path", "language", "size", "lines"}
    # Size and lines are counts of the content, which is how they stay
    # harmless.
    for entry, planned in zip(manifest["files"], plan["files"]):
        assert planned["size"] == len(entry["content"])
        assert planned["lines"] == len(entry["content"].splitlines())


def test_each_file_is_announced_as_it_starts(monkeypatch):
    """The progress view marks a file "running" by reading "<path>: ..." out
    of the latest status message. Heartbeats only fire every few seconds, so
    without an announcement at the START of each file, a quick file was
    never shown as running at all - the status went straight from the
    previous file's "done" message to this file's."""
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(
        review_mod, "review_chunk",
        lambda client, prompt, path, *a, **k:
        {"file": path, "summary": "ok", "issues": [], "score": 8})

    messages: list[str] = []
    manifest = dummy_manifest()
    review_mod.review_manifest(manifest, "p",
                               lambda i, t, m: messages.append(m), "deep")

    reviewed = [f["path"] for f in manifest["files"]
                if review_mod._trivial_review(f["path"], f["content"]) is None]
    assert reviewed, "the fixture must contain files that reach the model"
    for path in reviewed:
        started = messages.index(f"{path}: reviewing")
        finished = next(i for i, m in enumerate(messages)
                        if m.startswith(f"{path} done"))
        assert started < finished, path
