"""Tests for the deterministic-findings intake (the platform hand-off).

The MCP runs no scanner; it consumes a findings JSON file produced outside
(the project's separate scanner component) and feeds those findings to the
LLM for verification/enrichment. These tests cover the loader, prompt
injection in all three modes, identity-preserving report attachment with
confirmed_by_llm, markdown rendering, and the server-level findings_file
path over the dummy repo fixture.
"""

import asyncio
import json
from pathlib import Path

import pytest

from code_review_mcp.findings import (
    FindingsError, load_findings_file, match_to_manifest,
)
from code_review_mcp.review import review_manifest
from test_dummy_repo import dummy_manifest


# ---------- loader ----------

def _write(tmp_path, payload):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_load_wrapped_shape_and_normalization(tmp_path):
    path = _write(tmp_path, {
        "source": "semgrep",
        "findings": [
            {"file": ".\\app\\main.py", "rule": "dangerous-eval",
             "severity": "ERROR", "line": 12, "description": "  eval  used "},
            {"path": "app/main.py", "rule": "todo-marker",
             "severity": "info", "line": 16},
            {"file": "app/storage.py", "rule": "pickle-load",
             "severity": "warning", "line": 9, "cwe": "CWE-502"},
            {"rule": "no-file-key"},                # invalid: no path
        ],
    })
    findings_map, meta = load_findings_file(path)
    assert set(findings_map) == {"app/main.py", "app/storage.py"}
    first = findings_map["app/main.py"][0]
    assert first["severity"] == "high"              # ERROR -> high
    assert first["line"] == 12
    assert first["source"] == "semgrep"
    assert first["description"] == "eval used"      # whitespace collapsed
    assert findings_map["app/storage.py"][0]["severity"] == "medium"
    assert findings_map["app/storage.py"][0]["cwe"] == "CWE-502"
    assert meta["findings_total"] == 3
    assert meta["invalid_entries"] == 1
    assert meta["findings_by_severity"]["high"] == 1


def test_load_bare_list_shape(tmp_path):
    path = _write(tmp_path, [
        {"file": "a.py", "severity": "critical", "rule": "r", "line": 1},
    ])
    findings_map, meta = load_findings_file(path)
    assert findings_map["a.py"][0]["severity"] == "critical"
    assert meta["source"] == "static"               # default source


def test_load_missing_and_invalid_files_raise(tmp_path):
    with pytest.raises(FindingsError, match="not found"):
        load_findings_file(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(FindingsError, match="not valid JSON"):
        load_findings_file(bad)
    wrong = _write(tmp_path, {"findings": "nope"})
    with pytest.raises(FindingsError, match="list"):
        load_findings_file(wrong)


def test_match_to_manifest_records_unmatched():
    fmap = {"app/main.py": [{"rule": "a"}], "ghost.py": [{"rule": "b"},
                                                         {"rule": "c"}]}
    meta = {}
    matched = match_to_manifest(fmap, ["app/main.py"], meta)
    assert set(matched) == {"app/main.py"}
    assert meta["unmatched"]["files"] == ["ghost.py"]
    assert meta["unmatched"]["findings_total"] == 2


# ---------- deep mode: injection + enrichment attachment ----------

def test_deep_mode_feeds_findings_to_llm_and_confirms(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    static_map = {"app/main.py": [
        {"source": "semgrep", "rule": "dangerous-eval", "severity": "high",
         "line": 13, "title": "dangerous-eval",
         "description": "eval of user input"}]}
    captured = {}

    def spy_llm(client, prompt, path, content, language, part=None,
                heartbeat=None, static_findings=None, **kwargs):
        captured[path] = static_findings
        return {"file": path, "summary": "ok", "score": 4,
                "issues": [{"severity": "high", "line": 14,
                            "title": "eval confirmed"}]}

    monkeypatch.setattr(review_mod, "review_chunk", spy_llm)
    report = review_manifest(dummy_manifest(), "prompt", mode="deep",
                             static_map=static_map)

    assert captured["app/main.py"][0]["rule"] == "dangerous-eval"
    assert captured["app/clean.py"] is None         # no findings -> plain call
    entry = next(r for r in report["reviews"] if r["file"] == "app/main.py")
    # LLM issue at line 14 is within 2 lines of the finding at line 13.
    assert entry["static_findings"][0]["confirmed_by_llm"] is True
    assert "static_findings" not in next(
        r for r in report["reviews"] if r["file"] == "app/clean.py")
    assert report["stats"]["static_findings"] == 1


# ---------- brief mode: static_flags in digests ----------

def test_brief_mode_packs_static_flags(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    static_map = {"app/storage.py": [
        {"source": "semgrep", "rule": "pickle-load", "severity": "medium",
         "line": 9, "title": "pickle-load",
         "description": "Unsafe deserialization."}]}
    digests = []

    def fake_digest(client, prompt, digest, heartbeat=None):
        digests.append(digest)
        return {"summary": "ok", "score": 5,
                "key_issues": [{"severity": "medium", "file": "app/storage.py",
                                "line": 9, "title": "pickle"}],
                "files": []}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)
    report = review_manifest(dummy_manifest(), "prompt", mode="brief",
                             static_map=static_map)

    flagged = [f for d in digests for f in d.get("files", [])
               if f.get("file") == "app/storage.py"]
    assert flagged and flagged[0]["static_flags"] == [
        "L9 medium: pickle-load — Unsafe deserialization."]
    assert any("deterministic" in d.get("note", "") for d in digests)
    entry = next(r for r in report["reviews"]
                 if r["file"] == "app/storage.py")
    assert entry["static_findings"][0]["confirmed_by_llm"] is True
    assert report["stats"]["static_findings"] == 1


# ---------- quick mode: merged into issues ----------

def test_quick_mode_merges_findings_into_issues(monkeypatch):
    from code_review_mcp import review as review_mod

    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    static_map = {"app/clean.py": [
        {"source": "gitleaks", "rule": "generic-api-key", "severity": "high",
         "line": 2, "title": "generic-api-key",
         "description": "Key-shaped string."}]}
    monkeypatch.setattr(
        review_mod, "review_digest",
        lambda client, prompt, digest, heartbeat=None:
        {"summary": "ok", "score": 6, "key_issues": [], "files": []})
    report = review_manifest(dummy_manifest(), "prompt", mode="quick",
                             static_map=static_map)

    entry = next(r for r in report["reviews"] if r["file"] == "app/clean.py")
    merged = [i for i in entry["issues"] if i.get("source") == "gitleaks"]
    assert merged and merged[0]["rule"] == "generic-api-key"
    assert entry["score"] < 9                       # finding lowered the score


# ---------- markdown rendering ----------

def test_render_markdown_shows_deterministic_findings():
    from code_review_mcp.review import render_markdown

    report = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "model": "m",
        "generated_at": "now", "mode": "deep",
        "stats": {"files_reviewed": 1, "files_failed": 0, "files_skipped": 0},
        "reviews": [{"file": "a.py", "summary": "s", "score": 5, "issues": [],
                     "static_findings": [{"source": "semgrep",
                                          "rule": "sql-injection",
                                          "severity": "high", "line": 3,
                                          "description": "SQL injection.",
                                          "confirmed_by_llm": True}]}],
        "failures": [],
    }
    md = render_markdown(report)
    assert "## Key issues" in md
    assert "⚙ `a.py` (line 3) — semgrep sql-injection" in md
    assert "semgrep `sql-injection` (line 3)" in md
    assert "confirmed by AI review" in md


# ---------- server level: findings_file end to end ----------

def test_job_with_findings_file(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, review as review_mod, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(pipeline, "ingest_repository",
                        lambda *a, **k: dummy_manifest())
    (tmp_path / "scan.json").write_text(json.dumps({
        "source": "semgrep",
        "findings": [
            {"file": "app/main.py", "rule": "dangerous-eval",
             "severity": "high", "line": 13, "description": "eval"},
            {"file": "not/in/repo.py", "rule": "ghost", "severity": "low"},
        ],
    }), encoding="utf-8")

    def spy_llm(client, prompt, path, *args, static_findings=None, **kwargs):
        return {"file": path, "summary": "ok", "score": 7,
                "issues": ([{"severity": "high", "line": 13,
                             "title": "confirmed"}]
                           if static_findings else [])}

    monkeypatch.setattr(review_mod, "review_chunk", spy_llm)
    server._jobs.clear()

    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p", review_id="FND-01",
        mode="deep", findings_file="scan.json"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=15)))
    assert status["status"] == "done", status

    report = json.loads((tmp_path / "FND-01.json").read_text(encoding="utf-8"))
    assert report["deterministic"]["source"] == "semgrep"
    assert report["deterministic"]["findings_total"] == 2
    # The out-of-repo finding is reported, not silently dropped.
    assert report["deterministic"]["unmatched"]["files"] == ["not/in/repo.py"]
    entry = next(r for r in report["reviews"] if r["file"] == "app/main.py")
    assert entry["static_findings"][0]["confirmed_by_llm"] is True
    assert report["stats"]["static_findings"] == 1

    # get_report summary carries the deterministic block + combined counts.
    summary = json.loads(server.get_report("FND-01.json"))
    assert summary["deterministic"]["findings_total"] == 2
    main_row = next(f for f in summary["files"] if f["file"] == "app/main.py")
    assert main_row["issues"] == 2                  # 1 LLM issue + 1 finding


def test_job_with_missing_findings_file_errors(monkeypatch, tmp_path):
    from code_review_mcp import pipeline, server

    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    server._jobs.clear()
    started = json.loads(server.start_review(
        "https://github.com/dummy/dummy-repo", "p", review_id="FND-02",
        mode="deep", findings_file="does-not-exist.json"))
    status = json.loads(asyncio.run(
        server.get_review_status(started["job_id"], wait_seconds=10)))
    assert status["status"] == "error"
    assert "not found" in status["error"]
