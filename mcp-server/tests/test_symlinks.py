"""A repository's symbolic links must never make the engine read outside it.

From a teammate's report, confirmed in a Linux container: collect_files used
rglob + read_text, which follow links, so a repository holding

    leak.py -> /proc/self/environ          (the worker's environment, token included)
    r.json  -> /reports/<someone-else>.json (another user's report)

sent those files to the model as if they were source. Popping GITHUB_TOKEN
from os.environ does not help: /proc/self/environ still has it.

Now no link is read. A link inside the repository is listed with its target
(that file is reviewed under its own name), a link out of it becomes a
`high` finding, and a broken one is skipped with the reason.
"""

import json
import os
from pathlib import Path

import pytest

from code_review_mcp import pipeline
from code_review_mcp.repo_ingest import (SYMLINK_ESCAPE_RULE, collect_files,
                                         symlink_finding)
from code_review_mcp.review import (_build_report, add_link_findings,
                                    compute_stats, render_markdown)

SECRET = "OUTSIDE-THE-REPO-SECRET-0123456789"


def _symlink(link: Path, target: str | Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        # Windows without Developer Mode cannot create links; Jenkins (Linux)
        # always runs these.
        pytest.skip(f"cannot create symbolic links here: {exc}")


@pytest.fixture
def outside(tmp_path):
    """A directory beside the repository, standing in for /reports."""
    out = tmp_path / "reports"
    out.mkdir()
    (out / "someone-else.json").write_text(json.dumps({"s": SECRET}),
                                           encoding="utf-8")
    (out / "secret.py").write_text(f"TOKEN = '{SECRET}'\n", encoding="utf-8")
    return out


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return root


def _links(result):
    return {link["path"]: link for link in result["symlinks"]}


def test_a_link_out_of_the_repository_is_not_read(repo, outside):
    _symlink(repo / "leak.py", outside / "secret.py")
    _symlink(repo / "r.json", outside / "someone-else.json")
    result = collect_files(repo)
    assert [f["path"] for f in result["files"]] == ["src/app.py"]
    assert SECRET not in json.dumps(result)
    assert _links(result)["leak.py"]["kind"] == "escape"
    assert _links(result)["r.json"]["kind"] == "escape"


def test_a_link_out_of_the_repository_is_a_high_finding(repo, outside):
    _symlink(repo / "leak.py", outside / "secret.py")
    findings = collect_files(repo)["security_findings"]
    assert len(findings) == 1
    assert findings[0]["file"] == "leak.py"
    assert findings[0]["rule"] == SYMLINK_ESCAPE_RULE
    assert findings[0]["severity"] == "high"
    assert str(outside / "secret.py") in findings[0]["description"]


@pytest.mark.skipif(not Path("/proc/self/environ").exists(),
                    reason="needs Linux /proc")
def test_proc_self_environ_is_not_read(repo, monkeypatch):
    """The exact case from the report, token in the environment and all."""
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    _symlink(repo / "leak.py", "/proc/self/environ")
    result = collect_files(repo)
    assert SECRET not in json.dumps(result)
    assert _links(result)["leak.py"] == {
        "path": "leak.py", "kind": "escape", "target": "/proc/self/environ"}


def test_a_linked_directory_is_not_walked(repo, outside):
    _symlink(repo / "stolen", outside)
    result = collect_files(repo)
    assert [f["path"] for f in result["files"]] == ["src/app.py"]
    assert SECRET not in json.dumps(result)
    assert _links(result)["stolen"]["kind"] == "escape"


def test_climbing_out_with_dot_dot_counts_as_escaping(repo, outside):
    _symlink(repo / "src" / "up.py", "../../reports/secret.py")
    result = collect_files(repo)
    assert _links(result)["src/up.py"]["kind"] == "escape"
    assert SECRET not in json.dumps(result)


def test_a_chain_of_links_is_judged_by_where_it_ends(repo, outside):
    _symlink(repo / "hop.py", outside / "secret.py")
    _symlink(repo / "start.py", "hop.py")       # inside, but leads out
    links = _links(collect_files(repo))
    assert links["start.py"]["kind"] == "escape"
    assert links["hop.py"]["kind"] == "escape"


def test_a_link_inside_the_repository_is_listed_not_read_twice(repo):
    _symlink(repo / "alias.py", "src/app.py")
    result = collect_files(repo)
    assert [f["path"] for f in result["files"]] == ["src/app.py"]
    assert _links(result)["alias.py"] == {
        "path": "alias.py", "kind": "internal", "target": "src/app.py"}
    assert result["security_findings"] == []
    assert result["skipped"] == []


def test_a_broken_link_is_skipped_with_the_reason(repo):
    _symlink(repo / "dead.py", "nowhere/missing.py")
    result = collect_files(repo)
    assert result["skipped"] == [{
        "path": "dead.py",
        "reason": "broken symbolic link (to nowhere/missing.py)"}]
    assert _links(result)["dead.py"]["kind"] == "broken"
    assert result["security_findings"] == []


def test_a_link_loop_is_broken_not_a_hang(repo):
    _symlink(repo / "a.py", "b.py")
    _symlink(repo / "b.py", "a.py")
    result = collect_files(repo)
    assert {s["path"] for s in result["skipped"]} == {"a.py", "b.py"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_fifo_is_ignored_instead_of_blocking(repo):
    os.mkfifo(repo / "pipe.py")
    result = collect_files(repo)          # would block forever if opened
    assert [f["path"] for f in result["files"]] == ["src/app.py"]


def test_a_repository_without_links_is_collected_as_before(repo):
    result = collect_files(repo)
    assert result["symlinks"] == []
    assert result["security_findings"] == []
    assert result["files"][0]["content"] == "print('hi')\n"


# ---------- the report ----------

def _report_with_links():
    links = [{"path": "leak.py", "kind": "escape", "target": "/proc/self/environ"},
             {"path": "alias.py", "kind": "internal", "target": "src/app.py"}]
    manifest = {"repo_url": "https://github.com/o/r", "commit": "c",
                "files": [{"path": "src/app.py"}], "skipped": [],
                "symlinks": links,
                "security_findings": [symlink_finding(links[0])]}
    reviews = [{"file": "src/app.py", "score": 9, "issues": []}]
    return add_link_findings(_build_report(manifest, reviews, []), manifest)


def test_the_finding_reaches_the_report_where_findings_are_read():
    report = _report_with_links()
    entry = next(r for r in report["reviews"] if r["file"] == "leak.py")
    assert entry["not_read"] is True and entry["issues"] == []
    (finding,) = entry["static_findings"]
    assert finding["severity"] == "high"
    assert finding["source"] == "ingest"
    assert finding["rule"] == SYMLINK_ESCAPE_RULE
    assert report["symlinks"][1]["kind"] == "internal"


def test_a_link_is_not_counted_as_a_reviewed_file():
    report = _report_with_links()
    assert report["stats"]["files_reviewed"] == 1
    assert report["stats"]["static_findings"] == 1
    # A later retry merge recounts from the entries: same answer.
    again = compute_stats(report["reviews"], [])
    assert again["files_reviewed"] == 1


def test_adding_the_findings_twice_does_not_duplicate_them():
    report = _report_with_links()
    manifest = {"symlinks": report["symlinks"],
                "security_findings": [symlink_finding(report["symlinks"][0])]}
    add_link_findings(report, manifest)
    assert [r["file"] for r in report["reviews"]].count("leak.py") == 1


def test_the_markdown_names_the_link_and_its_target():
    markdown = render_markdown(_report_with_links())
    assert "lead outside the repository" in markdown
    assert "`leak.py` → `/proc/self/environ`" in markdown
    assert "`alias.py` is a link to `src/app.py`" in markdown
    assert "symlink-escapes-repository" in markdown


def test_run_review_writes_the_finding_into_the_report(monkeypatch, tmp_path):
    link = {"path": "leak.py", "kind": "escape", "target": "/proc/self/environ"}

    def fake_ingest(repo_url, branch, extensions, **kwargs):
        return {"repo_url": repo_url, "commit": "abc", "file_count": 1,
                "files": [{"path": "a.py", "content": "x",
                           "language": "python"}],
                "skipped": [], "symlinks": [link],
                "security_findings": [symlink_finding(link)]}

    def fake_review(manifest, prompt, progress=None, mode="brief", **_):
        return _build_report(manifest, [{"file": "a.py", "score": 8,
                                         "issues": []}], [])

    monkeypatch.setattr(pipeline, "ingest_repository", fake_ingest)
    monkeypatch.setattr(pipeline, "review_manifest", fake_review)
    out = tmp_path / "r.json"
    pipeline.run_review("https://github.com/o/r", "review", str(out),
                        mode="quick")
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert [r["file"] for r in saved["reviews"]] == ["a.py", "leak.py"]
    assert saved["stats"]["files_reviewed"] == 1
    assert "leak.py" in out.with_suffix(".md").read_text(encoding="utf-8")
