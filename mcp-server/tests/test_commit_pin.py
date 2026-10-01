"""Pinning a clone to one commit - what makes a resumed review reuse its
checkpoint even after the branch moved on.

Runs real git against a local repository (file://), so it checks the actual
fetch-by-SHA and checkout, not a mock of them.
"""

import subprocess

import pytest

from code_review_mcp import repo_ingest
from code_review_mcp.repo_ingest import IngestError, clone_repo


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def two_commit_repo(tmp_path, monkeypatch):
    """A repository whose branch tip moved after the first commit."""
    monkeypatch.setattr(repo_ingest.settings, "github_token", "")
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "t@example.com")
    _git(src, "config", "user.name", "t")
    (src / "a.py").write_text("print(1)\n")
    _git(src, "add", ".")
    _git(src, "commit", "-q", "-m", "first")
    first = _git(src, "rev-parse", "HEAD")
    (src / "a.py").write_text("print(2)\n")
    _git(src, "commit", "-q", "-am", "second")
    second = _git(src, "rev-parse", "HEAD")
    return f"file://{src}", first, second


def test_without_commit_clones_the_tip(tmp_path, two_commit_repo):
    url, _, second = two_commit_repo
    work = tmp_path / "w1"
    work.mkdir()
    assert clone_repo(url, work / "repo") == second


def test_commit_pins_the_clone_to_an_older_commit(tmp_path, two_commit_repo):
    url, first, _ = two_commit_repo
    work = tmp_path / "w2"
    work.mkdir()
    assert clone_repo(url, work / "repo", commit=first) == first
    assert (work / "repo" / "a.py").read_text() == "print(1)\n"


def test_commit_equal_to_the_tip_needs_no_fetch(tmp_path, two_commit_repo):
    url, _, second = two_commit_repo
    work = tmp_path / "w3"
    work.mkdir()
    assert clone_repo(url, work / "repo", commit=second.upper()) == second


def test_unknown_commit_fails_loudly(tmp_path, two_commit_repo):
    url, _, _ = two_commit_repo
    work = tmp_path / "w4"
    work.mkdir()
    with pytest.raises(IngestError, match="could not be fetched"):
        clone_repo(url, work / "repo", commit="0" * 40)


@pytest.mark.parametrize("bad", ["abc123", "z" * 40, "--upload-pack=x"])
def test_commit_must_be_a_full_sha(tmp_path, bad):
    with pytest.raises(IngestError, match="full 40-character SHA"):
        clone_repo("https://github.com/o/r", tmp_path / "repo", commit=bad)
