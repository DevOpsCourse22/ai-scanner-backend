"""A repository's symlinks must never be read as its source.

`collect_files` used to call is_file() and read_text(), and both follow
links. A repository shipping `leak.py -> /proc/self/environ`, or a link to
another review's report on the shared /reports volume, had that file read
and handed to the model as if it were code - verified on Linux before this
fix, including a token that had already been popped from os.environ.

Symlinks need a POSIX filesystem (or Windows developer mode) to create, so
each test skips where the platform refuses; Jenkins runs these on Linux.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from code_review_mcp.repo_ingest import collect_files


def _link(target: Path | str, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform
        pytest.skip(f"cannot create symlinks here: {exc}")


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return repo


def _reasons(result: dict) -> dict[str, str]:
    return {s["path"]: s["reason"] for s in result["skipped"]}


def test_link_to_another_review_is_not_read(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "other-review.json").write_text(
        '{"issues": "SOMEONE ELSES PRIVATE FINDINGS"}', encoding="utf-8")
    repo = _repo(tmp_path)
    _link(reports / "other-review.json", repo / "leak.py")

    result = collect_files(repo)

    assert [f["path"] for f in result["files"]] == ["app.py"]
    assert all("SOMEONE ELSES" not in f["content"] for f in result["files"])
    assert "outside the repository" in _reasons(result)["leak.py"]


@pytest.mark.skipif(not os.path.exists("/proc/self/environ"),
                    reason="needs /proc (Linux)")
def test_link_to_proc_environ_does_not_leak_a_popped_token(tmp_path, monkeypatch):
    # The worker pops GITHUB_TOKEN before the engine loads, but
    # /proc/self/environ is the process's ORIGINAL environment block and
    # still holds it. Simulated here with a variable set for this process.
    monkeypatch.setenv("CANARY_TOKEN", "ghp_canary_must_not_leak")
    repo = _repo(tmp_path)
    _link("/proc/self/environ", repo / "env.py")

    result = collect_files(repo)

    assert all("ghp_canary" not in f["content"] for f in result["files"])
    assert "env.py" in _reasons(result)


def test_link_inside_the_repository_is_recorded_not_read_twice(tmp_path):
    repo = _repo(tmp_path)
    _link(repo / "app.py", repo / "alias.py")

    result = collect_files(repo)

    assert [f["path"] for f in result["files"]] == ["app.py"]
    assert "inside the repository" in _reasons(result)["alias.py"]


def test_broken_link_is_recorded(tmp_path):
    repo = _repo(tmp_path)
    _link(tmp_path / "does-not-exist.py", repo / "gone.py")

    result = collect_files(repo)

    assert "broken symlink" in _reasons(result)["gone.py"]


def test_linked_directory_is_not_walked_into(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("API_KEY = 'outside'\n", encoding="utf-8")
    repo = _repo(tmp_path)
    _link(outside, repo / "shared")

    result = collect_files(repo)

    paths = [f["path"] for f in result["files"]]
    assert paths == ["app.py"]
    assert not any(p.startswith("shared/") for p in paths)
    assert "outside the repository" in _reasons(result)["shared"]
