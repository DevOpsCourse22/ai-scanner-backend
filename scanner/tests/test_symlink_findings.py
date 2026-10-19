"""A symlink that leaves the repository is a finding (symlinks.py).

Symlinks need a POSIX filesystem (or Windows developer mode) to create, so
each test skips where the platform refuses; Jenkins runs these on Linux.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from repo_scanner.runner import scan_repository
from repo_scanner.symlinks import RULE, escaping_symlinks


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


def test_link_to_a_sensitive_path_is_high(tmp_path):
    repo = _repo(tmp_path)
    _link("/proc/self/environ", repo / "env.py")

    [finding] = escaping_symlinks(str(repo))

    assert finding["file"] == "env.py"
    assert finding["rule"] == RULE
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-59"
    assert "/proc/self/environ" in finding["description"]


def test_other_link_out_is_low_and_says_it_may_be_intended(tmp_path):
    shared = tmp_path / "shared-config.yaml"
    shared.write_text("a: 1\n", encoding="utf-8")
    repo = _repo(tmp_path)
    _link(shared, repo / "config.yaml")

    [finding] = escaping_symlinks(str(repo))

    assert finding["severity"] == "low"
    assert "may be intentional" in finding["description"]


def test_link_inside_the_repository_is_not_a_finding(tmp_path):
    repo = _repo(tmp_path)
    _link(repo / "app.py", repo / "alias.py")

    assert escaping_symlinks(str(repo)) == []


def test_linked_directory_is_one_finding_and_not_walked(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("x = 1\n", encoding="utf-8")
    (outside / "b.py").write_text("y = 2\n", encoding="utf-8")
    repo = _repo(tmp_path)
    _link(outside, repo / "shared")

    assert [f["file"] for f in escaping_symlinks(str(repo))] == ["shared"]


def test_scan_repository_reports_it_with_no_scanner_installed(tmp_path):
    repo = _repo(tmp_path)
    _link("/proc/self/environ", repo / "env.py")

    doc = scan_repository(str(repo), scanners=())

    assert [f["rule"] for f in doc["findings"]] == [RULE]
    # A tree check, not a tool: it must not appear as a scanner that ran.
    assert "symlinks" not in doc.get("scanners_run", [])
