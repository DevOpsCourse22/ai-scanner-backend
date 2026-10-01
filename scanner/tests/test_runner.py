"""The runner's contract: a missing scanner degrades the run, it does not
fail it - but the gap is always recorded, never swallowed."""

from unittest.mock import patch

from repo_scanner.runner import scan_repository


def test_missing_scanner_is_recorded_not_silently_skipped():
    """"0 findings" from a scanner that never ran is exactly the lie the
    roadmap's "truthful scanner coverage" gate exists to prevent."""
    with patch("repo_scanner.runner.find_executable", return_value=None):
        doc = scan_repository("somewhere", ("semgrep", "gitleaks", "trivy"))

    assert doc["findings"] == []
    assert doc["scanners_run"] == []
    assert set(doc["scanners_failed"]) == {"semgrep", "gitleaks", "trivy"}
    assert all("not installed" in why for why in doc["scanners_failed"].values())


def test_one_missing_scanner_does_not_block_the_others():
    def only_semgrep(cmd):
        return "/usr/bin/semgrep" if cmd == "semgrep" else None

    fake = ([{"file": "a.py", "severity": "high"}], {"scanned_files": 1}, None)
    with (
        patch("repo_scanner.runner.find_executable", side_effect=only_semgrep),
        patch("repo_scanner.runner.run_scanner", return_value=fake),
    ):
        doc = scan_repository("somewhere", ("semgrep", "trivy"))

    assert "semgrep" in doc["scanners_run"]
    assert doc["findings"]


def test_unknown_scanner_name_is_reported():
    doc = scan_repository("somewhere", ("nosuchtool",))
    assert doc["scanners_failed"]["nosuchtool"] == "no such scanner"


def test_findings_are_sorted_most_severe_first():
    mixed = [
        {"file": "b.py", "severity": "low", "line": 1},
        {"file": "a.py", "severity": "critical", "line": 2},
        {"file": "c.py", "severity": "medium", "line": 3},
    ]
    with (
        patch("repo_scanner.runner.find_executable", return_value="/usr/bin/x"),
        patch("repo_scanner.runner.run_scanner", return_value=(mixed, {}, None)),
    ):
        doc = scan_repository("somewhere", ("semgrep",))

    assert [f["severity"] for f in doc["findings"]] == ["critical", "medium", "low"]


def test_document_carries_the_fields_review_api_reads():
    with patch("repo_scanner.runner.find_executable", return_value=None):
        doc = scan_repository("somewhere", ("semgrep",))
    assert "source" in doc and "findings" in doc
