"""The --fail-on gate's contract: what each exit code promises.

Every test here fakes scan_repository. That is deliberate: the gate is
OUR logic, while Semgrep, Gitleaks and Trivy are not - a test that ran
them for real would be slow, would need them installed, and would be
testing someone else's tool instead of the decision we wrote.

    0 = ran fully, nothing at or above the threshold
    1 = the gate fired
    2 = the tool could not do its job (bad arguments)
    3 = coverage is incomplete, so no threshold can be judged
"""

import sys
from unittest.mock import patch

import pytest

from repo_scanner.cli import main


def _document(findings, failed=None):
    """A findings document shaped like the real one, with only the fields
    the gate actually reads. Keeps each test to one variable."""
    return {
        "findings": findings,
        "scanners_run": ["semgrep"],
        "scanners_failed": failed or {},
        "coverage": {},
        "source": "semgrep",
    }


def _run(tmp_path, document, *flags):
    """Call main() with a faked scan and a faked command line.

    Extracted because the patch/argv boilerplate is noise that repeats in
    every test, and noise that repeats is where a typo hides - an argv
    built slightly wrong in one test would silently exercise a different
    code path while still looking like its neighbours. The data each test
    cares about stays in the test; only the plumbing moves here.
    """
    argv = ["repo-scan", str(tmp_path), "-o", str(tmp_path / "f.json"), *flags]
    with (
        patch("repo_scanner.cli.scan_repository", return_value=document),
        patch.object(sys, "argv", argv),
    ):
        return main()


# --- report mode ------------------------------------------------------


def test_report_mode_returns_zero_even_with_findings(tmp_path):
    """Without --fail-on, repo-scan reports and does not gate - so an
    existing caller that just wants the file is never broken by findings."""
    doc = _document([{"file": "a.py", "severity": "critical"}])
    assert _run(tmp_path, doc) == 0


# --- the threshold ----------------------------------------------------


def test_a_threshold_above_the_worst_finding_does_not_fire(tmp_path):
    """--fail-on critical must ignore a repository whose worst finding is
    high. This is what makes the flag a threshold rather than an
    any-findings switch: a team can block on critical while still shipping
    with known high-severity debt, which is the only way a gate survives
    contact with a real codebase."""
    doc = _document([{"file": "a.py", "severity": "high"}])
    assert _run(tmp_path, doc, "--fail-on", "critical") == 0


def test_a_finding_at_the_threshold_fires_the_gate(tmp_path):
    """"At this severity OR WORSE" includes the severity itself. Off by
    one here would mean --fail-on high quietly ignores every high."""
    doc = _document([{"file": "a.py", "severity": "high"}])
    assert _run(tmp_path, doc, "--fail-on", "high") == 1


def test_a_finding_worse_than_the_threshold_fires_the_gate(tmp_path):
    """The other side of the same boundary: asking to fail on high must
    also fail on critical. Getting the <= comparison backwards would pass
    the test above and fail this one."""
    doc = _document([{"file": "a.py", "severity": "critical"}])
    assert _run(tmp_path, doc, "--fail-on", "high") == 1


def test_the_gate_does_not_fire_on_a_clean_repository(tmp_path):
    """A gate that fires on zero findings would be worse than no gate:
    nothing would ever be green, and the flag would be removed within a
    week."""
    assert _run(tmp_path, _document([]), "--fail-on", "info") == 0


# --- coverage outranks the threshold ----------------------------------


def test_a_failed_scanner_returns_three_even_without_the_flag(tmp_path):
    """A scanner that did not run is missing evidence, not a clean result.
    This holds in report mode too: "could not check" is never success, no
    matter what the caller asked for."""
    doc = _document([], failed={"trivy": "not installed"})
    assert _run(tmp_path, doc) == 3


def test_a_failed_scanner_returns_three_not_one_even_with_the_flag(tmp_path):
    """THE ORDER-LOCKING TEST. Do not delete this one.

    A threshold cannot be judged against findings we already know are
    incomplete, so 3 ("cannot tell") has to outrank 1 ("told you, and it
    was bad"). The two codes also mean different things to whoever reads
    the build: 1 is "fix your code", 3 is "fix the pipeline" - collapsing
    them sends the wrong person to investigate.

    The gate check sits after the coverage check in cli.py precisely so
    this holds. Reorder those two blocks and only this test notices."""
    doc = _document(
        [{"file": "a.py", "severity": "critical"}],
        failed={"trivy": "timed out after 600s"},
    )
    assert _run(tmp_path, doc, "--fail-on", "critical") == 3


# --- unexpected input -------------------------------------------------


def test_an_unrecognised_severity_does_not_crash_or_block(tmp_path):
    """Severities arrive from third-party tools whose rule packs change
    under us, so an unknown one has to be survivable. It is treated as
    the LEAST severe rather than the most: a new label from a scanner
    update must not start failing everybody's build on its own.

    The cost of that choice is that a genuinely severe unknown label is
    under-reported - which is the right trade only because the findings
    file still contains it for a human to read."""
    doc = _document([{"file": "a.py", "severity": "banana"}])
    assert _run(tmp_path, doc, "--fail-on", "critical") == 0


def test_a_missing_target_directory_returns_two(tmp_path):
    """2 is for "you called me wrong", and is checked before anything is
    scanned - distinct from 3, which means the tool ran and cannot vouch
    for what it produced."""
    missing = tmp_path / "does-not-exist"
    with patch.object(sys, "argv", ["repo-scan", str(missing)]):
        assert main() == 2


def test_a_misspelled_threshold_is_rejected_before_scanning(tmp_path):
    """argparse's choices= turns a typo into a loud failure instead of a
    gate that never fires. Without it, --fail-on hihg would be accepted
    and every build would pass forever - the most expensive kind of bug,
    because it looks like success.

    SystemExit(2) is argparse's own exit, raised before main() reaches
    any of our code."""
    with patch.object(sys, "argv", ["repo-scan", str(tmp_path), "--fail-on", "hihg"]):
        with pytest.raises(SystemExit) as exit_info:
            main()
    assert exit_info.value.code == 2
