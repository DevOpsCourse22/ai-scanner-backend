"""Adapters are tested against recorded samples of real tool output, so
they run in CI without the scanners installed.

The Semgrep sample below is trimmed from an actual 1.175.0 run against a
Django repository - including the Windows backslash paths, which is what
makes the path test meaningful rather than hypothetical.
"""

import json

from repo_scanner.adapters import GitleaksAdapter, SemgrepAdapter, TrivyAdapter
from repo_scanner.findings import repo_relative

SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "javascript.lang.security.audit.incomplete-sanitization",
                "path": "evoting\\DjangoWebApp\\src\\static\\js\\app.js",
                "start": {"line": 393},
                "extra": {
                    "severity": "WARNING",
                    "message": "`replace` only replaces the first occurrence.",
                    "metadata": {"cwe": ["CWE-116: Improper Encoding"]},
                    "lines": "const SECRET_IN_SOURCE = 'sk_live_do_not_leak';",
                },
            },
            {
                "check_id": "python.django.security.audit.hardcoded-secret",
                "path": "evoting\\app\\settings.py",
                "start": {"line": 23},
                "extra": {"severity": "ERROR", "message": "Hardcoded secret key."},
            },
        ],
        "errors": [],
        "paths": {"scanned": ["a.js", "b.py", "c.py"]},
    }
).encode()

GITLEAKS_SAMPLE = json.dumps(
    [
        {
            "RuleID": "github-pat",
            "Description": "GitHub Personal Access Token",
            "File": "myclone/config/prod.py",
            "StartLine": 12,
            "Secret": "ghp_ACTUALSECRETVALUE1234567890",
            "Match": "GITHUB_TOKEN = 'ghp_ACTUALSECRETVALUE1234567890'",
        }
    ]
).encode()

TRIVY_SAMPLE = json.dumps(
    {
        "Results": [
            {
                "Target": "myclone/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "django",
                        "InstalledVersion": "3.2.0",
                        "FixedVersion": "3.2.18",
                        "Severity": "CRITICAL",
                        "Title": "SQL injection in QuerySet",
                        "CweIDs": ["CWE-89"],
                    }
                ],
            }
        ]
    }
).encode()


# --------------------------------------------------------------- semgrep --

def test_semgrep_strips_scan_root_and_normalizes_separators():
    """The silent killer: a mismatched path means the finding lands in
    `unmatched` and the model is handed nothing, while the run still
    reports success."""
    findings = SemgrepAdapter().parse(SEMGREP_SAMPLE, "evoting")
    assert findings[0]["file"] == "DjangoWebApp/src/static/js/app.js"
    assert findings[1]["file"] == "app/settings.py"


def test_semgrep_maps_severity_and_never_claims_critical():
    findings = SemgrepAdapter().parse(SEMGREP_SAMPLE, "evoting")
    assert findings[0]["severity"] == "medium"  # WARNING
    assert findings[1]["severity"] == "high"  # ERROR
    assert all(f["severity"] != "critical" for f in findings)


def test_semgrep_shortens_the_rule_id_for_the_title():
    findings = SemgrepAdapter().parse(SEMGREP_SAMPLE, "evoting")
    assert findings[0]["title"] == "incomplete-sanitization"
    assert findings[0]["rule"].startswith("javascript.lang")


def test_semgrep_reports_coverage():
    assert SemgrepAdapter().coverage(SEMGREP_SAMPLE)["scanned_files"] == 3


def test_semgrep_names_the_files_it_could_not_fully_parse():
    """Shaped like real Semgrep output (captured 2026-09-27 on Windows): a
    PartialParsing error carries the file's path, and that file is ALSO in
    paths.scanned - so "scanned" alone cannot tell a file that was checked
    from one that was only partly read. The paths must come back in the same
    repo-relative form as findings, or they match nothing in the review."""
    raw = json.dumps({
        "results": [],
        "paths": {"scanned": ["myclone\\src\\broken.py",
                              "myclone\\src\\good.py"]},
        "errors": [
            {"type": "PartialParsing", "level": "warn",
             "path": "myclone\\src\\broken.py"},
            {"type": "PartialParsing", "level": "warn",
             "path": "myclone\\src\\broken.py"},   # same file twice
            {"type": "Rule parse error", "level": "error"},  # no file
        ],
    }).encode()

    coverage = SemgrepAdapter().coverage(raw, "myclone")

    assert coverage["errors"] == 3                  # the exact count stays
    assert coverage["error_files"] == ["src/broken.py"]
    assert coverage["scanned_files"] == 2


def test_every_adapter_accepts_the_scan_root():
    """The runner passes it to all of them; one that did not accept it would
    turn a clean scan into 'unreadable output'."""
    for adapter, raw in ((GitleaksAdapter(), b"[]"),
                         (TrivyAdapter(), b'{"Results": []}'),
                         (SemgrepAdapter(), b'{"results": [], "errors": []}')):
        assert isinstance(adapter.coverage(raw, "some/root"), dict)


# -------------------------------------------------------------- gitleaks --

def test_gitleaks_reports_the_location_not_the_credential():
    finding = GitleaksAdapter().parse(GITLEAKS_SAMPLE, "myclone")[0]
    assert finding["file"] == "config/prod.py"
    assert finding["line"] == 12
    assert finding["rule"] == "github-pat"
    assert finding["severity"] == "high"


def test_gitleaks_secret_value_never_reaches_the_finding():
    """If this fails, reporting a leaked credential republishes it into a
    findings file, an LLM prompt, and a stored report."""
    serialized = json.dumps(GitleaksAdapter().parse(GITLEAKS_SAMPLE, "myclone"))
    assert "ghp_ACTUALSECRETVALUE1234567890" not in serialized
    assert "GITHUB_TOKEN =" not in serialized


# ----------------------------------------------------------------- trivy --

def test_trivy_passes_through_cve_critical():
    """Unlike a pattern match, a CVSS-backed CRITICAL is real evidence."""
    finding = TrivyAdapter().parse(TRIVY_SAMPLE, "myclone")[0]
    assert finding["severity"] == "critical"
    assert finding["file"] == "requirements.txt"
    assert "CVE-2023-12345" in finding["rule"]


def test_trivy_puts_the_fixed_version_in_the_description():
    finding = TrivyAdapter().parse(TRIVY_SAMPLE, "myclone")[0]
    assert "3.2.18" in finding["description"]


# ---------------------------------------------------------------- shared --

def test_no_adapter_leaks_matched_source_text():
    """One assertion covering the rule that justifies this whole layer."""
    all_findings = (
        SemgrepAdapter().parse(SEMGREP_SAMPLE, "evoting")
        + GitleaksAdapter().parse(GITLEAKS_SAMPLE, "myclone")
        + TrivyAdapter().parse(TRIVY_SAMPLE, "myclone")
    )
    serialized = json.dumps(all_findings)
    assert "sk_live_do_not_leak" not in serialized
    assert "ghp_ACTUALSECRETVALUE" not in serialized


def test_output_that_is_not_valid_utf8_still_parses():
    """A real Windows Semgrep run emitted a cp1252 0x92 byte, which makes a
    plain UTF-8 decode raise and would lose the entire scan."""
    broken = SEMGREP_SAMPLE.replace(b"Hardcoded secret key.", b"Hardcoded \x92secret\x92.")
    findings = SemgrepAdapter().parse(broken, "evoting")
    assert len(findings) == 2


def test_malformed_output_yields_no_findings_rather_than_raising():
    assert SemgrepAdapter().parse(b"not json at all", "x") == []
    assert GitleaksAdapter().parse(b"", "x") == []


def test_repo_relative_leaves_an_already_relative_path_alone():
    assert repo_relative("app/views.py", "myclone") == "app/views.py"
