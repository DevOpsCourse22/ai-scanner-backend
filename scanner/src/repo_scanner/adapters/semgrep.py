"""Semgrep - static code analysis (SAST).

Verified against real output from Semgrep 1.175.0 scanning a Django repo:
13 findings across 59 files.
"""

from __future__ import annotations

from typing import Any

from ..findings import make_finding, repo_relative, short_rule_title
from .base import load_json

# A bound on how many errored paths the findings file carries. The exact
# count is always in "errors"; a repository that fails to parse wholesale
# should not balloon a file that is re-read on every progress poll.
MAX_ERROR_FILES = 500

# Semgrep's three levels onto the report's five. Nothing maps to
# "critical": a rule match is evidence that a pattern fired, not a
# judgement about blast radius, and Semgrep itself does not claim one.
# Escalating to critical is the AI enrichment tier's job, with the
# surrounding context that a pattern match does not have.
_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

DEFAULT_CONFIG = "p/default"


class SemgrepAdapter:
    name = "semgrep"

    def __init__(self, config: str = DEFAULT_CONFIG) -> None:
        self.config = config

    def command(self, target: str, output_path: str) -> list[str]:
        return [
            "semgrep",
            "scan",
            f"--config={self.config}",
            "--json",
            "--quiet",
            # No telemetry: repository paths and rule hits are not ours to
            # send anywhere, and a scan must not depend on the network
            # being reachable to succeed.
            "--metrics=off",
            "-o",
            output_path,
            target,
        ]

    def parse(self, raw: bytes, scan_root: str) -> list[dict[str, Any]]:
        data = load_json(raw)
        findings = []
        for result in data.get("results") or []:
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            rule = str(result.get("check_id") or "")
            finding = make_finding(
                file=repo_relative(result.get("path") or "", scan_root),
                source=self.name,
                rule=rule,
                severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), "info"),
                line=(result.get("start") or {}).get("line"),
                title=short_rule_title(rule),
                description=extra.get("message", ""),
                cwe=_first_cwe(metadata),
            )
            # NB: extra["lines"] holds the matched source. Never copied -
            # see the redaction rule in findings.py.
            if finding is not None:
                findings.append(finding)
        return findings

    def coverage(self, raw: bytes, scan_root: str = "") -> dict[str, Any]:
        data = load_json(raw)
        paths = data.get("paths") or {}
        errors = data.get("errors") or []
        # WHICH files errored, not only how many. A file Semgrep could only
        # partly parse is still listed under paths.scanned, so "scanned" does
        # not mean "checked"; without these names a file it never really
        # read would look exactly like one it read and found clean.
        # Errors without a path (bad rule, config) concern no single file.
        error_files = sorted({
            repo_relative(e["path"], scan_root) for e in errors
            if isinstance(e, dict) and e.get("path")})
        coverage: dict[str, Any] = {
            "scanned_files": len(paths.get("scanned") or []),
            "errors": len(errors),
            "error_files": error_files[:MAX_ERROR_FILES],
        }
        if len(error_files) > MAX_ERROR_FILES:
            coverage["error_files_truncated"] = (
                len(error_files) - MAX_ERROR_FILES)
        return coverage


def _first_cwe(metadata: dict[str, Any]) -> str | None:
    """Semgrep gives a list like ["CWE-89: SQL Injection"]; keep the first."""
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str) and cwe:
        return cwe
    return None
