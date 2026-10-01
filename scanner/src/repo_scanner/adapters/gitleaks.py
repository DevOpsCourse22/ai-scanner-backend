"""Gitleaks - committed secrets.

This adapter is where the redaction rule earns its keep. Gitleaks' JSON
carries the credential it found, in the clear, in two fields:

    {"RuleID": "...", "File": "...", "StartLine": 12,
     "Secret": "ghp_REAL_TOKEN_HERE",       <- the actual credential
     "Match":  "token = ghp_REAL_TOKEN..."} <- the line containing it

Neither is ever read here. Copying them would write the leaked credential
into a findings file, which is then pasted into an LLM prompt and stored
in a report - publishing the secret a second time, in more places, as a
side effect of reporting it. The finding says WHICH rule fired and WHERE;
the developer looks at their own repository for the value.
"""

from __future__ import annotations

from typing import Any

from ..findings import make_finding, repo_relative
from .base import load_json


class GitleaksAdapter:
    name = "gitleaks"

    def command(self, target: str, output_path: str) -> list[str]:
        # `gitleaks git <dir>` scans the repository's COMMIT HISTORY, not
        # just the working tree - and that history is the whole reason
        # this scanner is in the set. Semgrep and Trivy both look at the
        # files as they are NOW (Trivy has a secret scanner too), so a
        # credential that was committed and later deleted is invisible to
        # both, while remaining published forever in the history to anyone
        # who clones. `gitleaks dir` would miss it for the same reason.
        #
        # Verified against 8.30.1. The older `detect --source` spelling
        # still works but is the legacy name; `git` is the current one.
        return [
            "gitleaks",
            "git",
            target,
            "--report-format",
            "json",
            "--report-path",
            output_path,
            # Findings are the point of the run, so a non-empty result
            # must not read as a crashed scan.
            "--exit-code",
            "0",
            "--no-banner",
        ]

    def parse(self, raw: bytes, scan_root: str) -> list[dict[str, Any]]:
        data = load_json(raw)
        # Gitleaks emits a bare JSON array, unlike the other two.
        entries = data if isinstance(data, list) else (data.get("findings") or [])

        findings = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            rule = str(entry.get("RuleID") or entry.get("rule") or "")
            finding = make_finding(
                file=repo_relative(entry.get("File") or entry.get("file") or "", scan_root),
                source=self.name,
                rule=rule,
                # Gitleaks assigns no severity - every hit is a credential
                # sitting in a repository, so none of them are minor.
                # "critical" is left to the enrichment tier, which can see
                # whether the secret is live, scoped, or already rotated.
                severity="high",
                line=entry.get("StartLine") or entry.get("startLine"),
                title=rule or "committed secret",
                # entry["Description"] describes the RULE ("GitHub personal
                # access token"), not the matched text - safe. entry
                # ["Secret"] and entry["Match"] are the credential itself
                # and are deliberately never read.
                description=entry.get("Description") or entry.get("description") or "",
                cwe="CWE-798: Use of Hard-coded Credentials",
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def coverage(self, raw: bytes, scan_root: str = "") -> dict[str, Any]:
        data = load_json(raw)
        entries = data if isinstance(data, list) else (data.get("findings") or [])
        # Gitleaks reports no file count, so we cannot claim one. Saying
        # "0 files scanned" would be a lie; omitting it is honest.
        return {"scanned_files": None, "errors": 0, "raw_entries": len(entries)}
