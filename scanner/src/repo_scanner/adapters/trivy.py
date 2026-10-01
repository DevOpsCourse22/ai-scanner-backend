"""Trivy - vulnerable dependencies (CVEs) and IaC misconfiguration.

Trivy nests everything under Results, one entry per target (a lockfile, a
Dockerfile, a manifest), each of which may carry Vulnerabilities,
Misconfigurations, or Secrets. All three are folded into the same flat
finding shape here.
"""

from __future__ import annotations

from typing import Any

from ..findings import make_finding, repo_relative
from .base import load_json

# Trivy is the one scanner whose "CRITICAL" is passed through unchanged.
# Its severities come from CVSS scores published with the CVE - an
# external, evidence-backed judgement about a KNOWN vulnerability, not a
# pattern that happened to match. That is a different kind of claim from
# Semgrep's, and flattening it would throw away real information.
_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class TrivyAdapter:
    name = "trivy"

    def command(self, target: str, output_path: str) -> list[str]:
        return [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "json",
            "--output",
            output_path,
            "--quiet",
            target,
        ]

    def parse(self, raw: bytes, scan_root: str) -> list[dict[str, Any]]:
        data = load_json(raw)
        findings: list[dict[str, Any]] = []

        for result in data.get("Results") or []:
            target = repo_relative(result.get("Target") or "", scan_root)

            for vuln in result.get("Vulnerabilities") or []:
                vuln_id = str(vuln.get("VulnerabilityID") or "")
                pkg = vuln.get("PkgName") or ""
                installed = vuln.get("InstalledVersion") or ""
                fixed = vuln.get("FixedVersion") or ""
                # The fixed version is the single most actionable fact in
                # a CVE finding, so it goes in the description rather than
                # being left for the reader to look up.
                remedy = f" Fixed in {fixed}." if fixed else " No fixed version published."
                finding = make_finding(
                    file=target,
                    source=self.name,
                    rule=vuln_id,
                    severity=_SEVERITY.get(str(vuln.get("Severity", "")).upper(), "info"),
                    title=f"{pkg} {installed}: {vuln_id}".strip(),
                    description=(vuln.get("Title") or vuln.get("Description") or "") + remedy,
                    cwe=_first(vuln.get("CweIDs")),
                )
                if finding is not None:
                    findings.append(finding)

            for miscfg in result.get("Misconfigurations") or []:
                finding = make_finding(
                    file=target,
                    source=self.name,
                    rule=str(miscfg.get("ID") or ""),
                    severity=_SEVERITY.get(str(miscfg.get("Severity", "")).upper(), "info"),
                    line=((miscfg.get("CauseMetadata") or {}).get("StartLine")),
                    title=miscfg.get("Title") or "",
                    description=miscfg.get("Description") or "",
                )
                if finding is not None:
                    findings.append(finding)

            for secret in result.get("Secrets") or []:
                # secret["Match"] holds the matched text - never read, for
                # the same reason as in the Gitleaks adapter.
                finding = make_finding(
                    file=target,
                    source=self.name,
                    rule=str(secret.get("RuleID") or ""),
                    severity=_SEVERITY.get(str(secret.get("Severity", "")).upper(), "high"),
                    line=secret.get("StartLine"),
                    title=secret.get("Title") or "committed secret",
                    description=secret.get("Category") or "",
                    cwe="CWE-798: Use of Hard-coded Credentials",
                )
                if finding is not None:
                    findings.append(finding)

        return findings

    def coverage(self, raw: bytes, scan_root: str = "") -> dict[str, Any]:
        data = load_json(raw)
        return {
            "scanned_files": len(data.get("Results") or []),
            "errors": 0,
        }


def _first(values: Any) -> str | None:
    if isinstance(values, list) and values:
        return str(values[0])
    return None
