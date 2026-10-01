"""Deterministic scanner tier for AI Scan Repos (FR-007, FR-008).

Runs three scanners over a cloned repository, each covering something the
others cannot:

    Semgrep   - static analysis of the code as written (SAST)
    Gitleaks  - credentials committed to the repository's git HISTORY
    Trivy     - known CVEs in dependencies, plus IaC misconfiguration

Their three different output formats are normalized into the single
finding format review-api ingests, so the LLM's job is ENRICHMENT of real
evidence rather than discovery from scratch. Adding a fourth scanner is
one adapter module plus one registry line - see adapters/__init__.py.
"""

from .runner import scan_repository, write_findings_file

__all__ = ["scan_repository", "write_findings_file"]
