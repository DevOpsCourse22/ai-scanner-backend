"""Shared fixtures for the MCP server tests."""

import pytest

from code_review_mcp.config import settings


@pytest.fixture(autouse=True)
def no_real_scanners(monkeypatch):
    """Never shell out to Semgrep, Gitleaks or Trivy during the suite.

    `repo_scanner` is an optional dependency, so whether it is installed
    varies by machine — and when it IS installed the pipeline would run
    three real binaries against a temp directory in every test that clones.
    That makes the suite slow, non-deterministic, and dependent on tools
    the developer may not have. Tests that exercise the scanner path turn
    this back on explicitly.
    """
    monkeypatch.setattr(settings, "run_scanner", False)
