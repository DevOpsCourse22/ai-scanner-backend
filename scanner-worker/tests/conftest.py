"""Shared setup for the scanner-worker tests.

entrypoint.py is a script, not an installed package, so its folder goes on
sys.path. The pipeline test reuses the planted-issue fixture repository
from mcp-server/tests (the same way backend/tests does) rather than a copy.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
_MCP_TESTS = HERE.parent / "mcp-server" / "tests"

for path in (HERE, _MCP_TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


@pytest.fixture(autouse=True)
def no_real_scanners(monkeypatch):
    """Never shell out to Semgrep/Gitleaks/Trivy during the suite."""
    from code_review_mcp.config import settings
    monkeypatch.setattr(settings, "run_scanner", False)
