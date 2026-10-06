"""Shared setup for the backend test suite.

The API tests drive the REAL review pipeline (only the clone and the LLM call
are faked), so they need a realistic manifest to feed it. That manifest comes
from the planted-issue fixture repository that lives with the component which
owns the pipeline — `mcp-server/tests/fixtures/dummy_repo` — rather than from
a second copy maintained here, because two copies drift.

The fixture is test material, so it is deliberately not shipped inside the
installed `code_review_mcp` package; mcp-server/ is a folder of this
repository (next to tests/), so the import path is resolved from that layout.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_MCP_TESTS = Path(__file__).resolve().parents[1] / "mcp-server" / "tests"

if not (_MCP_TESTS / "test_dummy_repo.py").is_file():  # pragma: no cover
    raise RuntimeError(
        f"Expected the MCP server component's tests at {_MCP_TESTS}. The "
        "backend tests reuse its dummy-repo fixture. Run them from a full "
        "checkout of the repository (mcp-server/ next to tests/)."
    )

if str(_MCP_TESTS) not in sys.path:
    sys.path.insert(0, str(_MCP_TESTS))


@pytest.fixture(autouse=True)
def no_real_scanners(monkeypatch):
    """Never shell out to Semgrep/Gitleaks/Trivy during the suite.

    `repo_scanner` is optional, so whether it is installed varies by
    machine; when it is, every review test would run three real binaries.
    """
    from code_review_mcp.config import settings
    monkeypatch.setattr(settings, "run_scanner", False)
