"""The plugin registry (ADR-007 / FR-007).

Adding a scanner is: write an adapter module, add one line here. Nothing
in the runner, the CLI, or the review pipeline changes.
"""

from __future__ import annotations

from .base import ScannerAdapter, load_json
from .gitleaks import GitleaksAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

# The three scanners FR-007 names. Order is report order: code issues,
# then committed secrets, then dependency and configuration problems.
ADAPTERS: dict[str, type] = {
    "semgrep": SemgrepAdapter,
    "gitleaks": GitleaksAdapter,
    "trivy": TrivyAdapter,
}

DEFAULT_SCANNERS = tuple(ADAPTERS)

__all__ = [
    "ADAPTERS",
    "DEFAULT_SCANNERS",
    "GitleaksAdapter",
    "ScannerAdapter",
    "SemgrepAdapter",
    "TrivyAdapter",
    "load_json",
]
