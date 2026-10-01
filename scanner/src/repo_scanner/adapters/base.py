"""What a scanner plugin is (ADR-007 / FR-007).

Adding a scanner means writing one module here and registering it - no
change to the runner, the CLI, or the review pipeline. Each adapter owns
exactly two things it alone knows: how to invoke its tool, and how to read
its output. Everything shared - the finding shape, severity vocabulary,
path handling, redaction - lives in findings.py so adapters cannot drift.

Parsing is kept separate from running on purpose: a parser that takes
bytes can be tested against a recorded sample of real tool output without
the tool installed, which is what makes these adapters testable in CI.
"""

from __future__ import annotations

import json
from typing import Any, Protocol


class ScannerAdapter(Protocol):
    """One deterministic scanner."""

    name: str

    def command(self, target: str, output_path: str) -> list[str]:
        """Argv that runs the tool over `target`, writing JSON to
        `output_path`."""
        ...

    def parse(self, raw: bytes, scan_root: str) -> list[dict[str, Any]]:
        """Tool output -> findings in the common format."""
        ...

    def coverage(self, raw: bytes, scan_root: str = "") -> dict[str, Any]:
        """What the tool actually looked at, for honest reporting.

        `scan_root` lets a tool that names files in its coverage report them
        repo-relative, like its findings - see `repo_relative`.
        """
        ...


def load_json(raw: bytes) -> Any:
    """Parse tool output that is not necessarily valid UTF-8.

    Real Semgrep output from a Windows run carried a 0x92 byte - a cp1252
    smart quote picked up from a scanned source file - which makes a plain
    UTF-8 decode raise. Scanner results must not be lost because someone
    else's file has a legacy encoding, so undecodable bytes are replaced
    rather than fatal.
    """
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
