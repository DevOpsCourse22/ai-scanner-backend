"""Run Semgrep, Gitleaks and Trivy over a repository and merge their findings.

The output is one findings file in the format review-api ingests, which a
review then references by name via `findings_file`.

The design point worth knowing: a scanner that is not installed, crashes,
or times out does NOT fail the run. It is recorded, by name, in
`scanners_failed`. The alternative - letting one missing binary abort
everything - would mean a machine without Trivy gets no Semgrep results
either. But a partial scan must never be presentable as a complete one,
which is why the failure is written INTO the output rather than logged and
forgotten: docs/12-roadmap makes "truthful scanner coverage" a release
gate, and "0 findings" from a scanner that never ran is the exact lie it
is guarding against.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import ADAPTERS, DEFAULT_SCANNERS
from .symlinks import escaping_symlinks

# Generous: a first Semgrep run downloads its rule packs, and Trivy
# refreshes its vulnerability database.
DEFAULT_TIMEOUT_SECONDS = 900

# Same cap review-api applies per file, applied here too so a pathological
# repo cannot produce a findings file too large to prompt with.
MAX_FINDINGS = 2000

# Public, not module-private: the CLI's --fail-on gate compares against
# this, and a second copy of "how bad is worse" would be free to drift
# from this one. Lower number = MORE severe, so "at this severity or
# worse" is <=, not >=.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def find_executable(name: str) -> str | None:
    """Locate a scanner binary.

    PATH alone is not enough. Semgrep installs as a Python package, which
    puts its executable next to the running interpreter (venv/Scripts on
    Windows, venv/bin elsewhere) - a directory that is only on PATH when
    the venv happens to be activated. Reporting an installed scanner as
    "not installed" because of that would understate our own coverage, so
    the interpreter's own script directory is checked too.
    """
    found = shutil.which(name)
    if found:
        return found
    return shutil.which(name, path=str(Path(sys.executable).parent))


def run_scanner(
    adapter: Any, target: str, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """Run one scanner. Returns (findings, coverage, error_or_None)."""
    argv = adapter.command(target, "x")
    executable = find_executable(argv[0])
    if executable is None:
        return [], {}, "not installed"

    with tempfile.TemporaryDirectory() as tmp:
        out_path = str(Path(tmp) / f"{adapter.name}.json")
        command = adapter.command(target, out_path)
        # Use the resolved absolute path, so the child process does not
        # have to re-find on PATH what we just located off it.
        command[0] = executable
        try:
            subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [], {}, f"timed out after {timeout}s"
        except OSError as exc:
            return [], {}, f"could not run: {exc}"

        # Read bytes, not text: output is not guaranteed valid UTF-8.
        # See load_json in adapters/base.py.
        try:
            raw = Path(out_path).read_bytes()
        except OSError:
            return [], {}, "produced no output file"

    try:
        return (adapter.parse(raw, target), adapter.coverage(raw, target),
                None)
    except Exception as exc:  # noqa: BLE001 - a malformed report from one
        # scanner must not take down the others.
        return [], {}, f"unreadable output: {exc}"


def scan_repository(
    target: str,
    scanners: tuple[str, ...] = DEFAULT_SCANNERS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run every requested scanner and merge into one findings document."""
    findings: list[dict[str, Any]] = []
    coverage: dict[str, Any] = {}
    failed: dict[str, str] = {}

    for name in scanners:
        adapter_cls = ADAPTERS.get(name)
        if adapter_cls is None:
            failed[name] = "no such scanner"
            continue
        adapter = adapter_cls()
        found, cov, error = run_scanner(adapter, target, timeout)
        if error:
            failed[name] = error
            continue
        findings.extend(found)
        coverage[name] = cov

    # Not one of the scanners: a check of the tree itself (symlinks.py).
    # Kept out of `coverage` and `scanners_run`, which describe the tools.
    try:
        findings.extend(escaping_symlinks(target))
    except OSError as exc:
        failed["symlinks"] = f"symlink check failed: {exc}"

    # Most severe first, then by file, so a truncated list keeps what
    # matters rather than whatever happened to be scanned first.
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "info"), 4),
            f.get("file", ""),
            f.get("line") or 0,
        )
    )
    truncated = max(0, len(findings) - MAX_FINDINGS)
    del findings[MAX_FINDINGS:]

    document: dict[str, Any] = {
        # review-api reads "source" and "findings"; everything else is
        # provenance it ignores and a human reading the file will want.
        "source": "+".join(coverage) or "none",
        "findings": findings,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scanners_run": sorted(coverage),
        "scanners_failed": failed,
        "coverage": coverage,
    }
    if truncated:
        document["truncated_findings"] = truncated
    return document


def write_findings_file(document: dict[str, Any], output_path: str | Path) -> Path:
    """Write the findings file review-api will ingest."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path
