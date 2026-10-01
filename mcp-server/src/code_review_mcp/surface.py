"""Static surface checks for quick mode.

Pure regex heuristics — no LLM involved, so scanning even hundreds of files
takes milliseconds. Findings are shallow by design (that's the point of a
surface pass); anything interesting deserves a brief or deep follow-up.
"""

from __future__ import annotations

import re
from typing import Any

# (pattern, severity, title). Ordered roughly by severity.
SURFACE_CHECKS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)\b(password|passwd|secret|api_?key|auth_?token)\s*[=:]\s*[\"'][^\"']{4,}[\"']"),
     "high", "Possible hardcoded secret"),
    (re.compile(r"\beval\s*\(|\bexec\s*\("), "high", "Use of eval/exec"),
    (re.compile(r"\bpickle\.loads?\s*\("), "high", "Unsafe pickle deserialization"),
    (re.compile(r"os\.system\s*\(|shell\s*=\s*True"), "high", "Shell command execution"),
    (re.compile(r"(?i)verify\s*=\s*False"), "high", "TLS verification disabled"),
    (re.compile(r"(?i)\bDEBUG\s*=\s*True\b"), "medium", "Debug mode enabled"),
    (re.compile(r"\brandom\.(random|randint|choice|randrange)\s*\("),
     "medium", "Non-cryptographic randomness"),
    (re.compile(r"\.innerHTML\s*="), "medium", "innerHTML assignment (XSS risk)"),
    (re.compile(r"(?m)^\s*except\s*:\s*(#.*)?$"), "low", "Bare except clause"),
    (re.compile(r"(?m)^\s*assert\b"), "low", "Assert used outside tests"),
    (re.compile(r"\b(TODO|FIXME|XXX|HACK)\b"), "info", "TODO/FIXME marker"),
]

_SEVERITY_WEIGHT = {"high": 3.0, "medium": 1.5, "low": 0.75, "info": 0.25}


def surface_scan(path: str, content: str) -> list[dict[str, Any]]:
    """Run all surface checks on one file; one issue per matching check."""
    issues: list[dict[str, Any]] = []
    is_test_file = "test" in path.lower()
    for pattern, severity, title in SURFACE_CHECKS:
        matches = list(pattern.finditer(content))
        if not matches:
            continue
        if title == "Assert used outside tests" and is_test_file:
            continue
        line = content.count("\n", 0, matches[0].start()) + 1
        count = len(matches)
        issues.append({
            "severity": severity,
            "line": line,
            "title": title + (f" (x{count})" if count > 1 else ""),
        })
    return issues


def surface_score(issues: list[dict[str, Any]]) -> int:
    """Heuristic 1-9 score from surface findings (9 = surface-clean)."""
    penalty = sum(_SEVERITY_WEIGHT.get(i["severity"], 0.5) for i in issues)
    return max(1, 9 - int(penalty))
