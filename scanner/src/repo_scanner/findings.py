"""The common internal finding format (FR-008) that every adapter emits.

The target shape is fixed by what review-api ingests - see
mcp-server/src/code_review_mcp/findings.py:

    {"source": "semgrep", "findings": [
        {"file", "rule", "severity", "line", "title", "description", "cwe"}
    ]}

Everything in this module exists so the three adapters cannot each invent
their own answer to the same question.

THE REDACTION RULE, which is the whole reason a normalization layer sits
between the scanners and the report: every one of these tools can hand
back the source text it matched - Semgrep's `extra.lines`, Gitleaks'
`Secret` and `Match`, Trivy's secret matches. That text is precisely the
material most likely to BE a credential. Adapters report where something
is and what rule fired; they never copy the matched text. A secrets
scanner whose report reprints the secret has just published it again, in
a file we then hand to an LLM.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Any

# The report's severity vocabulary, most severe first.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Prompt budget, mirroring the caps in review-api's own findings intake.
MAX_RULE_CHARS = 120
MAX_TITLE_CHARS = 120
MAX_DESCRIPTION_CHARS = 300


def repo_relative(raw_path: str, scan_root: str) -> str:
    """`<scan_root>/app/views.py` (any separator) -> `app/views.py`.

    Correctness-critical, and the failure is silent. Scanners report paths
    relative to the directory they were pointed at, with the host
    separator - on Windows, `myclone\\app\\views.py`. The review matches
    findings against its own manifest of repo-relative forward-slash
    paths. A mismatch does not raise: every finding simply lands in
    `unmatched` and the model is handed nothing, while the run still
    reports success.
    """
    parts = PurePath(str(raw_path).replace("\\", "/")).parts
    root_parts = PurePath(str(scan_root).replace("\\", "/")).parts
    # Scanners echo back however the target was spelled, so strip that
    # prefix when it is present rather than assuming it always is.
    if root_parts and parts[: len(root_parts)] == root_parts:
        parts = parts[len(root_parts) :]
    return "/".join(parts)


def make_finding(
    *,
    file: str,
    source: str,
    rule: str = "",
    severity: str = "info",
    line: int | None = None,
    title: str = "",
    description: str = "",
    cwe: str | None = None,
) -> dict[str, Any] | None:
    """Build one finding, or None if it lacks the one required field.

    A finding with no file cannot be shown next to code or matched to the
    manifest, so it is dropped rather than passed on as noise.
    """
    if not file:
        return None
    if severity not in SEVERITIES:
        severity = "info"
    if isinstance(line, (int, float)) and int(line) > 0:
        line = int(line)
    else:
        line = None

    finding: dict[str, Any] = {
        "file": file,
        "source": source[:40],
        "rule": rule[:MAX_RULE_CHARS],
        "severity": severity,
        "line": line,
        "title": (title or rule or f"{source} finding")[:MAX_TITLE_CHARS],
        # Collapse whitespace: scanner messages often carry embedded
        # newlines that would fragment the prompt.
        "description": " ".join(str(description).split())[:MAX_DESCRIPTION_CHARS],
    }
    if cwe:
        finding["cwe"] = str(cwe)[:80]
    return finding


def short_rule_title(rule_id: str) -> str:
    """`javascript.lang.security.audit.incomplete-sanitization` ->
    `incomplete-sanitization`. Registry ids are unreadable in a report."""
    return rule_id.rsplit(".", 1)[-1] if rule_id else ""
