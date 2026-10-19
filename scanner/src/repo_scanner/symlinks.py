"""Symlinks that point outside the repository, reported as findings.

Not a third-party tool: a check of the tree itself, which none of the
three scanners makes. A link inside a repository is just a short file
whose content is a path; git turns it into a real link on checkout, and
from then on ANY tool that reads the repository's files - a build, a CI
job, an AI review - silently reads the link's target instead, with its own
permissions. Nothing in the repository has to run for that to happen.

Two severities, because a link out of the repository is not always an
attack. `config.yaml -> /etc/app/config.yaml` can be a deliberate pointer
into the image the code is deployed in. A link to /proc, to mounted
Kubernetes secrets or to someone's home directory has no such reading in a
source repository, so those are `high` (and fail `--fail-on high`); every
other link out is `low`, worded as "check that it is intended".

The review engine never follows links at all (code_review_mcp.repo_ingest
.collect_files): even an intended link resolves to OUR filesystem here,
not to the one its author meant.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .findings import make_finding

SOURCE = "repo-scan"
RULE = "symlink-escapes-repository"
CWE = "CWE-59"  # Improper Link Resolution Before File Access

# Bounded like every other source of findings: a repository of ten
# thousand links must not crowd out the scanners' results.
MAX_SYMLINK_FINDINGS = 50

SKIP_DIRS = frozenset({".git"})

# Targets with no legitimate reason to be linked from source code. The last
# two are where a review Job keeps the reports of OTHER reviews and the
# clone itself.
SENSITIVE_PREFIXES = (
    "/proc", "/sys", "/dev",
    "/var/run/secrets", "/run/secrets",
    "/root", "/home",
    "/etc/shadow", "/etc/passwd", "/etc/gshadow",
    "/reports", "/workspace",
)
SENSITIVE_PARTS = frozenset({".ssh", ".aws", ".kube", ".docker", ".gnupg"})


def _is_sensitive(resolved: Path, link_text: str) -> bool:
    candidates = {resolved.as_posix(), link_text.replace("\\", "/")}
    for path in candidates:
        if any(path == p or path.startswith(p + "/") for p in SENSITIVE_PREFIXES):
            return True
        if SENSITIVE_PARTS.intersection(Path(path).parts):
            return True
    return False


def escaping_symlinks(target: str) -> list[dict[str, Any]]:
    """One finding per link under `target` that resolves outside it."""
    root = Path(target).resolve()
    found: list[dict[str, Any]] = []
    # followlinks=False (the default): a linked directory is reported here
    # as one link, never walked into.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            if not path.is_symlink():
                continue
            resolved = path.resolve()
            if resolved.is_relative_to(root):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                link_text = os.readlink(path)
            except OSError:
                link_text = "?"
            if _is_sensitive(resolved, link_text):
                severity = "high"
                title = "Symlink points at a sensitive path outside the repository"
                why = ("No source file has a reason to link there. Any tool "
                       "that reads this repository - a build, a CI job, a "
                       "scanner, an AI review - reads that path instead, "
                       "with its own permissions.")
            else:
                severity = "low"
                title = "Symlink points outside the repository"
                why = ("This may be intentional (a path in the image the "
                       "code is deployed in); check that it is. Tools that "
                       "read the repository's files follow it.")
            finding = make_finding(
                file=rel, source=SOURCE, rule=RULE, severity=severity,
                title=title, description=f"{rel} -> {link_text[:200]}. {why}",
                cwe=CWE)
            if finding:
                found.append(finding)
            if len(found) >= MAX_SYMLINK_FINDINGS:
                return found
    return found
