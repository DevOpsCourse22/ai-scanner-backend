"""Command line entry point.

Runs all three scanners (Semgrep, Gitleaks, Trivy) unless --scanners
narrows the set, and writes their merged, normalized findings to one file:

    repo-scan <repo-path> -o ../../reports/EVOTE.findings.json

Note that <repo-path> is a directory that is ALREADY cloned - this tool
does not clone anything itself, which is what keeps it runnable anywhere
(a laptop, a CI step, a Kubernetes Job) without knowing about GitHub.

Then reference that filename from a review:

    POST /api/v1/reviews {"findings_file": "EVOTE.findings.json", ...}

The output goes to the shared reports/ folder by default, because that is
where review-api resolves `findings_file` from - a findings file written
anywhere else is invisible to the review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import ADAPTERS, DEFAULT_SCANNERS
from .runner import (
    DEFAULT_TIMEOUT_SECONDS,
    SEVERITY_ORDER,
    scan_repository,
    write_findings_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="repo-scan",
        description="Run deterministic scanners and emit a findings file "
        "for review-api to enrich.",
    )
    parser.add_argument("target", help="Path to an already-cloned repository")
    parser.add_argument(
        "-o",
        "--output",
        help="Findings file to write (default: <target>.findings.json in the "
        "current directory)",
    )
    parser.add_argument(
        "--scanners",
        default=",".join(DEFAULT_SCANNERS),
        help=f"Comma-separated subset of: {', '.join(ADAPTERS)}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-scanner timeout in seconds",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit non-zero when a finding at this severity or worse exists. "
            "Without it, repo-scan only reports.",
    )
    args = parser.parse_args()

    target = Path(args.target)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2

    scanners = tuple(s.strip() for s in args.scanners.split(",") if s.strip())
    document = scan_repository(str(target), scanners, args.timeout)

    output = Path(args.output) if args.output else Path(f"{target.name}.findings.json")
    written = write_findings_file(document, output)

    by_severity: dict[str, int] = {}
    for finding in document["findings"]:
        sev = finding["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print(f"wrote {written}")
    print(f"  findings : {len(document['findings'])} {json.dumps(by_severity)}")
    print(f"  ran      : {', '.join(document['scanners_run']) or 'none'}")
    # Loud on purpose: a scanner that silently did not run is how a
    # partial scan gets mistaken for a clean one.
    if document["scanners_failed"]:
        print("  NOT RUN  :", file=sys.stderr)
        for name, why in document["scanners_failed"].items():
            print(f"    {name}: {why}", file=sys.stderr)
        print(
            "  -> coverage is incomplete; the findings above are not the "
            "whole picture.",
            file=sys.stderr,
        )
        # If the data lacks, fail the whole scanner. Deliberately BEFORE the
        # --fail-on gate below and not after: a threshold cannot be judged
        # against findings we know are incomplete, so "cannot tell" has to
        # outrank "told you, and it was fine". Do not reorder these.
        return 3

    # --- the --fail-on gate ---------------------------------------------
    # No flag means report mode: the findings file is written and the exit
    # code stays 0 even with findings in it. That is why --fail-on has no
    # default - the same tool is a reporter by default and a CI gate only
    # when someone asks for one.
    if not args.fail_on:
        return 0

    # SEVERITY_ORDER counts UP as severity goes DOWN, so a finding is "at
    # the threshold or worse" when its number is <= the threshold's.
    threshold = SEVERITY_ORDER[args.fail_on]
    blocking = {
        severity: count
        for severity, count in by_severity.items()
        # .get(..., 4) keeps an unrecognised severity from blocking a build:
        # it is treated as "info", the least severe, rather than crashing.
        if SEVERITY_ORDER.get(severity, 4) <= threshold
    }

    if blocking:
        # Says WHY on stderr, which is the stream CI surfaces first. A red
        # build with no reason on it is how people learn to route around a
        # gate instead of reading it.
        print(
            f"  FAILED   : {sum(blocking.values())} finding(s) at or above "
            f"'{args.fail_on}' {json.dumps(blocking)}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
