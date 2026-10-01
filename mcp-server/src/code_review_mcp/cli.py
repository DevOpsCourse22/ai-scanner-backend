"""Standalone CLI — runs the same pipeline as the MCP tool, without an MCP host.

Usage:
    python -m code_review_mcp.cli https://github.com/owner/repo report.json
    python -m code_review_mcp.cli https://github.com/owner/repo report.json --prompt-file prompt.txt
    python -m code_review_mcp.cli https://github.com/owner/repo manifest.json --ingest-only

Private repositories: set GITHUB_TOKEN in the environment first (never pass
a token on the command line — it would be visible in the process list).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .repo_ingest import ingest_repository, save_manifest
from .review import review_manifest

DEFAULT_PROMPT = (
    "You are a senior software engineer performing a thorough code review. "
    "Focus on correctness bugs, security vulnerabilities, error handling, "
    "and maintainability. Be specific and reference line numbers."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI code review via LM Studio")
    parser.add_argument("repo_url", help="GitHub repository URL")
    parser.add_argument("output", help="Path for the JSON report (or manifest with --ingest-only)")
    parser.add_argument("--prompt-file", help="File containing the review system prompt")
    parser.add_argument("--branch", default=None, help="Branch to review")
    parser.add_argument("--ext", nargs="*", default=None, help="Extensions filter, e.g. .py .ts")
    parser.add_argument("--ingest-only", action="store_true", help="Stop after repo->JSON conversion")
    args = parser.parse_args(argv)

    print(f"Cloning {args.repo_url} ...", file=sys.stderr)
    manifest = ingest_repository(args.repo_url, args.branch, args.ext)
    print(f"Ingested {manifest['file_count']} files @ {manifest['commit'][:8]}", file=sys.stderr)

    if args.ingest_only:
        out = save_manifest(manifest, args.output)
        print(f"Manifest written to {out}", file=sys.stderr)
        return 0

    system_prompt = (
        Path(args.prompt_file).read_text(encoding="utf-8")
        if args.prompt_file
        else DEFAULT_PROMPT
    )

    def progress(index: int, total: int, path: str) -> None:
        print(f"  [{index}/{total}] reviewing {path}", file=sys.stderr)

    report = review_manifest(manifest, system_prompt, progress)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    stats = report["stats"]
    print(
        f"Done: {stats['files_reviewed']} reviewed, {stats['files_failed']} failed, "
        f"{stats['issues_total']} issues -> {out}",
        file=sys.stderr,
    )
    return 0 if stats["files_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
