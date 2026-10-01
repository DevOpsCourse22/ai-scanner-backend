"""End-to-end review driver: runs a REAL review through the actual server
module (job thread, checkpoint writes, resume logic) against any
OpenAI-compatible endpoint — the mock LLM server for offline testing, or a
live LM Studio for real-hardware verification.

Usage:
    python tests/e2e_review.py --repo https://github.com/owner/repo \
        --review-id E2E-01 --mode brief [--files "*/views.py" ...] \
        [--model google/gemma-4-26b] [--prompt "Strict security reviewer"] \
        [--poll 10]

Endpoint and output directory come from the same environment variables the
MCP server uses:
    LMSTUDIO_BASE_URL   e.g. http://localhost:8765/v1 (mock) or :1234 (real)
    REVIEW_OUTPUT_DIR   where <review-id>.json/.md/.partial.json land

The job runs in the foreground while this process polls get_review_status
and prints every progress line. Exit code 0 = done, 1 = error.

DISASTER-RECOVERY DRILL: kill this process mid-run (taskkill / Ctrl+C /
docker kill) to simulate a crash, then rerun the exact same command — the
review must resume from <review-id>.partial.json instead of starting over.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="e2e review driver")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--mode", default="brief",
                        choices=["quick", "brief", "deep"])
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument("--findings-file", default="",
                        help="JSON file of deterministic scanner findings "
                             "to feed the review (platform hand-off)")
    parser.add_argument("--model", default="")
    parser.add_argument("--prompt", default="You are a strict senior code "
                        "reviewer focused on security and correctness.")
    parser.add_argument("--poll", type=int, default=10,
                        help="get_review_status wait_seconds per cycle")
    args = parser.parse_args()

    from code_review_mcp import server

    started = json.loads(server.start_review(
        repo_url=args.repo,
        system_prompt=args.prompt,
        mode=args.mode,
        model=args.model,
        review_id=args.review_id,
        files=args.files,
        findings_file=args.findings_file,
    ))
    print(f"[e2e] start_review -> {started}", flush=True)
    if started.get("status") not in ("started",):
        return 1
    job_id = started["job_id"]

    t0 = time.monotonic()
    while True:
        status = json.loads(asyncio.run(
            server.get_review_status(job_id, wait_seconds=args.poll)))
        line = status.get("progress") or status.get("status")
        print(f"[e2e] {int(time.monotonic() - t0):>4}s  {line}", flush=True)
        if status["status"] == "done":
            print(f"[e2e] DONE stats={json.dumps(status.get('stats'))}",
                  flush=True)
            print(f"[e2e] report={status.get('report')}", flush=True)
            print(f"[e2e] markdown={status.get('markdown')}", flush=True)
            return 0
        if status["status"] in ("error", "unknown_job"):
            print(f"[e2e] FAILED: {json.dumps(status)}", flush=True)
            return 1


if __name__ == "__main__":
    sys.exit(main())
