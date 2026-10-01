#!/usr/bin/env python3
"""A complete client for the AI review API — standard library only.

Copy this file into your own project; it has no dependencies and is meant to
be read as much as run. See ../API-CLIENT-GUIDE.md for the protocol it speaks.

    python review_client.py https://github.com/owner/repo --mode quick
    python review_client.py https://github.com/owner/repo --wait --markdown
    python review_client.py https://github.com/owner/repo --dry-run

Exit codes make it usable in CI:
    0  review completed
    1  review failed, was cancelled, or the request was rejected
    2  could not reach the API
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = os.environ.get("REVIEW_API_URL", "http://127.0.0.1:8000")

# Terminal states of the review lifecycle:
#   requested -> cloning -> reviewing -> completed | failed | cancelled
DONE_STATES = ("completed", "failed", "cancelled")


class ApiError(RuntimeError):
    """An API call returned a problem document (RFC 9457)."""

    def __init__(self, status: int, body: dict | str):
        self.status = status
        self.body = body
        detail = body.get("detail") if isinstance(body, dict) else body
        hint = body.get("hint") if isinstance(body, dict) else None
        super().__init__(f"HTTP {status}: {detail}" + (f"\n  hint: {hint}" if hint else ""))


class ReviewClient:
    """Thin wrapper over the REST surface. Every method returns parsed JSON."""

    def __init__(self, base_url: str = DEFAULT_BASE, api_key: str = "",
                 timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("REVIEW_API_KEY", "")
        self.timeout = timeout

    # ---------------- transport ----------------

    def _request(self, method: str, path: str, body: dict | None = None,
                 params: dict | None = None, extra_headers: dict | None = None):
        url = self.base_url + path
        if params:
            # Drop None so callers can pass optional values straight through.
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key      # only when configured
        if body is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra_headers or {})

        req = urllib.request.Request(
            url, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if resp.headers.get_content_type() != "application/json":
                    return raw.decode("utf-8", "replace")     # e.g. markdown
                return json.loads(raw or b"{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                parsed = raw.decode("utf-8", "replace")
            raise ApiError(exc.code, parsed) from None
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Cannot reach the API at {self.base_url} — {exc.reason}. "
                "Is it running? (docker compose up / scripts/run-api.sh)"
            ) from None

    # ---------------- discovery ----------------

    def health(self, probe: bool = False, provider: str | None = None,
               endpoint: str | None = None) -> dict:
        return self._request("GET", "/api/v1/health", params={
            "probe": "1" if probe else None,
            "provider": provider, "endpoint": endpoint})

    def config(self) -> dict:
        return self._request("GET", "/api/v1/config")

    def providers(self) -> dict:
        return self._request("GET", "/api/v1/providers")

    def models(self, provider: str | None = None,
               endpoint: str | None = None) -> dict:
        """Models a provider/endpoint actually serves. Never guess an id."""
        return self._request("GET", "/api/v1/models",
                             params={"provider": provider, "endpoint": endpoint})

    def personas(self) -> dict:
        return self._request("GET", "/api/v1/personas")

    def repo_access(self, repo_url: str, branch: str | None = None,
                    access_token: str = "") -> dict:
        """~1s reachability check. Do this before a long private-repo review."""
        return self._request(
            "GET", "/api/v1/repo-access",
            params={"repo_url": repo_url, "branch": branch},
            # The token goes in a header, never the query string: URLs land in
            # access logs, browser history and proxies.
            extra_headers={"X-Repo-Token": access_token} if access_token else None)

    # ---------------- reviews ----------------

    def create(self, review_id: str, repo_url: str, *, mode: str = "brief",
               persona: str | None = None, system_prompt: str | None = None,
               provider: str | None = None, model: str | None = None,
               endpoint: str | None = None, branch: str | None = None,
               files: list[str] | None = None,
               extensions: list[str] | None = None,
               focus: list[str] | None = None,
               findings_file: str | None = None,
               access_token: str = "", dry_run: bool = False) -> dict:
        """Start a review (202), or build the prompt only (dry_run, 200).

        `review_id` is the idempotency key: reusing it while the review runs
        returns 409, and reusing it after a failure RESUMES from checkpoint.
        """
        body = {"review_id": review_id, "repo_url": repo_url, "mode": mode}
        optional = {"persona": persona, "system_prompt": system_prompt,
                    "provider": provider, "model": model, "endpoint": endpoint,
                    "branch": branch, "files": files, "extensions": extensions,
                    "focus": focus, "findings_file": findings_file}
        body.update({k: v for k, v in optional.items() if v})
        if dry_run:
            body["dry_run"] = True
        # The credential travels in the body over HTTPS (or a header); it is
        # never logged, persisted, or returned.
        if access_token:
            body["access_token"] = access_token
        return self._request("POST", "/api/v1/reviews", body=body)

    def status(self, review_id: str) -> dict:
        return self._request("GET", f"/api/v1/reviews/{urllib.parse.quote(review_id)}")

    def list_reviews(self, status: str | None = None, limit: int = 50) -> dict:
        return self._request("GET", "/api/v1/reviews",
                             params={"status": status, "limit": limit})

    def prompt(self, review_id: str) -> dict:
        return self._request("GET", f"/api/v1/reviews/{urllib.parse.quote(review_id)}/prompt")

    def restart(self, review_id: str, access_token: str = "") -> dict:
        """Resume a failed/cancelled review from its checkpoint."""
        body = {"access_token": access_token} if access_token else {}
        return self._request("POST", f"/api/v1/reviews/{urllib.parse.quote(review_id)}/restart",
                             body=body)

    def cancel(self, review_id: str) -> dict:
        """Stops after the unit in flight, so the checkpoint stays complete."""
        return self._request("POST", f"/api/v1/reviews/{urllib.parse.quote(review_id)}/cancel",
                             body={})

    def report(self, review_id: str, view: str = "summary",
               file: str | None = None):
        """view: summary | full | markdown. `file` returns one file's review."""
        return self._request("GET", f"/api/v1/reviews/{urllib.parse.quote(review_id)}/report",
                             params={"view": view, "file": file})

    # ---------------- reports on disk ----------------
    # These read the reports DIRECTORY, not the in-memory job registry, so
    # they still answer after an API restart.

    def reports(self, limit: int | None = None) -> dict:
        """Every report on disk, newest first, plus resumable checkpoints."""
        return self._request("GET", "/api/v1/reports",
                             params={"limit": limit})

    def get_report(self, name: str, view: str = "summary",
                   file: str | None = None):
        """One report by NAME (`DEMO-01` or `DEMO-01.json`, either works)."""
        return self._request("GET", f"/api/v1/reports/{urllib.parse.quote(name)}",
                             params={"view": view, "file": file})

    def delete_report(self, name: str, include_checkpoint: bool = False) -> dict:
        """Delete a report and its .md/.notes.md. IRREVERSIBLE.

        The resume checkpoint is kept unless include_checkpoint=True: a
        report can be regenerated, an interrupted review's checkpoint is the
        only record of work already done. Raises ApiError 409 while that
        review is still running.
        """
        return self._request(
            "DELETE", f"/api/v1/reports/{urllib.parse.quote(name)}",
            params={"include_checkpoint": "true" if include_checkpoint else None})

    # ---------------- the bit everyone writes by hand ----------------

    def wait(self, review_id: str, *, interval: float = 5.0,
             timeout: float | None = None, on_progress=None) -> dict:
        """Poll until the review reaches a terminal state, then return it.

        There is no long-poll on this API, so a client polls. Every few
        seconds is plenty: a review is minutes to hours, and `progress` is a
        ready-made line to print.
        """
        deadline = time.monotonic() + timeout if timeout else None
        last = None
        while True:
            job = self.status(review_id)
            if on_progress and job.get("progress") != last:
                last = job.get("progress")
                on_progress(job)
            if job.get("status") in DONE_STATES:
                return job
            if deadline and time.monotonic() > deadline:
                raise TimeoutError(
                    f"{review_id} still {job.get('status')} after {timeout}s. "
                    "The review keeps running server-side; poll again later.")
            time.sleep(interval)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("repo_url")
    p.add_argument("--api", default=DEFAULT_BASE, help=f"default {DEFAULT_BASE}")
    p.add_argument("--api-key", default="", help="X-API-Key, if the server sets one")
    p.add_argument("--review-id", default=None, help="default: derived from the repo name")
    p.add_argument("--mode", default="quick", choices=("quick", "brief", "deep"))
    p.add_argument("--persona", default="security")
    p.add_argument("--provider", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--endpoint", default=None, help="e.g. 100.83.14.22")
    p.add_argument("--branch", default=None)
    p.add_argument("--files", default=None, help="comma-separated paths/globs")
    p.add_argument("--findings-file", default=None)
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                   help="private repos; defaults to $GITHUB_TOKEN")
    p.add_argument("--dry-run", action="store_true", help="print the prompt only")
    p.add_argument("--wait", action="store_true", help="poll until finished")
    p.add_argument("--markdown", action="store_true", help="print the .md report")
    args = p.parse_args()

    review_id = args.review_id or args.repo_url.rstrip("/").split("/")[-1][:40]
    client = ReviewClient(args.api, args.api_key)

    try:
        # 1. Is the API up, and can its model endpoint be reached?
        health = client.health(probe=True, provider=args.provider,
                               endpoint=args.endpoint)
        probe = health.get("probe", {})
        print(f"api: ok · provider {probe.get('provider')} "
              f"{'reachable' if probe.get('reachable') else 'NOT reachable'}"
              f" ({probe.get('base_url')})")
        if not probe.get("reachable"):
            print(f"  hint: {probe.get('hint', '')}", file=sys.stderr)

        # 2. Can it clone the repository? Seconds, versus failing an hour in.
        access = client.repo_access(args.repo_url, args.branch, args.token)
        print(f"repo: {access.get('status')} — {access.get('note', access.get('error', ''))}")
        if access.get("status") != "ok":
            return 1

        # 3. Start it.
        job = client.create(
            review_id, args.repo_url, mode=args.mode, persona=args.persona,
            provider=args.provider, model=args.model, endpoint=args.endpoint,
            branch=args.branch, findings_file=args.findings_file,
            files=args.files.split(",") if args.files else None,
            access_token=args.token, dry_run=args.dry_run)

        if args.dry_run:
            print("\n--- consolidated prompt (nothing was sent to a model) ---")
            print(job["prompt"]["system_prompt"])
            return 0

        print(f"started: {job['review_id']} (job {job['job_id']}) "
              f"· {job['mode']} · {job['provider']} · {job.get('model')}")
        if not args.wait:
            print(f"poll: {args.api}{job['poll']}")
            return 0

        # 4. Follow it.
        final = client.wait(review_id,
                            on_progress=lambda j: print(f"  {j['progress']}"))
        print(f"\n{final['status']}: {final.get('message')}")
        if final["status"] != "completed":
            print(f"  error: {final.get('error')}", file=sys.stderr)
            if final.get("restartable"):
                print("  restartable — rerun with the same --review-id to "
                      "resume from the checkpoint", file=sys.stderr)
            return 1

        # 5. Read the result.
        stats = final.get("stats", {})
        print(f"  files reviewed: {stats.get('files_reviewed')} · "
              f"issues: {stats.get('issues_total')} · "
              f"by severity: {stats.get('issues_by_severity')}")
        print(f"  report: {final.get('report', {}).get('json')}")
        if args.markdown:
            print("\n--- markdown report ---")
            print(client.report(review_id, view="markdown"))
        return 0

    except ApiError as exc:
        print(f"api error: {exc}", file=sys.stderr)
        return 1
    except ConnectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(f"\nstopped watching; the review continues server-side. "
              f"Resume with: --review-id {review_id}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
