#!/usr/bin/env node
/**
 * A complete client for the AI review API — Node 18+, no dependencies.
 * See ../API-CLIENT-GUIDE.md for the protocol.
 *
 *   node review_client.mjs https://github.com/owner/repo
 *   node review_client.mjs https://github.com/owner/repo --mode brief --wait
 *   REVIEW_API_URL=http://100.83.14.22:8000 node review_client.mjs <repo>
 *
 * The same fetch calls work unchanged in a browser, which is exactly what
 * ../../frontend/index.html does.
 */

const DEFAULT_BASE = process.env.REVIEW_API_URL || "http://127.0.0.1:8000";
const DONE_STATES = ["completed", "failed", "cancelled"];

export class ApiError extends Error {
  constructor(status, body) {
    const detail = typeof body === "object" ? body.detail : body;
    super(`HTTP ${status}: ${detail}`);
    this.status = status;
    this.body = body;
  }
}

export class ReviewClient {
  constructor(baseUrl = DEFAULT_BASE, apiKey = process.env.REVIEW_API_KEY || "") {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
  }

  async #request(method, path, { body, params, extraHeaders } = {}) {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(params || {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, v);
    }
    const headers = { Accept: "application/json", ...(extraHeaders || {}) };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    if (body !== undefined) headers["Content-Type"] = "application/json";

    let res;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (cause) {
      throw new Error(
        `Cannot reach the API at ${this.baseUrl} — ${cause.message}. ` +
        `Is it running? (docker compose up / scripts/run-api.sh)`);
    }

    const text = await res.text();
    const isJson = (res.headers.get("content-type") || "").includes("json");
    const parsed = isJson ? JSON.parse(text || "{}") : text;
    if (!res.ok) throw new ApiError(res.status, parsed);
    return parsed;
  }

  // ---- discovery ----
  health(probe = false, provider, endpoint) {
    return this.#request("GET", "/api/v1/health",
      { params: { probe: probe ? "1" : undefined, provider, endpoint } });
  }
  config()    { return this.#request("GET", "/api/v1/config"); }
  providers() { return this.#request("GET", "/api/v1/providers"); }
  personas()  { return this.#request("GET", "/api/v1/personas"); }

  /** Models the endpoint actually serves — never guess an id. */
  models(provider, endpoint) {
    return this.#request("GET", "/api/v1/models", { params: { provider, endpoint } });
  }

  /** ~1s reachability check; the token goes in a header, never the URL. */
  repoAccess(repoUrl, branch, accessToken = "") {
    return this.#request("GET", "/api/v1/repo-access", {
      params: { repo_url: repoUrl, branch },
      extraHeaders: accessToken ? { "X-Repo-Token": accessToken } : undefined,
    });
  }

  // ---- reviews ----
  /** review_id is the idempotency key: reuse it to RESUME after a failure. */
  create(reviewId, repoUrl, opts = {}) {
    const { accessToken, dryRun, ...rest } = opts;
    const body = { review_id: reviewId, repo_url: repoUrl, mode: "brief" };
    for (const [k, v] of Object.entries(rest)) if (v) body[k] = v;
    if (dryRun) body.dry_run = true;
    if (accessToken) body.access_token = accessToken;
    return this.#request("POST", "/api/v1/reviews", { body });
  }

  status(id)   { return this.#request("GET", `/api/v1/reviews/${encodeURIComponent(id)}`); }
  prompt(id)   { return this.#request("GET", `/api/v1/reviews/${encodeURIComponent(id)}/prompt`); }
  cancel(id)   { return this.#request("POST", `/api/v1/reviews/${encodeURIComponent(id)}/cancel`, { body: {} }); }
  restart(id, accessToken = "") {
    return this.#request("POST", `/api/v1/reviews/${encodeURIComponent(id)}/restart`,
      { body: accessToken ? { access_token: accessToken } : {} });
  }
  report(id, view = "summary", file) {
    return this.#request("GET", `/api/v1/reviews/${encodeURIComponent(id)}/report`,
      { params: { view, file } });
  }
  listReviews(status, limit = 50) {
    return this.#request("GET", "/api/v1/reviews", { params: { status, limit } });
  }
  // ---- reports on disk (survive an API restart; job records do not) ----
  /** Every report on disk, newest first, plus resumable checkpoints. */
  reports(limit) { return this.#request("GET", "/api/v1/reports", { params: { limit } }); }

  /** One report by NAME — "DEMO-01" or "DEMO-01.json", either works. */
  getReport(name, view = "summary", file) {
    return this.#request("GET", `/api/v1/reports/${encodeURIComponent(name)}`,
      { params: { view, file } });
  }

  /** Delete a report and its .md/.notes.md. IRREVERSIBLE.
   *  The resume checkpoint survives unless includeCheckpoint is true, and a
   *  review still running rejects this with 409. */
  deleteReport(name, includeCheckpoint = false) {
    return this.#request("DELETE", `/api/v1/reports/${encodeURIComponent(name)}`,
      { params: { include_checkpoint: includeCheckpoint ? "true" : undefined } });
  }

  /** Poll to a terminal state. There is no long-poll; every few seconds is plenty. */
  async wait(id, { intervalMs = 5000, timeoutMs, onProgress } = {}) {
    const deadline = timeoutMs ? Date.now() + timeoutMs : null;
    let last;
    for (;;) {
      const job = await this.status(id);
      if (onProgress && job.progress !== last) { last = job.progress; onProgress(job); }
      if (DONE_STATES.includes(job.status)) return job;
      if (deadline && Date.now() > deadline) {
        throw new Error(`${id} still ${job.status}; it continues server-side.`);
      }
      await new Promise(r => setTimeout(r, intervalMs));
    }
  }
}

// --------------------------------------------------------------------------
// "Was this run directly, or imported?" Every step is guarded, because this
// file is meant to be importable as a library as well as run as a CLI:
// process.argv[1] is undefined under `node -e` and in bundlers, and in a
// browser there is no `process` at all — an unguarded read throws before any
// of the class above becomes usable.
// The comparison uses pathToFileURL because on Windows argv[1] is
// C:\path\with\backslashes and a hand-built `file://${...}` never matches,
// which silently turned the CLI into a no-op.
const entryPath = typeof process !== "undefined" ? process.argv?.[1] : undefined;
let isMain = false;
if (entryPath) {
  const { pathToFileURL } = await import("node:url");
  isMain = import.meta.url === pathToFileURL(entryPath).href;
}

if (isMain) {
  const args = process.argv.slice(2);
  const repoUrl = args.find(a => !a.startsWith("--"));
  const flag = (name, fallback) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : fallback;
  };
  if (!repoUrl) {
    console.error("usage: node review_client.mjs <repo-url> [--mode quick|brief|deep]" +
                  " [--endpoint 100.x.y.z] [--wait]");
    process.exit(2);
  }

  const client = new ReviewClient(flag("api", DEFAULT_BASE));
  const reviewId = flag("review-id", repoUrl.replace(/\/+$/, "").split("/").pop().slice(0, 40));
  const endpoint = flag("endpoint");
  const token = process.env.GITHUB_TOKEN || "";

  try {
    const health = await client.health(true, flag("provider"), endpoint);
    const probe = health.probe || {};
    console.log(`api: ok · ${probe.provider} ` +
      `${probe.reachable ? "reachable" : "NOT reachable"} (${probe.base_url})`);

    const access = await client.repoAccess(repoUrl, flag("branch"), token);
    console.log(`repo: ${access.status} — ${access.note || access.error || ""}`);
    if (access.status !== "ok") process.exit(1);

    const job = await client.create(reviewId, repoUrl, {
      mode: flag("mode", "quick"),
      persona: flag("persona", "security"),
      provider: flag("provider"),
      model: flag("model"),
      endpoint,
      accessToken: token,
      dryRun: args.includes("--dry-run"),
    });

    if (args.includes("--dry-run")) {
      console.log("\n--- consolidated prompt (nothing sent to a model) ---");
      console.log(job.prompt.system_prompt);
      process.exit(0);
    }

    console.log(`started: ${job.review_id} (job ${job.job_id}) · ${job.mode} · ${job.provider}`);
    if (!args.includes("--wait")) {
      console.log(`poll: ${client.baseUrl}${job.poll}`);
      process.exit(0);
    }

    const final = await client.wait(reviewId, { onProgress: j => console.log(`  ${j.progress}`) });
    console.log(`\n${final.status}: ${final.message}`);
    if (final.status !== "completed") {
      if (final.restartable) console.error("  restartable — rerun with the same --review-id");
      process.exit(1);
    }
    console.log(`  files: ${final.stats?.files_reviewed} · issues: ${final.stats?.issues_total}`);
    console.log(`  report: ${final.report?.json}`);
  } catch (err) {
    console.error(err instanceof ApiError ? `api error: ${err.message}` : err.message);
    process.exit(err instanceof ApiError ? 1 : 2);
  }
}
