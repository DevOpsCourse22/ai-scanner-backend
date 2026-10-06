# mcp-server — the MCP front end and the shared review pipeline

An **MCP (Model Context Protocol) server** that performs AI code review of
GitHub repositories using an LLM — locally with **LM Studio**, or any
OpenAI-compatible endpoint. Packaged as a portable Docker image.

This component also owns **`pipeline.py`**, the review runner that the
[review-api microservice](..) embeds too. Clone, checkpointing,
resume and report writing therefore exist exactly once, and a review
interrupted in one front end can be resumed from the other.

| | |
|---|---|
| Image | `code-review-mcp` — built from **this folder**, nothing else |
| Build | [`build.sh`](build.sh) / [`build.ps1`](build.ps1), or `docker build .` |
| Transport | MCP over **stdio** — no port, no long-running service |
| Started by | the MCP host (LM Studio, Claude Code), once per session |
| Writes to | `/reports` (mount it) |

> 📖 Full reference: [docs/15-mcp-server-documentation.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/15-mcp-server-documentation.md)
> · Driving it from LM Studio: [docs/16-gemma-user-guide.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/16-gemma-user-guide.md)
> · Paste-ready prompts: [PROMPTS.md](PROMPTS.md)

> ⚙ This is the **LLM-only** version. The earlier Semgrep-hybrid variant was
> split out — deterministic scanning belongs to the platform's scanner
> component per the [adaptation plan](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/14-mcp-adaptation-plan.md). The
> hybrid implementation is preserved under the git tag `semgrep-hybrid`.
> Scanner **output** is still welcome here: see *Deterministic findings* below.

---

## Install and run

```powershell
# from the repository root
pip install -e ./mcp-server[dev]
python -m code_review_mcp.server        # speaks MCP over stdio
```

Or as a container (this is what LM Studio uses):

```powershell
bash mcp-server/build.sh          # or: docker build -t code-review-mcp ./mcp-server

docker run --rm -i --add-host=host.docker.internal:host-gateway `
  -v C:\Projects\Final-Project\reports:/reports `
  -e GITHUB_TOKEN code-review-mcp
```

Register it with an MCP host — see [`../.mcp.json`](../.mcp.json) for both a
venv entry and a Docker entry, and
[docs/16](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/16-gemma-user-guide.md) for LM Studio step by step.

Portability notes:
- The image is self-contained (Python + git + server, ~410 MB). Move it to
  another machine with `docker save code-review-mcp | docker load`.
- `host.docker.internal` reaches the host's LM Studio from the container;
  `--add-host=...:host-gateway` makes that work on plain Linux too (it is
  built in on Docker Desktop).
- **Relative `output_path` values land in `/reports`** = your mounted host
  folder.

## Build and publish the image

Self-contained: the build context is this folder and nothing else.

```bash
bash mcp-server/build.sh                                    # code-review-mcp:latest
bash mcp-server/build.sh --tag 1.2.0
bash mcp-server/build.sh --registry ghcr.io/<owner> --push  # build, then push
```

```powershell
powershell -ExecutionPolicy Bypass -File mcp-server\build.ps1 -Registry ghcr.io/<owner> -Push
```

`REGISTRY` and `TAG` can also come from the environment. Pushing needs a
prior `docker login`; the script refuses `--push` without a registry.

This image is not a Kubernetes service: an MCP server speaks stdio and is
started per session by its host. What runs in a cluster is
[review-api](..), which embeds this component's pipeline.

## Architecture

```
MCP host ──stdio──> docker run -i code-review-mcp ──HTTP──> LM Studio on host
                        │                                (host.docker.internal:1234)
                        │ 1. git clone --depth 1 <repo>     (inside container)
                        │ 2. repo -> pure JSON manifest     (repo_ingest.py)
                        │ 3. chunks -> LLM review           (llm.py / review.py)
                        │    streamed, liveness-monitored
                        │ 4. merge -> report                (review.py)
                        ▼
                    /reports (volume) -> host reports\ folder
```

The server contains **no AI**. It is orchestration only; wall time is
(number of LLM calls × model speed) plus a few seconds.

## The tools

| Tool | Purpose |
|---|---|
| `start_review(repo_url, system_prompt, output_path?, branch?, extensions?, mode?, model?, review_id?, files?, findings_file?)` | **Recommended.** Starts the review in the background, returns a `job_id` instantly. `review_id="X"` names the outputs `X.json` + `X.md`; the same id again **resumes** from a checkpoint |
| `get_review_status(job_id, wait_seconds=40)` | **Long-polls** up to 40s server-side and answers in one compact line with progress and ETA |
| `get_report(report, file?, full?)` | Results **through MCP**, by job_id or filename: summary, one file, or the raw JSON. No volume required |
| `get_report_entry(report, index)` | One file's review per call (context-safe iteration) |
| `append_report_notes(report, text)` / `read_report_notes(report, offset?)` | Persistent `<report>.notes.md` scratchpad for iterate → render → summarize |
| `list_reports()` | Reports on disk plus **resumable checkpoints** |
| `check_repo_access(repo_url, branch?)` | Can the server clone this repo (public or **private**)? A `ls-remote`, ~1s, no LLM. Reports whether a token is configured — never its value |
| `check_llm()` | Endpoint probe; returns `busy` instantly while a job runs |
| `ingest_repository_only(...)` | Clone → JSON manifest only, no LLM |
| `review_repository(...)` | The same pipeline as ONE blocking call — **hidden unless `REVIEW_ENABLE_BLOCKING=1`** |

> **Why the blocking tool is hidden.** Tested with Gemma 4: when
> `review_repository` is in the catalog the model picks it by name for any
> "review this repo" request (3/3 trials), blocks past the host's 60s tool
> timeout, and dies with `-32001`. Hidden, Gemma picks `start_review` (3/3).
> Long-timeout hosts such as Claude Code can re-enable it.

## The three modes

| Mode | LLM calls | Coverage | 123-file repo | Use |
|---|---|---|---|---|
| **quick** | 1 | all files (regex surface scan + AI overview) | ~30–60s | instant impression |
| **brief** (default) | batches + 1 (~10) | all files, head of each, batched | ~5 min (12b) / ~10–15 min (26b) | full-repo triage |
| **deep** | 1 per file | full detail, checkpointed | hours for a whole repo | targeted, with `files=` |

`files=["*/views.py", "exact/path.py", "admin.py"]` matches full path **or**
basename, globs allowed. The intended workflow is quick/brief triage → deep
on the flagged files.

## Private repositories

The server authenticates with a PAT from its own `GITHUB_TOKEN` (or
`GH_TOKEN`) environment variable. **No tool takes a token argument, on
purpose** — an argument would flow through the MCP protocol into the chat
transcript, the model's context and the host's logs. The credential reaches
git through `GIT_ASKPASS`, so it appears in no command line, no URL, no log
and no report; only an `authenticated: true` provenance flag is recorded.

Run `check_repo_access(repo_url)` first: ~1s, and it explains *why* on
failure — including GitHub's misleading "not found" for anonymous access to a
private repo.

## Deterministic findings intake

The MCP runs no scanner, but it **accepts scanner output**.
`start_review(..., findings_file="scan.json")` reads a findings JSON from the
reports folder and feeds it through the review: into deep-mode prompts for
verification and enrichment (impact + remediation, or a reasoned
false-positive dismissal), as `static_flags` hints in brief batches, and
merged into quick-mode issues. Findings are attached to the report
**verbatim** as `static_findings` — the model can never delete or downgrade
one — with `confirmed_by_llm` when it independently found the same thing
within ±2 lines.

## Self-healing

1. **Checkpoints** — after every completed unit (each file in deep, each
   batch in brief) partial results are written atomically to
   `<name>.partial.json`. A crash, even an OOM kill of the whole container,
   loses at most the unit in flight.
2. **Resume** — `start_review` again with the same `review_id` and mode: if
   the checkpoint matches the repo commit, completed units are reused
   (`resumed: true`, `reused_reviews`/`reused_batches`) and only the rest is
   reviewed. A changed commit safely starts fresh.
3. **Disconnect survival** — if the host tears down the session, the
   container finishes the review and writes the report before exiting.

Checkpoints are only observable **during** a run or **after** a crash: a
successful run deletes its `.partial.json`.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LMSTUDIO_BASE_URL` | `http://host.docker.internal:1234/v1` (image) | LLM endpoint |
| `LMSTUDIO_MODEL` | *(empty = first loaded model)* | Model id |
| `REVIEW_OUTPUT_DIR` | `/reports` (image) | Base dir for relative output paths |
| `REVIEW_STALL_TIMEOUT` | `300` | Seconds with NO tokens before declaring the model dead |
| `REVIEW_HEARTBEAT_SECONDS` | `3` | Min seconds between liveness updates |
| `REVIEW_MAX_CHUNK_CHARS` | `48000` | Per-request file content budget |
| `REVIEW_MAX_FILE_BYTES` | `512000` | Skip files larger than this |
| `REVIEW_MAX_FILES` | `500` | Cap on files per run |
| `REVIEW_TEMPERATURE` | `0.2` | Sampling temperature |
| `REVIEW_MAX_TOKENS` | `4096` | Max tokens per deep-mode response |
| `REVIEW_BRIEF_MAX_TOKENS` | `3000` | Token cap per brief response |
| `REVIEW_BRIEF_PACK_CHARS` | `12000` | Char budget per digest batch |
| `REVIEW_BRIEF_FILE_CAP` | `1200` | Max chars per file in the digest |
| `REVIEW_TRIVIAL_FILE_CHARS` | `50` | Files smaller than this skip the LLM |
| `REVIEW_JSON_RETRIES` | `2` | Self-correction retries on invalid JSON |
| `REVIEW_PARALLEL` | `1` | Concurrent LLM requests (1–8). Raise only after enabling parallel request processing in your LLM server |
| `REVIEW_ENABLE_BLOCKING` | *(unset)* | Set to `1` to expose the blocking tool |
| `GITHUB_TOKEN` / `GH_TOKEN` | *(empty = anonymous)* | PAT for **private** repos. Environment only |

## No timeouts — liveness instead

A review is never killed for taking long. Tokens are **streamed**, and
arriving tokens (including hidden reasoning tokens) are proof the model is
working; a heartbeat goes to the MCP host every few seconds. Only two things
end a run early, both real errors: a **stall** (no tokens for
`REVIEW_STALL_TIMEOUT`) and an **unreachable** endpoint. A file whose review
is invalid JSON after retries is recorded in `failures` and the run
continues.

## Testing

```powershell
# from the repository root
.venv\Scripts\python.exe -m pytest mcp-server/tests -q      # 91 tests, no LLM
```

- [`tests/fixtures/dummy_repo`](tests/fixtures/dummy_repo) — a dummy
  vulnerable repository with one planted instance of every surface-check
  class. Also used by the backend tests.
- [`tests/test_dummy_repo.py`](tests/test_dummy_repo.py) — includes full
  **disaster-recovery** tests that crash a review mid-run and prove the
  checkpoint + resume cycle, for deep and brief.
- [`tests/mock_llm_server.py`](tests/mock_llm_server.py) — a stdlib-only
  OpenAI-compatible server that always answers with valid review JSON, so
  the whole pipeline can be exercised with **no LLM and no GPU**:

  ```powershell
  .venv\Scripts\python.exe mcp-server\tests\mock_llm_server.py --port 8765
  # --delay 0.8 simulates a slow model, --stall-after 5 a wedged one
  ```

- [`tests/e2e_review.py`](tests/e2e_review.py) — runs a REAL review (job
  thread, checkpoints, resume) against any endpoint. The kill-test drill:
  start a review, kill the process mid-run, rerun the same command — the
  status line shows `(+N restored)`.

## Troubleshooting

- **`MCP error -32001` in LM Studio** — a tool call exceeded the host's
  per-call timeout (60s default). Add `"timeout": 300000` to the server entry
  in LM Studio's mcp.json, and make sure you rebuilt the image.
- **After ANY code change**: `docker build -t code-review-mcp ./mcp-server`,
  then **toggle the MCP server off and on in LM Studio** — otherwise it keeps
  using the old container. This is the number one cause of "the fix didn't
  take".
- **`Model stalled`** — no tokens for `REVIEW_STALL_TIMEOUT`s. Check the model
  is loaded and the server isn't wedged.
- **`Cannot reach LLM endpoint`** — from inside the container the host is
  `host.docker.internal`, never `localhost`.
- **Truncated/invalid JSON on complex files** — reasoning models spend hidden
  tokens from the same budget; raise `REVIEW_MAX_TOKENS` or lower
  `REVIEW_MAX_CHUNK_CHARS`.
- **Windows-native (non-Docker) git hangs** — see `_run_git` in
  [`src/code_review_mcp/repo_ingest.py`](src/code_review_mcp/repo_ingest.py):
  MCP hosts spawn servers console-less, where Git for Windows deadlocks on
  pipe stdio. The hardening stays in place for the venv entry; the Docker
  path avoids the problem class entirely.
