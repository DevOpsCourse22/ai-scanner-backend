# review-api — the review API microservice

An HTTP API over the review pipeline. It accepts a review request,
consolidates everything into one server-owned prompt, runs the review in the
background against an **on-prem or a cloud LLM**, and lets a client follow
progress, restart a failed run, and fetch, list or delete reports.

**It is an API and nothing else.** No UI, no static files. The test console
that used to be served here is its own microservice now —
[review-console](https://github.com/hadsahar/DevSecOps-Final-Project/tree/main/Code-Review-MCP/frontend) — which proxies `/api/` to this one.

> 📖 **Calling it from code: [API-CLIENT-GUIDE.md](API-CLIENT-GUIDE.md)** —
> every endpoint with real request/response pairs, error handling, and
> runnable clients in [`examples/`](examples) (Python, Node, curl) ·
> Design and rationale: [17-review-api.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/17-review-api.md) ·
> Deploying to Kubernetes: [21-kubernetes-manifests-guide.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/21-kubernetes-manifests-guide.md)

---

## At a glance

| | |
|---|---|
| Image | `review-api` — built from **this folder** |
| Build | [`build.sh`](build.sh) / [`build.ps1`](build.ps1), or `docker build --build-context mcp-server=./mcp-server --build-context scanner=./scanner .` |
| Port | `8000/TCP` |
| Runs as | uid/gid **10001** (non-root, numeric) |
| Liveness | `GET /healthz` — no auth, checks nothing external |
| Readiness | `GET /readyz` — no auth; `503` if `/reports` or `/tmp` is not writable |
| Writable paths | `/reports` (keep: reports + checkpoints) · `/tmp` (clones, deleted after each review) |
| Root filesystem | may be read-only |
| Configuration | environment variables (below), over the baked `config/api.example.yaml` |
| Needs to reach | the LLM endpoint · `github.com:443` |
| Replicas | **one** — in-memory job registry, one review at a time |
| Depends on | the shared review engine in [`mcp-server/`](mcp-server) (embedded at build time) |

```
client (review-console / gateway / CI / curl)
   │  REST /api/v1
   ▼
review-api ── config.py ── providers: on-prem (LM Studio / Ollama / vLLM)
   │                                  cloud   (Google AI Studio / OpenAI / …)
   │  prompts.py  consolidate the request -> ONE system prompt
   │  jobs.py     job store + worker thread + per-review credential
   ▼
code_review_mcp.pipeline.run_review()      ← shared with the MCP server
   clone -> manifest -> review (quick|brief|deep) -> checkpoint -> report
   ▼
/reports/<review_id>.json + .md    (+ <review_id>.partial.json while running)
```

It **shares the pipeline with the MCP server rather than reimplementing it**,
so crash recovery behaves identically whichever door a review came through.

---

## Build and publish the image

Everything happens from this folder. The one thing the image needs from
outside it is the shared review engine, which is passed in as a **named
build context** rather than by widening the context to the whole repository.

```bash
bash ./build.sh                                    # review-api:latest
bash ./build.sh --tag 1.2.0                        # review-api:1.2.0
bash ./build.sh --registry ghcr.io/<owner> --push  # build, then push
```

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 -Tag 1.2.0
powershell -ExecutionPolicy Bypass -File build.ps1 -Registry ghcr.io/<owner> -Push
```

`REGISTRY` and `TAG` can also come from the environment. Pushing needs a
prior `docker login  -u <username>` — the script never touches credentials, and
it refuses `--push` without a registry, because an unqualified name would be
pushed to Docker Hub's official `library/` namespace.

By hand, from this folder:

```bash
docker build --build-context mcp-server=./mcp-server -t review-api .
```

Forget the `--build-context` and the build stops at its first step with a
message saying so, instead of trying to pull an image called `mcp-server`.

---

## How to Run

**As a Python process** (development), from the repository root:

***Linux / macOS***
```bash
pip install -e ./mcp-server[dev] -e ./scanner -e .[dev]
cp config\api.example.yaml config\api.yaml
python -m review_api.app --config config/api.yaml
```

***Windows***
```powershell
pip install -e ./mcp-server[dev] -e ./scanner -e .[dev]
copy config\api.example.yaml config\api.yaml
python -m review_api.app --config config/api.yaml
```

**As a Docker Container:**

```bash
docker run --rm -p 127.0.0.1:8000:8000 -v "$PWD/reports:/reports" review-api
```

**With the console, via compose** (repository root): `docker compose up --build`
starts both services — the API on <http://localhost:8000> (JSON only) and the
console on <http://localhost:8090>.

**On Kubernetes:** no manifests ship with this service on purpose — writing
them is part of the course. [21-kubernetes-manifests-guide.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/21-kubernetes-manifests-guide.md)
walks through what this image needs from them, the traps, and how to verify.

Then check it:

```text
curl http://127.0.0.1:8000/                          # what this service is
curl http://127.0.0.1:8000/readyz                    # can it do its job?
curl "http://127.0.0.1:8000/api/v1/health?probe=1"   # can it reach the model?
```

---

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service descriptor (JSON). No auth, reveals no configuration |
| GET | `/healthz` | Liveness. No auth. Checks nothing external |
| GET | `/readyz` | Readiness. No auth. `503` when reports or clones cannot be written |
| GET | `/api/v1/health` | Status. `?probe=1[&provider=x]` also asks the LLM for its model list — the model-reachability check |
| GET | `/api/v1/config` | The effective configuration, secrets stripped |
| GET | `/api/v1/providers` | Configured LLM endpoints with `location: on_prem\|cloud` and whether each key is set |
| GET | `/api/v1/models` | Models a provider (or `?endpoint=…`) actually serves |
| GET | `/api/v1/personas` | Named reviewer personas |
| GET | `/api/v1/repo-access` | `?repo_url=…[&branch=…]` — can we clone it? Accepts `X-Repo-Token`. Seconds, no clone |
| POST | `/api/v1/reviews` | **Create** a review. `dry_run: true` returns the prompt without calling the model |
| GET | `/api/v1/reviews` | List reviews (`?status=`, `?limit=`) |
| GET | `/api/v1/reviews/{id}` | **Progress**: state, done/total, percent, ETA, printable line |
| GET | `/api/v1/reviews/{id}/prompt` | The consolidated prompt that was used |
| POST | `/api/v1/reviews/{id}/restart` | **Restart** a failed/cancelled review — resumes from the checkpoint |
| POST | `/api/v1/reviews/{id}/retry-failed` | Re-review only the files a finished report lists as failed, merged into the same report |
| POST | `/api/v1/reviews/{id}/cancel` | Stop after the unit in flight, keeping the checkpoint complete |
| GET | `/api/v1/reviews/{id}/report` | Report: `?view=summary` (default) `\|full\|markdown`, or `?file=path` |
| GET | `/api/v1/reports` | All reports on disk, newest first, plus **resumable checkpoints**. `?limit=` |
| GET | `/api/v1/reports/{name}` | One report by name, straight off disk. Same `?view=` and `?file=` |
| DELETE | `/api/v1/reports/{name}` | Delete one report and its `.md`/`.notes.md`. Keeps the checkpoint unless `?include_checkpoint=true` |

Errors are RFC 9457-style problem documents. `review_id` doubles as the
**idempotency key**: the same id while running returns `409` with the running
job; the same id after a failure resumes from its checkpoint. When
`REVIEW_API_KEY` is set, every `/api/v1/*` call needs it as `X-API-Key`;
`/`, `/healthz` and `/readyz` never do.

---

## Configuration

The image bakes [`config/api.example.yaml`](config/api.example.yaml), whose
values are `${VAR:-default}` placeholders — so in a container, **environment
variables are the configuration**. Outside a container, copy it to
`config/api.yaml` (found via `--config`, `REVIEW_API_CONFIG`, or the
`config/` convention).

### The API itself

| Variable | Default | Meaning |
|---|---|---|
| `REVIEW_API_HOST` | `0.0.0.0` in the image, `127.0.0.1` otherwise | Bind address |
| `REVIEW_API_PORT` | `8000` | Bind port |
| `REVIEW_API_KEY` | *(empty = open)* | Shared secret required as `X-API-Key` on `/api/v1/*` |
| `REVIEW_API_OUTPUT_DIR` | `/reports` in the image | Reports, markdown renders, checkpoints |
| `REVIEW_API_DEFAULT_PROVIDER` | `lmstudio` | Which LLM endpoint a review uses unless it names one |
| `REVIEW_API_DEFAULT_MODE` | `brief` | `quick` \| `brief` \| `deep` |
| `REVIEW_API_DEFAULT_PERSONA` | `general` | Reviewer persona |
| `REVIEW_API_CORS_ORIGINS` | `*` | Comma-separated browser origins allowed to call the API |
| `REVIEW_API_CONFIG` | `/app/config/api.yaml` in the image | Config file path |
| `REVIEW_API_DEBUG` | off | Flask debug mode — never in production |

### The model

| Variable | Default | Meaning |
|---|---|---|
| `LMSTUDIO_BASE_URL` | `http://host.docker.internal:1234/v1` in the image | LM Studio, as seen **from where the API runs** |
| `LMSTUDIO_MODEL` | `google/gemma-4-26b-a4b-qat` | Model id |
| `TAILSCALE_LMSTUDIO_HOST` / `_PORT` | — / `1234` | LM Studio on a teammate's machine over Tailscale |
| `GOOGLE_API_KEY`, `GOOGLE_MODEL`, `GOOGLE_BASE_URL` | — | Google AI Studio (cloud) |
| `OLLAMA_BASE_URL`, `VLLM_BASE_URL`, `AZURE_OPENAI_BASE_URL` | — | Other providers |
| `OPENAI_API_KEY`, `GROQ_API_KEY`, `AZURE_OPENAI_API_KEY`, `VLLM_API_KEY` | — | Their keys |

### The review pipeline

| Variable | Default | Meaning |
|---|---|---|
| `GITHUB_TOKEN` (or `GH_TOKEN`) | — | Server-wide token for private repositories |
| `REVIEW_RUN_SCANNER` | `1` | Run the deterministic scanner tier when `repo_scanner` is installed (it is not, in this image) |
| `REVIEW_SKIP_GENERATED` | `1` | Skip minified and generated files, and report them as skipped |
| `REVIEW_PARALLEL` | `1` | Concurrent LLM requests |
| `REVIEW_STALL_TIMEOUT` | `300` | Seconds without a token before a request counts as stalled |
| `REVIEW_MAX_FILES`, `REVIEW_MAX_FILE_BYTES`, `REVIEW_MAX_CHUNK_CHARS`, `REVIEW_MAX_TOKENS`, … | see [`mcp-server`](mcp-server) | Limits |

**Secrets** — `REVIEW_API_KEY`, `GITHUB_TOKEN` and every `*_API_KEY` — come
from the environment only, never from a file you commit.

Two things make the same config file work everywhere:

- `${VAR}` and `${VAR:-fallback}` are expanded when the file is read. A
  `${VAR}` with no fallback that is not set is a **startup error**.
- Relative paths resolve against the **config file's** directory, not the
  working directory.

Two things it tolerates, on purpose:

- **`frontend_dir:`** in an older `api.yaml` is ignored with a warning — the
  console is a separate service now.
- **Kubernetes service-link variables.** A Service named `review-api` makes
  Kubernetes inject `REVIEW_API_PORT=tcp://<ip>:8000`, which is not a port.
  Any setting whose value looks like `tcp://…` is ignored with a warning
  instead of crashing startup. Set `enableServiceLinks: false` on the pod to
  stop Kubernetes injecting them at all.

---

## Cloud and on-prem LLMs

A **provider** is a named LLM endpoint. One request field (`provider`)
chooses where the review runs, so the same API serves a local model or a
hosted one with no code change. `kind: openai_compatible` covers LM Studio,
Ollama, vLLM, **Google AI Studio**, OpenAI, Groq, Together and
OpenAI-compatible Azure deployments.

`location: on_prem | cloud` is advisory but deliberate: it makes visible
whether a review would send code off the premises.

**Keys never live in the config file.** A provider names the *environment
variable* holding its key (`api_key_env: GOOGLE_API_KEY`), resolved at call
time, so `/api/v1/config` can report `api_key_configured` without exposing
anything.

## Private repositories

A request may carry `access_token` in the body or `X-Repo-Token` as a header.
The API routes it to the clone and nowhere else: held in a map keyed by job
id and deleted in the worker's `finally`, never on the job record, never in a
response, report or checkpoint, redacted from every log and error, and passed
to git through `GIT_ASKPASS` so it is in no command line. If a request omits
a token, the server-wide `GITHUB_TOKEN` is used.

## Security posture — read before exposing it

- **No user authentication.** `REVIEW_API_KEY` is a single shared secret, not
  identity. OIDC and per-repository authorization are platform work.
- **Not meant to be public.** It clones repositories, accepts tokens and
  deletes reports. Keep it on `127.0.0.1` (compose), on a tailnet address
  ([docs/18 §6](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/18-team-setup-guide.md)), or behind a ClusterIP
  Service — and set `REVIEW_API_KEY` before it is reachable by anyone else.
  At startup it prints whether it is reachable from the network, and warns
  loudly if it is and has no key.
- **Non-root, read-only-root capable.** The image runs as uid 10001 and needs
  write access only to `/reports` and `/tmp`.
- **One review at a time** by design; a second request gets `409 busy`.
- **In-memory job registry.** A restart loses job records but not reports or
  checkpoints — those are on the volume, and `/api/v1/reports` reads them
  from disk.

---

## Testing

```powershell
# from the repository root
.venv\Scripts\python.exe -m pytest tests -q
```

| File | Covers |
|---|---|
| `test_review_api.py` | config, providers, prompts, the review lifecycle, restart/resume against the real pipeline, report management, retry-failed, token handling |
| `test_pure_api.py` | no UI surface, `/healthz` and `/readyz` without a key, retired `frontend_dir`, Kubernetes service-link variables |
| `test_image.py` | the Dockerfile (non-root, no console, named context, healthcheck), the build script, the compose service |

These tests reuse the dummy-repo fixture from the
[mcp-server component](mcp-server/tests/fixtures/dummy_repo); see
[`tests/conftest.py`](tests/conftest.py).
