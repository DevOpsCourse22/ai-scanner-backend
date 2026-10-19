# scanner-worker

One review, run to completion as a **Kubernetes Job**, then exit.

The combined image described in
[docs/job-container-contract.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/job-container-contract.md): the
deterministic scanner tier ([../scanner](../scanner): Semgrep + Gitleaks +
Trivy) and the review engine ([../mcp-server](../mcp-server): clone, AI
enrichment, checkpoint/resume, reports) in one container. review-api's
`kubernetes` execution mode (`src/review_api/k8s_jobs.py`) creates one
Job per review from this image and polls it.

[entrypoint.py](entrypoint.py) is a thin wrapper around
`code_review_mcp.pipeline.run_review()`. It holds no review logic of its own.
It reads the Job's environment, calls the engine once, and turns the outcome
into an exit code.

```
Job env ──► entrypoint.py ──► run_review()
                                 ├─ clone          → /workspace   (emptyDir, gone with the Pod)
                                 ├─ scan           → /reports/<id>.findings.json
                                 ├─ AI review      → /reports/<id>.partial.json  (checkpoint)
                                 │                 → /reports/<id>.progress.json (live file timing)
                                 └─ report         → /reports/<id>.json + <id>.md
            ◄── exit 0 / 1 / 2  +  one line in /dev/termination-log
                                +  the same line in /reports/<id>.error.json
```

The full interface is [docs/job-container-contract.md](https://github.com/hadsahar/DevSecOps-Final-Project/blob/main/docs/job-container-contract.md) (v2).

## Inputs (environment)

| Variable | Required | Notes |
|---|---|---|
| `REPO_URL` | yes | `https://github.com/<owner>/<repo>` only |
| `REVIEW_ID` | yes | Names every output file. **Keep it the same on a retry**, because that is how the retry finds the checkpoint. Letters, digits, `_ . -`, max 128, no leading dot |
| `MODE` | yes | `quick` \| `brief` \| `deep` |
| `LMSTUDIO_BASE_URL` | yes | e.g. the Tailscale egress Service, `http://<svc>:1234/v1` |
| `SYSTEM_PROMPT` | yes | The reviewer's system prompt |
| `BRANCH` | no | Default: the repository's default branch |
| `GITHUB_TOKEN_FILE` | no | Path to a file holding the clone token. **What review-api uses** (contract v5): the file is read, then deleted |
| `GITHUB_TOKEN` | no | The same token as a variable, for a plain `docker run`. Never a literal in a Job spec |
| `LMSTUDIO_MODEL` | no | Pin the model; empty = whatever LM Studio has loaded |
| `COMMIT` | no | Full 40-character SHA; pins the clone to that commit (set by review-api on resume, contract v3) |
| `LLM_API_KEY_FILE` | no | Path to a file holding the AI service's API key from Settings (contract v5); read, then deleted |
| `LLM_API_KEY` | no | The same key as a variable (contract v4); never logged, removed from the environment before scanners run |

Every other `REVIEW_*` tuning variable of the engine (see
`mcp-server/src/code_review_mcp/config.py`) works too, for example
`REVIEW_RUN_SCANNER=0` to skip the deterministic tier.

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| `0` | The pipeline completed. **Findings in the code are a success.** | any finished review, even one with failed units inside it |
| `1` | Technical failure, **worth retrying** | LLM unreachable, network/DNS, git timeout, SIGTERM (Pod deleted / deadline), anything unexpected |
| `2` | Permanent failure, **a retry cannot fix it** | missing/invalid input, not a GitHub URL, repo not found or no access (bad or missing token), branch not found, no reviewable files, `/reports` or `/workspace` not writable |

The reason is written as **one line** in two places:

- `/reports/<id>.error.json` — `{"permanent": true|false, "error": "<line>"}`.
  This is what **review-api reads**: `permanent: true` stops the review at
  once; `false`, or no file at all (OOM kill, node lost), is retried. A file
  on the PVC rather than the Pod status, so review-api needs no `list` on
  pods (every Pod carries its Job's `REPO_URL` and `SYSTEM_PROMPT`). The
  worker deletes the previous attempt's file when it starts.
- `/dev/termination-log`, which Kubernetes copies into the Pod status — for
  a human with kubectl:

```bash
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[0].state.terminated.message}'
```

When a failure is unclear, the worker returns 1, because review-api caps
retries at 5 attempts. A wrong guess that way wastes a few attempts. A wrong
guess the other way (2) would give up on a review that could have succeeded.

## Live progress: `<id>.progress.json`

A Job pod cannot send progress messages to review-api the way an in-process
review does, so the worker writes them where review-api can read them:

```json
{"current_file": "src/app.py", "current_started_at": 1758830000.12,
 "durations": [["src/a.py", 41.2]], "updated_at": 1758830012.0}
```

Written fresh when an attempt starts, then when each file starts and
finishes, atomically; deleted at success. Between those, `updated_at` is
refreshed at most once a minute (`REVIEW_PROGRESS_HEARTBEAT_SECONDS`) while
the review shows any sign of life, in every mode: review-api treats an
attempt whose `updated_at` is 15 minutes old as stuck. Epoch seconds,
because a monotonic clock does not carry between Pods. `durations` holds
only this attempt's files. Per-file timing is deep mode only — brief and
quick have no per-file events. The file-start/finish patterns are the ones `review_api/jobs.py`
uses in process; a test fails if the two drift apart.

## The token

- review-api hands it over as a **file**, not a variable. Its Job copies the
  per-attempt Secret into an in-memory `emptyDir`
  (`/run/review-credentials`, init container `copy-credentials`), points
  `GITHUB_TOKEN_FILE` / `LLM_API_KEY_FILE` at it, and the worker deletes each
  file as soon as it has read it. A variable could not be made safe: removing
  it from `os.environ` leaves it in `/proc/<pid>/environ`, which keeps the
  environment the process started with and which anything running as the
  same user (a scanner, code in the reviewed repository) can read. The main
  container never mounts the Secret itself, and review-api deletes the
  Secret after every attempt.
- The worker takes it **out of the environment** before the engine is
  imported. Semgrep, Trivy and Gitleaks are child processes and inherit the
  environment, so they never see it.
- It is handed to `run_review()` as an argument, and the engine passes it to
  git through `GIT_ASKPASS`, so it never appears in a command line or a URL.
- Every log line and the termination message are **scrubbed** of it (`***`).
  Logs show `token supplied` or `token none`, never the value.
- It is NOT erased from memory right after the clone: `run_review()` holds
  its argument until it returns. Contract v2 says so plainly; v1's "dropped
  from memory" could not be honoured for an env var.

## Security posture it is built for

These are the settings `k8s_jobs.build_job_manifest()` already uses:

- `runAsNonRoot`, `runAsUser: 10001`: the image's user is numeric `10001:10001`
- `readOnlyRootFilesystem: true`: everything that writes goes to a mount:
  - `/workspace` (emptyDir): `TMPDIR`, the clone, `HOME`, Semgrep's
    `~/.semgrep`, Trivy's DB cache (`TRIVY_CACHE_DIR`). The worker creates
    these at start-up, because an emptyDir starts empty.
  - `/reports` (the PVC): reports and checkpoints only, never source code.
    Only the review's OWN folder of it (`subPath: .jobs/<review_id>`): the
    Job cannot see any other review's files. review-api copies what is
    written there to the flat `/reports/<id>.*` it reads (`sync_job_dir`).
  - `/tmp` (emptyDir): mounted by the Job as a backstop
- `capabilities: drop [ALL]`, `allowPrivilegeEscalation: false`
- `git safe.directory '*'` is in the **system** config (`/etc/gitconfig`),
  because `$HOME` is on the emptyDir and starts empty

**Network the Job needs (for a future NetworkPolicy):** GitHub (clone), the
LLM endpoint, and, because nothing is cached between Pods, **Trivy's
vulnerability DB** (`mirror.gcr.io` / `ghcr.io`) and **Semgrep's rule registry**
(`semgrep.dev`) on every run. Without the last two, those scanners are
recorded as failed in `<id>.findings.json` and the review continues without
them. The run does not fail.

## Build

From `Code-Review-MCP/`:

```bash
bash scanner-worker/build.sh                                   # scanner-worker:latest
bash scanner-worker/build.sh --tag 0.1.0                       # scanner-worker:0.1.0
bash scanner-worker/build.sh --registry ghcr.io/me --push      # needs docker login first
```

```powershell
powershell -ExecutionPolicy Bypass -File scanner-worker\build.ps1 -Tag 0.1.0
```

The build context is this folder; `mcp-server` and `scanner` arrive as named
build contexts. `k8s_jobs.py` defaults to the image name
`ai-scan-repos/scanner-worker:latest` (`SCANNER_WORKER_IMAGE` overrides it),
which is what `--registry ai-scan-repos` produces.

## Run it locally, the way a Job would

```bash
docker run --rm --read-only --user 10001:10001 --cap-drop ALL \
  --tmpfs /workspace:rw,exec,uid=10001,gid=10001,size=2g \
  --tmpfs /tmp:rw,uid=10001,gid=10001 \
  -v "$PWD/reports:/reports" \
  --add-host=host.docker.internal:host-gateway \
  -e REPO_URL=https://github.com/hadsahar/Secured-e-voting-system \
  -e REVIEW_ID=SW-LOCAL-01 -e MODE=brief \
  -e LMSTUDIO_BASE_URL=http://host.docker.internal:1234/v1 \
  -e SYSTEM_PROMPT="Strict security reviewer" \
  scanner-worker:latest
echo "exit: $?"
```

On Docker Desktop for Windows the `reports` bind mount must be writable by
uid 10001. The simplest way to try it there is `--tmpfs /reports:rw,uid=10001,gid=10001`
(the files disappear with the container).

## Tests

```powershell
# from Code-Review-MCP\ (Windows PowerShell)
.venv\Scripts\python.exe -m pytest scanner-worker/tests -q
# plus the tests that run the BUILT image under --read-only:
$env:SCANNER_WORKER_IMAGE_TEST = "1"; .venv\Scripts\python.exe -m pytest scanner-worker/tests -q
```

- `test_worker_entrypoint.py`: inputs, exit-code mapping, token handling and
  redaction, and a **crash → retry → resume** run through the real pipeline
  (the clone and the LLM are faked).
- `test_worker_progress.py`: `error.json` (written on every failure, one
  line, stale file removed at start) and `progress.json` (start/finish
  only, epoch times, this attempt's durations, deleted at success), the
  latter also through a real deep review and a crash + retry.
- `test_worker_image.py`: static Dockerfile and build-script checks, plus
  opt-in checks against the built image.
