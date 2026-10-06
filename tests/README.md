# AI Scan Repos Backend Tests

This directory contains the automated tests for the `review-api` backend.
They cover API behavior, review lifecycle and reporting, Kubernetes Job
construction, and deployment configuration. Most tests use temporary files,
Flask's test client, and mocked external services so they do not submit code
to a real model or launch real repository scans.

## Test Files

### `conftest.py`

Provides shared test setup. It reuses the planted-issue repository fixture
from `mcp-server/tests/test_dummy_repo.py` and disables real Semgrep,
Gitleaks, and Trivy execution for the suite.

### `test_review_api.py`

Exercises the review API using a Flask test client and a mocked review
pipeline. Coverage includes:

- Configuration loading, environment overrides, provider setup, and endpoint
  validation.
- Review creation, prompt generation, progress, pause, resume, restart, and
  retry behavior.
- API-key enforcement and protection of GitHub and model credentials.
- Report listing, retrieval, deletion, checkpoints, and file-level progress.
- Scanner status and coverage reporting, including incomplete or failed
  scanner runs.

### `test_k8s_jobs.py`

Checks Kubernetes Job manifests and the job store without requiring a live
cluster. It covers pod security settings, secret references, valid names and
labels, retry limits, worker error and progress files, timeouts, and pause or
resume behavior.

### `test_pure_api.py`

Verifies that the backend remains an API rather than serving a frontend. It
checks the JSON service descriptor, absence of static routes, unauthenticated
health and readiness probes, configuration compatibility, and Kubernetes
service-link handling.

### `test_image.py`

Checks deployment artifacts without building or starting a container. It
validates the Dockerfile's non-root user, health check, scanner binaries,
build contexts, and ignored files, along with build scripts and the API's
Docker Compose configuration.

## Prerequisites

- Python 3.10 or newer.
- The backend and shared `mcp-server` Python packages, plus the backend's
  development dependency (`pytest`).
- `mcp-server/` in this repository: `conftest.py` reuses its dummy-repo
  fixture from `mcp-server/tests`.

The suite runs from this repository alone. `test_image.py` checks this
repository's Dockerfile and build scripts (root, `mcp-server/`,
`scanner-worker/`). Its four Compose checks need `docker-compose.yml`, which
stayed in the umbrella repository (hadsahar/DevSecOps-Final-Project,
`Code-Review-MCP/`); here they are skipped.

## Run the Tests

From the root of this repository, install the editable packages and run
pytest (Semgrep, a dependency of `scanner`, does not install on Windows: there
use `pip install --no-deps -e ./scanner`, the tests fake the scanners anyway):

```bash
python -m pip install -e './mcp-server[dev]' -e './scanner' -e '.[dev]'
python -m pytest tests
```

The Kubernetes tests use fakes and do not need a cluster. The API tests mock
the review pipeline and do not need an LLM endpoint, GitHub token, or scanner
binaries. `test_image.py` performs static checks; its build-script guard test
may be skipped when a compatible Bash executable is unavailable.