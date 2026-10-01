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
- The original `Code-Review-MCP` checkout layout for the shared fixtures and
  deployment-artifact checks.

The suite expects these paths to be siblings in the original checkout:
`backend/`, `mcp-server/`, `frontend/`, `scanner/`, and
`docker-compose.yml`. In particular, `conftest.py` looks for the shared MCP
fixture under `mcp-server/tests`, and `test_image.py` reads the root Compose
file and other components' build scripts. Since the backend has been moved
into its own repository, the tests cannot currently run from the extracted
`ai-scanner-backend` repository alone. Use the original monorepo layout or
restore an equivalent layout before running them; no test code is changed by
this README.

## Run the Tests

From the root of a checkout with the expected monorepo layout, install the
editable packages and run pytest:

```bash
python -m pip install -e './mcp-server[dev]' -e './backend[dev]'
python -m pytest backend/tests
```

The Kubernetes tests use fakes and do not need a cluster. The API tests mock
the review pipeline and do not need an LLM endpoint, GitHub token, or scanner
binaries. `test_image.py` performs static checks; its build-script guard test
may be skipped when a compatible Bash executable is unavailable.