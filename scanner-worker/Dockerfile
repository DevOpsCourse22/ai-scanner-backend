# syntax=docker/dockerfile:1
#
# scanner-worker — ONE review, run as a Kubernetes Job, then exit.
#
# The combined image of docs/job-container-contract.md: the deterministic
# scanner tier (../scanner: Semgrep + Gitleaks + Trivy) and the review
# engine (../mcp-server: clone, AI enrichment, checkpoint/resume, reports)
# in one container, because for one review they only ever run in sequence.
# entrypoint.py turns the Job's env vars into a run_review() call and the
# outcome into exit code 0 / 1 (retry) / 2 (do not retry).
#
# Build context is THIS folder; the two packages arrive as NAMED build
# contexts, exactly as in backend/Dockerfile:
#
#     ./build.sh                                        # or .\build.ps1
#     docker build --build-context mcp-server=../mcp-server \
#                  --build-context scanner=../scanner -t scanner-worker .
#
# Job-shaped like scanner/Dockerfile: no port, no HEALTHCHECK, no server.
# Kubernetes judges it by exit code.

# Placeholder, REPLACED by --build-context mcp-server=... when it is given.
FROM python:3.12-slim AS mcp-server
RUN echo "scanner-worker: build with --build-context mcp-server=../mcp-server (or run ./build.sh)" >&2 \
    && exit 1

# Placeholder, REPLACED by --build-context scanner=... when it is given.
FROM python:3.12-slim AS scanner
RUN echo "scanner-worker: build with --build-context scanner=../scanner (or run ./build.sh)" >&2 \
    && exit 1

FROM python:3.12-slim

# git: cloning the repository under review, and Gitleaks shells out to it
# to walk the commit history.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The two compiled scanners, lifted out of the vendors' own images: pinned,
# nothing downloaded by hand at build time. The SOURCE paths differ (Trivy
# ships in /usr/local/bin, Gitleaks in /usr/bin) — same as scanner/Dockerfile.
COPY --from=aquasec/trivy:0.74.0 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=zricethezav/gitleaks:v8.30.1 /usr/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app

# Dependencies before the entrypoint: the entrypoint changes more often.
# Semgrep arrives here too, as a Python dependency of the scanner package.
COPY --from=mcp-server pyproject.toml README.md ./mcp-server/
COPY --from=mcp-server src ./mcp-server/src
COPY --from=scanner pyproject.toml README.md ./scanner/
COPY --from=scanner src ./scanner/src
RUN pip install --no-cache-dir ./mcp-server ./scanner && pip cache purge || true

COPY entrypoint.py ./entrypoint.py

# SYSTEM git config (/etc/gitconfig), not --global: the global file lives in
# $HOME, and $HOME here is an emptyDir that starts empty on every Pod. The
# clone is owned by this same user, but Gitleaks runs git over it, and a
# "dubious ownership" refusal shows up as a scan that silently finds
# nothing. The container only sees what the Job mounted, so trusting every
# path widens nothing.
RUN git config --system --add safe.directory '*'

# Fixed numeric non-root user, so a Job can assert runAsUser: 10001 and
# runAsNonRoot. No home directory in the image: HOME is on /workspace.
# /workspace and /reports exist and belong to that user so a plain
# `docker run` works; in Kubernetes both are mounts (emptyDir and PVC).
RUN groupadd --system --gid 10001 worker \
    && useradd --system --uid 10001 --gid worker --no-create-home \
               --home-dir /workspace/home --shell /usr/sbin/nologin worker \
    && mkdir -p /workspace /reports \
    && chown worker:worker /workspace /reports

# READ-ONLY ROOT FILESYSTEM: everything that writes goes to /workspace
# (the clone, temp files, HOME, Semgrep's ~/.semgrep, Trivy's vulnerability
# DB cache) or to /reports. entrypoint.py creates these directories at
# start-up, because an emptyDir is empty. Nothing is cached between Pods:
# Trivy downloads its DB and Semgrep its rules on every review.
ENV TMPDIR=/workspace \
    HOME=/workspace/home \
    XDG_CACHE_HOME=/workspace/.cache \
    XDG_CONFIG_HOME=/workspace/.config \
    TRIVY_CACHE_DIR=/workspace/.cache/trivy \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SEND_METRICS=off \
    REVIEW_OUTPUT_DIR=/reports \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

# Exec form: python is PID 1 and receives SIGTERM itself, so a deleted Pod
# still writes its reason to /dev/termination-log.
ENTRYPOINT ["python", "/app/entrypoint.py"]
