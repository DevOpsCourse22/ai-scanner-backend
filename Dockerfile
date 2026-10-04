# syntax=docker/dockerfile:1
#
# review-api — the review API microservice. API only: no UI, no static files.
#
# Build context is THIS folder. Two things come from outside it, each as a
# NAMED build context rather than by widening the context to the whole
# repository: the shared review engine (./mcp-server) and the deterministic
# scanner tier (./scanner).
#
#     ./build.sh                                        # or .\build.ps1
#     docker build --build-context mcp-server=./mcp-server \
#                  --build-context scanner=./scanner -t review-api .
#
# Forget either --build-context and the build stops at the matching step
# below with a message saying so, instead of trying to pull an image by that
# name.

# Placeholder, REPLACED by --build-context mcp-server=... when it is given.
FROM python:3.12-slim AS mcp-server
RUN echo "review-api: build with --build-context mcp-server=./mcp-server (or run ./build.sh)" >&2 \
    && exit 1

# Placeholder, REPLACED by --build-context scanner=... when it is given.
FROM python:3.12-slim AS scanner
RUN echo "review-api: build with --build-context scanner=./scanner (or run ./build.sh)" >&2 \
    && exit 1

FROM python:3.12-slim

# git is required twice over: for shallow-cloning the repositories under
# review, and because Gitleaks shells out to it to walk history.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The deterministic tier's two compiled scanners, taken from their own
# official images so the versions are pinned and nothing is downloaded at
# build time. Semgrep is not here because it is a Python package and arrives
# with the scanner below.
#
# Without these, this image can still serve the API and run AI reviews — the
# scanner hook degrades to "not installed" rather than failing. That is
# exactly why they belong in the image: a deployed review-api that silently
# produces AI-only reports looks like it is working, and the missing half
# only shows up as an absence in the findings.
#
# The SOURCE paths differ between the two upstream images (Trivy ships in
# /usr/local/bin, Gitleaks in /usr/bin), which is why they are not one line.
COPY --from=aquasec/trivy:0.74.0 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=zricethezav/gitleaks:v8.30.1 /usr/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app

# Dependencies change far less often than source, so copy the three packages
# and install them before anything else that invalidates the layer cache.
COPY --from=mcp-server pyproject.toml README.md ./mcp-server/
COPY --from=mcp-server src ./mcp-server/src
COPY --from=scanner pyproject.toml README.md ./scanner/
COPY --from=scanner src ./scanner/src
COPY pyproject.toml README.md ./backend/
COPY src ./backend/src
# The [kubernetes] extra is the python client k8s_jobs.py needs when
# REVIEW_API_EXECUTION_MODE=kubernetes. Without it the image starts fine and
# every review then fails with "requires the optional dependency" — the
# same image has to work in both modes, so it is always installed.
# Quoted: [ ] are glob characters to the shell running this RUN line.
RUN pip install --no-cache-dir ./mcp-server ./scanner "./backend[kubernetes]" \
    && pip cache purge || true

COPY config/api.example.yaml ./config/api.yaml

# A fixed, numeric, unprivileged user. Numeric so Kubernetes can verify
# runAsNonRoot without guessing; fixed so a volume's fsGroup can match it.
# /reports is created here, owned by that user, so a fresh named volume or
# an emptyDir is writable without any init step.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /home/app \
               --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /reports \
    && chown app:app /reports

# 0.0.0.0 binds inside the CONTAINER's network namespace only. Who can reach
# the API is decided by the port publication in docker-compose.yml (limited
# to 127.0.0.1) or by the Kubernetes Service (ClusterIP) — see those first.
ENV REVIEW_API_HOST=0.0.0.0 \
    REVIEW_API_PORT=8000 \
    REVIEW_API_CONFIG=/app/config/api.yaml \
    REVIEW_API_OUTPUT_DIR=/reports \
    LMSTUDIO_BASE_URL=http://host.docker.internal:1234/v1 \
    HOME=/home/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Reports, markdown renders and crash checkpoints. Mount a volume to keep them
# (and to share them with the MCP server's own /reports mount).
VOLUME /reports
USER 10001:10001
EXPOSE 8000

# /healthz needs no API key and checks nothing external, so a key being set
# or the model being down never marks a working API unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).read()"]

CMD ["python", "-m", "review_api.app"]
