# code-review-mcp: portable MCP server image.
# The MCP host runs it with:  docker run --rm -i code-review-mcp
# (stdio flows through docker run -i; no ports needed for MCP itself).
FROM python:3.12-slim

# git is required for shallow-cloning the repos under review.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge || true

# host.docker.internal reaches the host machine (where LM Studio listens)
# from inside the container on Docker Desktop; on plain Linux add
# --add-host=host.docker.internal:host-gateway to the run args.
ENV LMSTUDIO_BASE_URL=http://host.docker.internal:1234/v1 \
    REVIEW_OUTPUT_DIR=/reports \
    PYTHONUNBUFFERED=1

# Reports land here; mount a host directory to receive them.
VOLUME /reports

ENTRYPOINT ["python", "-m", "code_review_mcp.server"]
