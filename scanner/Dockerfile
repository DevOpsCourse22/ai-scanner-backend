# Scanner image — Semgrep + Gitleaks + Trivy, normalized to one findings file.
#
# Job-shaped, not server-shaped: it runs, writes a file, and exits. That is
# why it has no port, no HEALTHCHECK, and an ENTRYPOINT that takes arguments
# — the opposite of gateway/Dockerfile in every one of those respects.
#
#     docker build -t repo-scanner .
#     docker run --rm \
#       -v /path/to/clone:/workspace:ro \
#       -v /path/to/reports:/reports \
#       repo-scanner /workspace -o /reports/scan.findings.json
FROM python:3.12-slim

WORKDIR /app

# Binaries lifted straight out of the official images rather than downloaded
# with curl: the vendors' own builds, pinned to an exact version, with no
# tarball to verify by hand and none of the rest of those images coming
# along. Both land in /usr/local/bin so find_executable() sees them the same
# way it sees Semgrep.
#
# Note the differing SOURCE paths — Trivy ships in /usr/local/bin, Gitleaks
# in /usr/bin. Checked with `docker run --entrypoint sh <image> -c 'command
# -v <tool>'` rather than assumed; the two are genuinely not the same.
COPY --from=aquasec/trivy:0.74.0 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=zricethezav/gitleaks:v8.30.1 /usr/bin/gitleaks /usr/local/bin/gitleaks

# git is not in python:3.12-slim, and Gitleaks shells out to it to walk
# the commit history - without it that scanner reports nothing while
# looking like it ran.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Semgrep needs no COPY --from: it is a Python package and comes in through
# the dependency below, unlike the two Go binaries above.
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge || true

# Same non-root posture as the gateway image, with the same fixed UID so a
# Kubernetes Job can assert runAsUser: 10001 / runAsNonRoot: true.
#
# What differs from the gateway: this container is handed SOMEONE ELSE'S
# REPOSITORY. It runs three parsers over untrusted input, which is exactly
# the process you least want running as root. Mount the repository read-only
# (`:ro`) as well — nothing here needs to write to it.
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /workspace /reports \
    && chown -R scanner:scanner /workspace /reports /app
USER scanner

# Gitleaks walks the history of a repository owned by a different UID than
# the one scanning it, which modern git refuses by default ("dubious
# ownership") — and the refusal surfaces as a scan that quietly finds
# nothing rather than as an error. The container only ever sees paths its
# caller mounted, so trusting them here does not widen anything.
RUN git config --global --add safe.directory '*'

# No EXPOSE and no HEALTHCHECK on purpose: nothing listens, and a task that
# is meant to exit has no steady state to be healthy in. Kubernetes judges
# a Job by its exit code instead.
#
# ENTRYPOINT, not CMD, so `docker run <image> /workspace -o out.json`
# APPENDS those arguments rather than replacing the command. CMD supplies
# the default when none are given, so a bare `docker run` prints usage
# instead of failing with an unhelpful error.
ENTRYPOINT ["repo-scan"]
CMD ["--help"]
