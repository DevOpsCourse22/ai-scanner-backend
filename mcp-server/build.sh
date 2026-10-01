#!/usr/bin/env bash
# Build — and optionally push — the code-review-mcp image, from this folder only.
#
#   bash mcp-server/build.sh                                 # code-review-mcp:latest
#   bash mcp-server/build.sh --tag 1.2.0                     # code-review-mcp:1.2.0
#   bash mcp-server/build.sh --registry ghcr.io/me --push    # build, then push
#
# REGISTRY and TAG can also come from the environment. Pushing needs a prior
# `docker login <registry>`: this script never handles credentials.
set -euo pipefail

IMAGE=code-review-mcp
REGISTRY="${REGISTRY:-}"
TAG="${TAG:-latest}"
PUSH=0

while [ $# -gt 0 ]; do
    case "$1" in
        --registry) REGISTRY="$2"; shift 2 ;;
        --tag)      TAG="$2"; shift 2 ;;
        --push)     PUSH=1; shift ;;
        -h|--help)  sed -n '2,9p' "$0"; exit 0 ;;
        *)          echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done

# Refuse before building, not after: an unqualified name would be pushed to
# Docker Hub's official "library" namespace, which nobody here can write to.
if [ "$PUSH" = 1 ] && [ -z "$REGISTRY" ]; then
    echo "--push needs --registry (e.g. ghcr.io/<owner> or docker.io/<user>)" >&2
    exit 2
fi

cd "$(dirname "${BASH_SOURCE[0]}")"
REF="${REGISTRY:+${REGISTRY%/}/}${IMAGE}:${TAG}"

# Self-contained: the build context is this folder and nothing else.
docker build --tag "$REF" .
echo "built:  $REF"

if [ "$PUSH" = 1 ]; then
    if ! docker push "$REF"; then
        echo "push failed. Logged in? docker login ${REGISTRY%%/*}" >&2
        exit 1
    fi
    echo "pushed: $REF"
fi
