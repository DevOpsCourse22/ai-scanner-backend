#!/usr/bin/env bash
# Build — and optionally push — the scanner-worker image, from this folder only.
#
#   bash scanner-worker/build.sh                              # scanner-worker:latest
#   bash scanner-worker/build.sh --tag 1.2.0                  # scanner-worker:1.2.0
#   bash scanner-worker/build.sh --registry ghcr.io/me --push # build, then push
#
# REGISTRY and TAG can also come from the environment. Pushing needs a prior
# `docker login <registry>`: this script never handles credentials.
set -euo pipefail

IMAGE=scanner-worker
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

# The shared review engine and the deterministic scanner tier both live
# outside this folder; each arrives as a named build context.
docker build --build-context mcp-server=../mcp-server \
             --build-context scanner=../scanner \
             --tag "$REF" .
echo "built:  $REF"

if [ "$PUSH" = 1 ]; then
    if ! docker push "$REF"; then
        echo "push failed. Logged in? docker login ${REGISTRY%%/*}" >&2
        exit 1
    fi
    echo "pushed: $REF"
fi
