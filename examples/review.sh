#!/usr/bin/env bash
# The whole flow in curl + jq — the shortest thing that is still correct.
# See ../API-CLIENT-GUIDE.md.
#
#   ./review.sh https://github.com/owner/repo
#   API=http://100.83.14.22:8000 MODE=brief ./review.sh https://github.com/owner/repo
#
# Requires: curl, jq.
set -euo pipefail

REPO="${1:?usage: review.sh <repo-url>}"
API="${API:-http://127.0.0.1:8000}"
MODE="${MODE:-quick}"
PERSONA="${PERSONA:-security}"
REVIEW_ID="${REVIEW_ID:-$(basename "$REPO" .git)}"

# Only send the header when a key is configured; an empty one is still checked.
auth=()
[ -n "${REVIEW_API_KEY:-}" ] && auth=(-H "X-API-Key: $REVIEW_API_KEY")

say() { printf '%s\n' "$*" >&2; }

# 1. Is the API up, and can it reach a model?
#    Note each jq gets the JSON explicitly: a here-string on `say` would feed
#    `say`, not the command substitutions inside its argument.
probe=$(curl -sS "${auth[@]}" "$API/api/v1/health?probe=1")
say "api:  $(jq -r '.status' <<<"$probe") · provider $(jq -r '.probe.provider' <<<"$probe") reachable=$(jq -r '.probe.reachable' <<<"$probe")"

# 2. Can it clone the repo? Seconds, instead of failing an hour in.
#    The token goes in a header — a query string would land in access logs.
access=$(curl -sS "${auth[@]}" \
  ${GITHUB_TOKEN:+-H "X-Repo-Token: $GITHUB_TOKEN"} \
  --get --data-urlencode "repo_url=$REPO" "$API/api/v1/repo-access")
say "repo: $(jq -r '.status' <<<"$access") — $(jq -r '.note // .error' <<<"$access")"
[ "$(jq -r '.status' <<<"$access")" = "ok" ] || exit 1

# 3. Start it. 202 = accepted; the body is the job.
job=$(curl -sS -X POST "$API/api/v1/reviews" "${auth[@]}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg id "$REVIEW_ID" --arg repo "$REPO" --arg mode "$MODE" \
              --arg persona "$PERSONA" --arg tok "${GITHUB_TOKEN:-}" \
              --arg ep "${ENDPOINT:-}" '
        {review_id:$id, repo_url:$repo, mode:$mode, persona:$persona}
        + (if $tok == "" then {} else {access_token:$tok} end)
        + (if $ep  == "" then {} else {endpoint:$ep}      end)')")

if [ "$(jq -r '.status' <<<"$job")" = "busy" ]; then
  say "busy: another review is running. $(jq -r '.hint' <<<"$job")"
  exit 1
fi
say "started: $(jq -r '.review_id' <<<"$job") (job $(jq -r '.job_id' <<<"$job"))"

# 4. Poll to a terminal state.
while :; do
  s=$(curl -sS "${auth[@]}" "$API/api/v1/reviews/$REVIEW_ID")
  say "  $(jq -r '.progress' <<<"$s")"
  case "$(jq -r '.status' <<<"$s")" in
    completed) break ;;
    failed|cancelled)
      say "FAILED: $(jq -r '.error // .message' <<<"$s")"
      jq -e '.restartable' <<<"$s" >/dev/null && \
        say "restartable — rerun with REVIEW_ID=$REVIEW_ID to resume"
      exit 1 ;;
  esac
  sleep 5
done

# 5. Read it.
curl -sS "${auth[@]}" "$API/api/v1/reviews/$REVIEW_ID/report" \
  | jq '{report, commit, stats, overall: .overall.summary}'
