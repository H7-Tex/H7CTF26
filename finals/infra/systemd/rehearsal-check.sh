#!/usr/bin/env bash
# rehearsal-check.sh — Fri dry-run: verify engine-driven hill windows fire at compressed times.
# Run after the Fri rehearsal config is applied. Polls the admin API every 30s
# and reports when each hill transitions open/closed at the expected times.
#
# Usage: rehearsal-check.sh [poll_interval_s]
#   poll_interval_s — how often to poll (default 30)
#
# Required env (same as eoe.sh):
#   ANVIL_URL, ANVIL_ADMIN_TOKEN
set -euo pipefail

POLL=${1:-30}
ANVIL_URL=${ANVIL_URL:?ANVIL_URL not set}
ANVIL_ADMIN_TOKEN=${ANVIL_ADMIN_TOKEN:?ANVIL_ADMIN_TOKEN not set}
TAG="rehearsal-check"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $TAG $*"; }

arena_state() {
    # returns JSON array of {id, slug, status} for game-type challenges
    curl -fsS --max-time 15 \
        -H "Authorization: Bearer $ANVIL_ADMIN_TOKEN" \
        "${ANVIL_URL}/api/v1/admin/challenges" 2>/dev/null \
        | python3 -c "
import sys, json
cs = json.load(sys.stdin).get('challenges', [])
hills = [{'id': c['id'], 'slug': c['slug'], 'status': c.get('arena_status', 'unknown')}
         for c in cs if c.get('category') in ('hardware', 'blockchain', 'koth')]
print(json.dumps(hills, indent=2))
" 2>/dev/null || echo "[]"
}

log "starting rehearsal check (poll every ${POLL}s); ctrl-c to stop"
log "watching for hill open/close transitions..."

declare -A LAST_STATUS

while true; do
    HILLS=$(arena_state)
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    while IFS= read -r line; do
        SLUG=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['slug'])" 2>/dev/null || continue)
        STATUS=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'])" 2>/dev/null || continue)
        PREV=${LAST_STATUS[$SLUG]:-}
        if [[ "$STATUS" != "$PREV" ]]; then
            log "TRANSITION $SLUG: ${PREV:-unknown} -> $STATUS"
            LAST_STATUS[$SLUG]=$STATUS
        fi
    done < <(echo "$HILLS" | python3 -c "import sys,json; [print(json.dumps(h)) for h in json.load(sys.stdin)]" 2>/dev/null || true)

    sleep "$POLL"
done
