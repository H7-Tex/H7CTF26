#!/usr/bin/env bash
# seed-deployer.sh - resolve TEAM_IDs from Anvil and restart deployer containers.
# run after seed.sh has created game teams.
set -euo pipefail

API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
TOKEN=rehearsal-internal-token
PROJECT=${COMPOSE_PROJECT:-rehearsal}

log() { echo "$(date -u +%T) seed-deployer $*"; }

# fetch team list
TEAMS=$(curl -fsS "$API/internal/arena/teams" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "[]")

get_team_id() {
    echo "$TEAMS" | python3 -c "
import sys,json
teams = json.load(sys.stdin)
for t in teams:
    if str(t.get('team_number','')) == '$1':
        print(t.get('id','')); break
" 2>/dev/null || echo ""
}

for N in 1 2 3 4 5; do
    UUID=$(get_team_id "$N")
    if [ -z "$UUID" ]; then
        log "warn: could not resolve team_id for team $N (check /internal/arena/teams)"
        continue
    fi
    log "team$N uuid=$UUID"
    docker compose -p "$PROJECT" exec "h7d-$N" \
        /bin/sh -c "kill -HUP 1 || true" 2>/dev/null || true
    # set env and restart
    docker compose -p "$PROJECT" \
        -f docker-compose.yml -f compose-deployer.yml \
        up -d --no-deps --force-recreate \
        --env "TEAM_ID_$N=$UUID" "h7d-$N" 2>/dev/null || \
    log "restart h7d-$N manually: docker compose ... up -d --no-deps h7d-$N with TEAM_ID=$UUID"
done

log "done. deploy-event reporting now uses real team UUIDs."
