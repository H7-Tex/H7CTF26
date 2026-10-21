#!/usr/bin/env bash
# burst-gate.sh - path 4: fire gate calls for all 5 teams simultaneously.
# verifies that the gate pool handles concurrent calls without dropping tasks.
# run while drive.sh is active (live checker tasks running).
set -euo pipefail

API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
TOKEN=rehearsal-internal-token
# staging addresses: use busybox notebooks at team IPs (already running)
TEAM_IPS=(172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 172.30.0.15)
PORT=7000
TIMEOUT=25

log() { echo "$(date -u +%T) burst-gate $*"; }

# fire all 5 gate calls in parallel, collect results
PIDS=()
RESULTS=()
for I in "${!TEAM_IPS[@]}"; do
    N=$((I+1))
    IP="${TEAM_IPS[$I]}"
    RESULT_FILE=$(mktemp)
    RESULTS+=("$RESULT_FILE")
    curl -fsS -X POST "$API/internal/arena/gate" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"service\":\"notebook\",\"address\":\"$IP\",\"port\":$PORT,\"rounds\":1,\"timeout_s\":$TIMEOUT}" \
        -o "$RESULT_FILE" &
    PIDS+=($!)
    log "fired gate team$N ($IP)"
done

log "waiting for $((${#PIDS[@]})) gate calls..."
FAIL=0
for I in "${!PIDS[@]}"; do
    N=$((I+1))
    if wait "${PIDS[$I]}"; then
        OK=$(python3 -c "import json,sys; d=json.load(open('${RESULTS[$I]}')); print(d.get('ok',False))" 2>/dev/null || echo "false")
        log "team$N gate ok=$OK"
    else
        log "team$N gate HTTP error"
        FAIL=$((FAIL+1))
    fi
    rm -f "${RESULTS[$I]}"
done

if [[ "$FAIL" -eq 0 ]]; then
    log "burst gate PASS: all 5 calls completed without error"
else
    log "burst gate FAIL: $FAIL calls errored"
    exit 1
fi
