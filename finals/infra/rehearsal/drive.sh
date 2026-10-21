#!/usr/bin/env bash
# drive.sh — run 22 game ticks of activity in the local rehearsal.
#
# teams 1+2: attack via TCP   | team 3: attack via PUT /arena/flags
# team 4: patched (store0 fixed; exploits for store0 should fail)
# team 5: stopped for ticks 8-9 (2 ticks down, then recovers)
# advisory_at is 3 min from seed time, so outbreak fires naturally.
set -euo pipefail

API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
GS=${ANVIL_GS:-127.0.0.1:4141}
TICK_INTERVAL=${TICK_INTERVAL:-32}  # poll slightly longer than 30s tick
TICKS=${TICKS:-22}
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "$(date -u +%T) drive $*"; }

wait_tick() {
    # waits until a new tick number appears
    local prev=$1 cur
    for _ in $(seq 1 40); do
        cur=$(curl -fsS "$API/arena/tick" 2>/dev/null \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('tick',0))" 2>/dev/null || echo 0)
        if [[ "$cur" -gt "$prev" ]]; then echo "$cur"; return 0; fi
        sleep 2
    done
    echo "$prev"
}

current_tick() {
    curl -fsS "$API/arena/tick" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('tick',0))" 2>/dev/null || echo 0
}

log "starting $TICKS tick drive (tick_interval ~30s)"

TICK=$(current_tick)
DOWN_DONE=0

for i in $(seq 1 $TICKS); do
    log "tick $i/$TICKS (engine tick=$TICK)..."

    # stop team5 for ticks 8-9
    if [[ "$i" -eq 8 && "$DOWN_DONE" -eq 0 ]]; then
        log "stopping team5 for 2 ticks..."
        docker compose -f "$DIR/docker-compose.yml" stop notebook-team5 >/dev/null 2>&1 || true
    fi
    if [[ "$i" -eq 10 && "$DOWN_DONE" -eq 0 ]]; then
        log "restarting team5..."
        docker compose -f "$DIR/docker-compose.yml" start notebook-team5 >/dev/null 2>&1 || true
        DOWN_DONE=1
    fi

    # attacker team1: TCP submit
    python3 "$DIR/farm.py" "$API" "$GS" "token-team1" "172.30.0.11" --tcp 2>/dev/null \
        | sed 's/^/  [team1-tcp] /' || true

    # attacker team2: TCP submit
    python3 "$DIR/farm.py" "$API" "$GS" "token-team2" "172.30.0.12" --tcp 2>/dev/null \
        | sed 's/^/  [team2-tcp] /' || true

    # attacker team3: PUT /arena/flags
    python3 "$DIR/farm.py" "$API" "$GS" "token-team3" "172.30.0.13" 2>/dev/null \
        | sed 's/^/  [team3-put] /' || true

    # wait for next tick
    NEW_TICK=$(wait_tick "$TICK")
    TICK=$NEW_TICK
done

log "drive complete after $TICKS ticks"
