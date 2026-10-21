#!/usr/bin/env bash
# verify.sh — post-drive verification of the local rehearsal.
# prints PASS/FAIL/SKIP per check; exits non-zero if any FAIL.
set -euo pipefail

API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
DB_HOST=${ANVIL_DB_HOST:-127.0.0.1}
DB_PORT=${ANVIL_DB_PORT:-5432}
BUGS=()

PASS=0; FAIL=0; SKIP=0

pass()  { echo "  PASS  $1"; ((PASS++)); }
fail()  { echo "  FAIL  $1: $2"; BUGS+=("$1: $2"); ((FAIL++)); }
skip()  { echo "  SKIP  $1: $2"; ((SKIP++)); }

psql_exec() {
    PGPASSWORD=anvil psql -h "$DB_HOST" -p "$DB_PORT" -U anvil -d anvil -qAt -c "$1" 2>/dev/null || echo ""
}

log_admin() {
    curl -fsS -X POST "$API/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin1234!"}' \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo ""
}

admin_get() {
    local jwt=$1 path=$2
    curl -fsS "$API$path" -H "Authorization: Bearer $jwt" 2>/dev/null || echo "{}"
}

team_get() {
    local token=$1 path=$2
    curl -fsS "$API$path" -H "X-Team-Token: $token" 2>/dev/null || echo "{}"
}

echo ""
echo "=== rehearsal verification ==="
echo ""

JWT=$(log_admin)
if [[ -z "$JWT" ]]; then
    echo "FATAL: cannot log in as admin"
    exit 1
fi

# ------------------------------------------------------------------
# 1. scoreboard has non-zero STEAL/HOLD/UP
# ------------------------------------------------------------------
echo "1. scoreboard STEAL/HOLD/UP"
BOARD=$(admin_get "$JWT" /arena/scoreboard 2>/dev/null || echo "{}")
HAS_STEAL=$(echo "$BOARD" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    total_steal = sum(t.get('ad',{}).get('steal',0) or 0 for t in d.get('teams',[]))
    total_hold  = sum(t.get('ad',{}).get('hold',0) or 0 for t in d.get('teams',[]))
    total_up    = sum(t.get('ad',{}).get('sla',0) or 0 for t in d.get('teams',[]))
    print(f'{total_steal} {total_hold} {total_up}')
except: print('0 0 0')
" 2>/dev/null || echo "0 0 0")
read -r STEAL HOLD UP <<< "$HAS_STEAL"
if [[ "$STEAL" -gt 0 && "$UP" -gt 0 ]]; then
    pass "scoreboard non-zero (steal=$STEAL hold=$HOLD up=$UP)"
else
    fail "scoreboard" "steal=$STEAL hold=$HOLD up=$UP (all zero)"
fi

# 1b. patched team (team4) has non-zero hold for store0
echo "1b. team4 holds store0 (patch effective)"
T4_HOLD=$(echo "$BOARD" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for t in d.get('teams',[]):
        if t.get('name','').lower().startswith('team 4'):
            print(t.get('ad',{}).get('hold',0))
            sys.exit(0)
    print(0)
except: print(0)
" 2>/dev/null || echo 0)
if [[ "$T4_HOLD" -gt 0 ]]; then
    pass "team4 hold=$T4_HOLD (patch is holding flags)"
else
    fail "team4 patch" "hold=0 for team4; patch may not be effective or not enough ticks"
fi

# ------------------------------------------------------------------
# 2. /arena/me/status shows credited + effective statuses
# ------------------------------------------------------------------
echo "2. /arena/me/status (team1)"
ME_STATUS=$(team_get "token-team1" /arena/me/status)
HAS_STATUS=$(echo "$ME_STATUS" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    stores = d.get('stores',[]) or d.get('services',[]) or []
    print('ok' if stores else 'empty')
except: print('error')
" 2>/dev/null || echo "error")
if [[ "$HAS_STATUS" == "ok" ]]; then
    pass "/arena/me/status has stores data"
else
    fail "/arena/me/status" "response=$HAS_STATUS body=${ME_STATUS:0:200}"
fi

# ------------------------------------------------------------------
# 3. /arena/attack-info lists teams
# ------------------------------------------------------------------
echo "3. /arena/attack-info"
AI=$(curl -fsS "$API/arena/attack-info" 2>/dev/null || echo "{}")
AI_COUNT=$(echo "$AI" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d.get('available_teams',[])))
except: print(0)
" 2>/dev/null || echo 0)
if [[ "$AI_COUNT" -ge 4 ]]; then
    pass "attack-info lists $AI_COUNT teams"
else
    fail "attack-info" "only $AI_COUNT available_teams (expected >=4)"
fi

# ------------------------------------------------------------------
# 4. Outbreak advisory published + wave started after 15 ticks
# ------------------------------------------------------------------
echo "4. Outbreak advisory + wave"
ADVISORY_COUNT=$(psql_exec "SELECT COUNT(*) FROM game_events WHERE kind='advisory'")
if [[ "$ADVISORY_COUNT" -gt 0 ]]; then
    pass "advisory published ($ADVISORY_COUNT rows)"
else
    fail "outbreak advisory" "no game_events rows with kind='advisory'"
fi

BOT_READS=$(psql_exec "SELECT COUNT(*) FROM game_bot_reads")
CURRENT_TICK=$(psql_exec "SELECT COALESCE(MAX(tick_number),0) FROM game_ticks")
ADV_TICK=$(psql_exec "SELECT COALESCE(MIN(tick_number),999) FROM game_events WHERE kind='advisory'")
WAVE_EXPECTED_AT=$((ADV_TICK + 15))
if [[ "$BOT_READS" -gt 0 ]]; then
    pass "outbreak wave fired ($BOT_READS bot_reads rows)"
elif [[ "$CURRENT_TICK" -lt "$WAVE_EXPECTED_AT" ]]; then
    skip "outbreak wave" "advisory at tick $ADV_TICK, wave expected at $WAVE_EXPECTED_AT, only $CURRENT_TICK ticks run"
else
    fail "outbreak wave" "advisory at tick $ADV_TICK, $CURRENT_TICK ticks run, still 0 bot_reads"
fi

# ------------------------------------------------------------------
# 5. POST /admin/arena/extend shifts event times
#    SKIP — endpoint not yet built (Finals-3 deliverable)
# ------------------------------------------------------------------
echo "5. /admin/arena/extend"
skip "arena/extend" "endpoint not yet in codebase; Finals-3 will add it"

# ------------------------------------------------------------------
# 6. game.state=stopped settles the board
# ------------------------------------------------------------------
echo "6. game.state=stopped settles board"
PGPASSWORD=anvil psql -h "$DB_HOST" -p "$DB_PORT" -U anvil -d anvil -qAt -c \
    "INSERT INTO platform_settings (key, value) VALUES ('game.state', '\"stopped\"'::jsonb)
     ON CONFLICT (key) DO UPDATE SET value = '\"stopped\"'::jsonb" 2>/dev/null || true
sleep 5  # give gameserver one cycle to detect the stop

STATE=$(psql_exec "SELECT COALESCE(value #>> '{}','') FROM platform_settings WHERE key='game.state'")
if [[ "$STATE" == "stopped" ]]; then
    pass "game.state=stopped persisted"
else
    fail "game.state=stopped" "value=$STATE"
fi

# board should no longer advance (tick count stable)
TICK_BEFORE=$(psql_exec "SELECT COALESCE(MAX(tick_number),0) FROM game_ticks")
sleep 35
TICK_AFTER=$(psql_exec "SELECT COALESCE(MAX(tick_number),0) FROM game_ticks")
if [[ "$TICK_AFTER" -le "$TICK_BEFORE" ]]; then
    pass "tick loop stopped after game.state=stopped (before=$TICK_BEFORE after=$TICK_AFTER)"
else
    fail "tick loop stopped" "ticks advanced after stopped: before=$TICK_BEFORE after=$TICK_AFTER"
fi

# ------------------------------------------------------------------
# summary
# ------------------------------------------------------------------
echo ""
echo "=== results: PASS=$PASS FAIL=$FAIL SKIP=$SKIP ==="
if [[ ${#BUGS[@]} -gt 0 ]]; then
    echo ""
    echo "bugs to report:"
    for b in "${BUGS[@]}"; do
        echo "  - $b"
    done
fi

[[ "$FAIL" -eq 0 ]]
