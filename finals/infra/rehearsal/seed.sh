#!/usr/bin/env bash
# seed.sh — seed the local rehearsal: admin user, 6 game teams, Notebook service, settings.
# run after compose is healthy. safe to re-run (idempotent where possible).
set -euo pipefail

API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
DB_HOST=${ANVIL_DB_HOST:-127.0.0.1}
DB_PORT=${ANVIL_DB_PORT:-5432}

log() { echo "$(date -u +%T) seed $*"; }

psql_exec() {
    PGPASSWORD=anvil psql -h "$DB_HOST" -p "$DB_PORT" -U anvil -d anvil -qAt -c "$1"
}

# ------------------------------------------------------------------
# 1. wait for API
# ------------------------------------------------------------------
HEALTH_URL="$(echo "$API" | sed 's|/api/v1||')/health"
log "waiting for api ($HEALTH_URL)..."
for i in $(seq 1 60); do
    if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then break; fi
    sleep 2
done

# ------------------------------------------------------------------
# 2. bootstrap admin user (register then promote via DB)
# ------------------------------------------------------------------
log "bootstrapping admin..."
curl -fsS -X POST "$API/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","email":"admin@rehearsal.local","password":"admin1234!"}' \
    >/dev/null 2>&1 || true  # ignore conflict if already exists

psql_exec "UPDATE users SET role = 'admin' WHERE username = 'admin' AND role <> 'admin'"

# login
JWT=$(curl -fsS -X POST "$API/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin1234!"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
log "admin jwt obtained"
api() {
    local method=$1 path=$2; shift 2
    curl -fsS -X "$method" "$API$path" \
        -H "Authorization: Bearer $JWT" \
        -H "Content-Type: application/json" \
        "$@"
}

# ------------------------------------------------------------------
# 3. create game teams (6: teams 1-5 + NOP)
# ------------------------------------------------------------------
log "creating game teams..."
create_team() {
    local name=$1 ip=$2 token=$3 number=$4 nop=${5:-false}
    api POST /admin/arena/teams -d "{
      \"name\": \"$name\",
      \"vulnbox_ip\": \"$ip\",
      \"token\": \"$token\",
      \"team_number\": $number,
      \"is_nop\": $nop
    }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','already-exists'))" || true
}

T1=$(create_team "Team 1" "172.30.0.11" "token-team1" 1)
T2=$(create_team "Team 2" "172.30.0.12" "token-team2" 2)
T3=$(create_team "Team 3" "172.30.0.13" "token-team3" 3)
T4=$(create_team "Team 4" "172.30.0.14" "token-team4" 4)
T5=$(create_team "Team 5" "172.30.0.15" "token-team5" 5)
NOP=$(create_team "NOP" "172.30.0.20" "token-nop" 6 true)
log "teams: t1=$T1 t2=$T2 t3=$T3 t4=$T4 t5=$T5 nop=$NOP"

# ------------------------------------------------------------------
# 4. create Notebook service (2 stores, 1 noise, 1 havoc)
# ------------------------------------------------------------------
log "creating Notebook service..."
SVC=$(api POST /admin/arena/services -d '{
  "name": "Notebook",
  "slug": "notebook",
  "category": "web",
  "tier": "core",
  "port": 7000,
  "checker_ref": "http://172.30.0.6:8000",
  "flag_stores": 2,
  "noise_variants": 1,
  "havoc_variants": 1
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','exists'))" || true)
log "service id: $SVC"

# enable the service
api PATCH "/admin/arena/services/$SVC" -d '{"enabled": true}' >/dev/null 2>&1 || true

# set advisory_at on store 1 (fallback: fires if first blood never occurs naturally).
# advisory_at is not exposed via the API - set directly.
NOW_PLUS_3MIN=$(date -u -d '+3 minutes' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
    || date -u -v +3M '+%Y-%m-%dT%H:%M:%SZ')
psql_exec "UPDATE game_services SET advisory_at = '$NOW_PLUS_3MIN' WHERE slug = 'notebook'"

# ------------------------------------------------------------------
# 5. set platform settings (game.state=running, event times)
# ------------------------------------------------------------------
log "setting game state..."
NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
END=$(date -u -d '+12 hours' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
    || date -u -v +12H '+%Y-%m-%dT%H:%M:%SZ')

upsert_setting() {
    psql_exec "INSERT INTO platform_settings (key, value)
               VALUES ('$1', '$2'::jsonb)
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
}

upsert_setting "game.state"   '"running"'
upsert_setting "event.start_at" "\"$NOW\""
upsert_setting "event.end_at"   "\"$END\""

# enable game on the platform level too
upsert_setting "game_enabled"    'true'

log "seed complete. game.state=running, event $NOW -> $END"
log "teams:  token-team1..5, token-nop"
log "admin:  admin / admin1234!"
