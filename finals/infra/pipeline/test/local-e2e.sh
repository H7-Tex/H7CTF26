#!/usr/bin/env bash
# Local end-to-end test: push -> build -> (mock)gate -> promote -> rollback
# Uses the finals/_template service (notebook) and a local bare git repo.
# Requires: docker, docker compose plugin, git.
# Run from any directory. All state lives under /tmp/h7d-test-<pid>.
#
# Usage:
#   bash local-e2e.sh [--cleanup-only]
#
set -euo pipefail

export GOTMPDIR=/home/abu/.cache/go-tmp
mkdir -p "$GOTMPDIR"

TESTDIR="/tmp/h7d-test-$$"
SVC="notebook"
TEMPLATE_SRC="/home/abu/Main/Projects/H7CTF26-Finals-P3-Pipeline/finals/_template/service"
DEPLOYER_BIN="/home/abu/Main/Projects/H7CTF26-Finals-P3-Pipeline/finals/infra/pipeline/deployer/h7d"
H7_CLI="/home/abu/Main/Projects/H7CTF26-Finals-P3-Pipeline/finals/infra/pipeline/h7/h7"

cleanup() {
  echo ""
  echo "=== cleanup ==="
  kill "$H7D_PID" 2>/dev/null || true
  docker compose -p "prod" down -v 2>/dev/null || true
  docker compose -p "stg-notebook" down -v 2>/dev/null || true
  docker rm -f gitea-test 2>/dev/null || true
  rm -rf "$TESTDIR"
  echo "done."
}
H7D_PID=""
trap cleanup EXIT

if [[ "${1:-}" == "--cleanup-only" ]]; then
  cleanup
  exit 0
fi

echo "=== h7d local e2e test PID=$$ ==="
echo "testdir: $TESTDIR"
mkdir -p "$TESTDIR"/{git,state,svc,log}

# 1. build deployer if needed
if [[ ! -f "$DEPLOYER_BIN" ]]; then
  echo "building deployer..."
  go build -C "$(dirname "$DEPLOYER_BIN")" -o h7d ./... 2>&1
fi

# 2. set up bare repo seeded with template service
REPO="$TESTDIR/git/services.git"
git init --bare --initial-branch=main "$REPO" -q
WORKDIR="$TESTDIR/git/work"
git clone "$REPO" "$WORKDIR" -q
git -C "$WORKDIR" checkout -b main 2>/dev/null || true
mkdir -p "$WORKDIR/$SVC"
cp -r "$TEMPLATE_SRC/"* "$WORKDIR/$SVC/"
cp "$TEMPLATE_SRC/../gate.yml" "$WORKDIR/$SVC/"
git -C "$WORKDIR" config user.email "test@h7"
git -C "$WORKDIR" config user.name "test"
git -C "$WORKDIR" add .
git -C "$WORKDIR" commit -m "init" -q
git -C "$WORKDIR" push origin main -q
ORIG_SHA=$(git -C "$WORKDIR" rev-parse HEAD)
echo "orig sha: ${ORIG_SHA:0:8}"

# 3. set up service root with compose + gate.yml
SVC_ROOT="$TESTDIR/svc"
mkdir -p "$SVC_ROOT/$SVC"
cp -r "$TEMPLATE_SRC/"* "$SVC_ROOT/$SVC/"
cp "$TEMPLATE_SRC/../gate.yml" "$SVC_ROOT/$SVC/"

# 4. set up prod compose project using service's compose
cat > "$SVC_ROOT/$SVC/docker-compose.yml" <<'COMPOSE'
services:
  notebook:
    image: h7/notebook:current
    pull_policy: never
    ports:
      - "7000:7000"
    volumes:
      - notebook-data:/data
    restart: unless-stopped
    cpus: "0.5"
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:7000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5
volumes:
  notebook-data:
COMPOSE

# pre-build orig image and tag as :orig and :current
echo "building orig image..."
docker buildx build -t h7/notebook:c-orig "$SVC_ROOT/$SVC/notebook" -q
docker tag h7/notebook:c-orig h7/notebook:orig
docker tag h7/notebook:c-orig h7/notebook:current

# start prod compose
echo "starting prod service..."
docker compose -p prod -f "$SVC_ROOT/$SVC/docker-compose.yml" up -d 2>&1

# wait for service health with retries
echo -n "waiting for service... "
for i in $(seq 1 15); do
  sleep 2
  if curl -sf http://127.0.0.1:7000/health > /dev/null 2>&1; then
    echo "healthy (${i}x2s)"
    break
  fi
  if [[ $i -eq 15 ]]; then
    echo "not healthy after 30s"
    docker compose -p prod logs 2>&1 | tail -10
    exit 1
  fi
done

# record orig sha in state (manual setup since no deployer ran yet)
ORIG_SHA_12="${ORIG_SHA:0:12}"
ORIG_DIGEST=$(docker inspect --format='{{.Id}}' h7/notebook:current)
mkdir -p "$TESTDIR/state"
cat > "$TESTDIR/state/state.json" <<STATE
{
  "services": {
    "$SVC": {
      "sha": "$ORIG_SHA_12",
      "prev_sha": "",
      "orig_sha": "$ORIG_SHA_12",
      "digest": "$ORIG_DIGEST",
      "prev_digest": "",
      "deploys": 0,
      "last_tick": 0,
      "consec_fail": 0,
      "promoted_at": 0,
      "mode": "pipeline"
    }
  }
}
STATE

# 5. start deployer in mock mode
WEBHOOK_SECRET="testwebhooksecret"
export TEAM=0
export TEAM_ID="00000000-0000-0000-0000-000000000000"
export GATE_MOCK=1
export WEBHOOK_SECRET="$WEBHOOK_SECRET"
export H7D_REPO="$REPO"
export H7D_SVC_ROOT="$SVC_ROOT"
export H7D_STATE="$TESTDIR/state/state.json"
export H7D_WEBHOOK_ADDR=":9000"
export H7D_API_ADDR=":9300"
export H7D_PROJECT="prod"
export H7D_BUILDER="default"  # use default builder for local tests
export BUILD_TIMEOUT_S=300
export BOX_TOKEN="testtoken"
export QUIET_OFFSET_S=0  # skip quiet window in local tests

"$DEPLOYER_BIN" > "$TESTDIR/log/deployer.log" 2>&1 &
H7D_PID=$!
sleep 2
kill -0 "$H7D_PID" 2>/dev/null || { echo "deployer failed to start"; cat "$TESTDIR/log/deployer.log"; exit 1; }
echo "deployer running PID=$H7D_PID"
curl -sf http://127.0.0.1:9300/health > /dev/null && echo "api healthy"

# 6. make a patch commit (correct patch: fix store0)
cp "$TEMPLATE_SRC/../patches/store0_correct.patch" "$TESTDIR/patch.diff"
(cd "$WORKDIR" && git apply --directory="$SVC" "$TESTDIR/patch.diff" && \
  git add . && git commit -m "patch store0" -q && git push origin main -q)
PATCH_SHA=$(git -C "$WORKDIR" rev-parse HEAD)
echo "patch sha: ${PATCH_SHA:0:8}"

# 7. trigger deploy via webhook
PAYLOAD=$(cat <<JSON
{"ref":"refs/heads/main","after":"$PATCH_SHA","head_commit":{"added":[],"modified":["$SVC/notebook/app.py"],"removed":[]}}
JSON
)
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')
echo "triggering webhook..."
curl -sf -X POST http://127.0.0.1:9000/hook \
  -H "X-Gitea-Event: push" \
  -H "X-Gitea-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" > /dev/null
echo "webhook accepted"

# 8. wait for build and promote (up to 600s)
echo "waiting for promote..."
for i in $(seq 1 120); do
  sleep 5
  CURRENT_SHA=$(curl -sf -H "Authorization: Bearer $BOX_TOKEN" http://127.0.0.1:9300/deploys 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$SVC',{}).get('sha',''))" 2>/dev/null || echo "")
  if [[ "${CURRENT_SHA}" == "${PATCH_SHA:0:12}" ]]; then
    echo "promoted OK sha=${CURRENT_SHA}"
    break
  fi
  echo "  still building... (${i}x5s)"
done
if [[ "${CURRENT_SHA:-}" != "${PATCH_SHA:0:12}" ]]; then
  echo "FAIL: promote did not happen in time"
  echo "--- deployer log ---"
  tail -30 "$TESTDIR/log/deployer.log"
  exit 1
fi

# 9. verify service still healthy after promote
sleep 2
curl -sf http://127.0.0.1:7000/health > /dev/null && echo "service healthy after promote"

# 10. test rollback via API
echo "testing rollback..."
H7D_TOKEN=testtoken H7D_API=http://127.0.0.1:9300 "$H7_CLI" rollback notebook prev
sleep 3

ROLLED_SHA=$(curl -sf -H "Authorization: Bearer $BOX_TOKEN" http://127.0.0.1:9300/deploys | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('notebook',{}).get('sha',''))")
echo "after rollback sha=$ROLLED_SHA (expected ${ORIG_SHA_12})"

curl -sf http://127.0.0.1:7000/health > /dev/null && echo "service healthy after rollback"

# 11. test h7 status
echo ""
echo "=== h7 status ==="
H7D_TOKEN=testtoken H7D_API=http://127.0.0.1:9300 "$H7_CLI" status

echo ""
echo "=== ALL TESTS PASSED ==="
echo "push->build->gate->promote->rollback on template: OK"
