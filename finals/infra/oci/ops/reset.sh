#!/usr/bin/env bash
# ops/reset.sh - trigger prod box reset via the reset API
# usage: reset.sh <team_number>
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

T=${1:?usage: reset.sh TEAM_NUMBER}
OPS_IP=10.60.200.5
API_PORT=8090
TOKEN=$(inv_get reset-token)

echo "resetting prod-$(printf %02d "$T") (10.60.${T}.2)..."
echo "this will stop the instance, replace boot volume, restart, and wait for deployer heartbeat."
echo "estimated time: 4-8 minutes."

resp=$(curl -fsS \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://$OPS_IP:$API_PORT/reset/$T")
echo "$resp" | jq .

phase=$(echo "$resp" | jq -r '.phase // "error"')
if [[ $phase == "ready" ]]; then
  elapsed=$(echo "$resp" | jq -r '.elapsed // "?"')
  echo "reset complete in ${elapsed}s. prod-$(printf %02d "$T") is ready."
else
  echo "ERROR: reset ended in phase=$phase"
  exit 1
fi
