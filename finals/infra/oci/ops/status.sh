#!/usr/bin/env bash
# ops/status.sh - quick event health check: instance states, deployer heartbeats, reset API
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

N=${H7F_N:-15}
TOKEN=$(inv_get reset-token)
OPS=10.60.200.5

echo "=== infra VMs ==="
for name in r1 r2 ops anvil checker gitea mirror hill-gw hill-ht; do
  id=$(inv_get "vm.$name")
  [[ -z $id ]] && { echo "$name: not in inventory"; continue; }
  state=$(oci compute instance get --instance-id "$id" | q_data '."lifecycle-state"' 2>/dev/null || echo "ERR")
  echo "$name: $state"
done

echo ""
echo "=== prod VMs ==="
for t in $(seq 1 "$((N+1))"); do
  tt=$(printf %02d "$t")
  id=$(inv_get "vm.prod-$tt")
  [[ -z $id ]] && continue
  state=$(oci compute instance get --instance-id "$id" | q_data '."lifecycle-state"' 2>/dev/null || echo "ERR")
  deployer="?"
  curl -fsS --max-time 3 "http://10.60.$t.2:9000/health" &>/dev/null && deployer="UP" || deployer="DOWN"
  printf "prod-%s: %-10s deployer=%s\n" "$tt" "$state" "$deployer"
done

echo ""
echo "=== reset API ==="
curl -fsS --max-time 5 -H "Authorization: Bearer $TOKEN" \
  "http://$OPS:8090/status" 2>/dev/null | jq -c 'to_entries[] | "\(.key): \(.value.phase)"' || \
  echo "reset API unreachable"

echo ""
echo "=== WireGuard peers (active in last 3 min) ==="
ssh -i "${H7F_SSH_KEY:-~/.ssh/h7f-orga}" -o StrictHostKeyChecking=no \
  "ubuntu@$(inv_get ip.r1)" \
  "sudo wg show wg0 | awk '/peer/{p=\$2} /latest handshake/{s=\$0} /transfer/{printf p\" \"s\" \"\$0\"\n\"}'" \
  2>/dev/null || echo "cannot reach r1"
