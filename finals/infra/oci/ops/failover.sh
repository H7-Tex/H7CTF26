#!/usr/bin/env bash
# ops/failover.sh - move floating IP + reserved public IP from r1 to r2 (or back).
# [LIVE] run from ops VM. test during rehearsal before trusting it mid-event.
# the floating IP (10.60.250.100) is the route target for all game subnets AND the SNAT source.
# moving it atomically: unassign from current VNIC, assign to target VNIC.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

TARGET=${1:?usage: failover.sh r1|r2}

R1_VNIC=$(inv_get vnic.r1)
R2_VNIC=$(inv_get vnic.r2)
FLOAT_ID=$(inv_get float)
PUB_IP=$(inv_get public-ip)

case $TARGET in
  r1) TO_VNIC=$R1_VNIC; FROM_VNIC=$R2_VNIC ;;
  r2) TO_VNIC=$R2_VNIC; FROM_VNIC=$R1_VNIC ;;
  *) echo "target must be r1 or r2"; exit 1 ;;
esac

echo "==> moving float 10.60.250.100 to $TARGET..."
# get float private IP OCID
FLOAT_OBJ=$(oci network private-ip list \
  --subnet-id "$(inv_get subnet.edge)" --ip-address 10.60.250.100 | q_data '.[0]')
FLOAT_OCID=$(echo "$FLOAT_OBJ" | jq -r '.id')

# unassign from current VNIC (detach private IP)
oci network vnic unassign-private-ip \
  --vnic-id "$FROM_VNIC" \
  --ip-address 10.60.250.100 2>/dev/null || true

# assign to target VNIC
oci network vnic assign-private-ip \
  --vnic-id "$TO_VNIC" \
  --ip-address 10.60.250.100 \
  --display-name h7f-float 2>/dev/null || true

# move reserved public IP (if not already following the private IP OCID)
PUB_OCID=$(oci network public-ip list \
  --compartment-id "$C" --lifetime RESERVED --scope REGION | \
  q_data '.[] | select(."ip-address"=="'"$PUB_IP"'") | .id')
oci network public-ip update --public-ip-id "$PUB_OCID" \
  --private-ip-id "$FLOAT_OCID" 2>/dev/null || true

echo "==> updating route tables to point at new float OCID..."
# route tables should already point at FLOAT_OCID (the OCID doesn't change; only VNIC binding changes)
# if OCI re-creates the private IP on reassign, refresh FLOAT_OCID:
NEW_FLOAT=$(oci network private-ip list \
  --subnet-id "$(inv_get subnet.edge)" --ip-address 10.60.250.100 | q_data '.[0].id')
if [[ $NEW_FLOAT != "$FLOAT_OCID" ]]; then
  echo "float OCID changed: $FLOAT_OCID -> $NEW_FLOAT; updating route tables..."
  inv_set float "$NEW_FLOAT"
  GAME_RULE="[{\"destination\":\"10.60.0.0/15\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$NEW_FLOAT\"}]"
  NAT_ID=$(inv_get nat)
  SVC_RULE="[{\"destination\":\"10.60.0.0/15\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$NEW_FLOAT\"},{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$NAT_ID\"}]"
  for rt_key in rt.rt-game rt.rt-core; do
    oci network route-table update --rt-id "$(inv_get $rt_key)" --force --route-rules "$GAME_RULE"
  done
  for rt_key in rt.rt-svc rt.rt-mirror; do
    oci network route-table update --rt-id "$(inv_get $rt_key)" --force --route-rules "$SVC_RULE"
  done
fi

echo "==> starting WireGuard on $TARGET..."
TARGET_IP=$(inv_get "ip.$TARGET")
ssh -i "${H7F_SSH_KEY:-~/.ssh/h7f-orga}" -o StrictHostKeyChecking=no \
  "ubuntu@$TARGET_IP" "sudo systemctl start wg-quick@wg0" 2>/dev/null || \
  echo "WireGuard start failed - start manually on $TARGET"

echo "failover to $TARGET complete."
echo "verify with: ops/check-snat.sh (from a WireGuard client)"
