#!/usr/bin/env bash
# 20-router.sh - launch r1, r2, assign floating IP, reserved public IP, update route tables
set -euo pipefail
source "$(dirname "$0")/lib.sh"

EDGE=$(inv_get subnet.edge)
NSG_ROUTER=$(inv_get nsg.nsg-router)

# --- r1: primary router ---
R1=$(oci compute instance launch \
  --compartment-id "$C" --availability-domain "$AD" \
  --shape VM.Standard.E4.Flex --shape-config '{"ocpus":4,"memoryInGBs":16}' \
  --subnet-id "$EDGE" --private-ip 10.60.250.10 \
  --assign-public-ip true --skip-source-dest-check true \
  --nsg-ids "[\"$NSG_ROUTER\"]" \
  --image-id "$IMG_UBUNTU" --boot-volume-size-in-gbs 50 \
  --display-name r1 --hostname-label r1 \
  --user-data-file "$(dirname "$0")/cloud-init/router.yaml" \
  --ssh-authorized-keys-file "$(dirname "$0")/keys/orga.pub" \
  --instance-options '{"areLegacyImdsEndpointsDisabled":true}' \
  --wait-for-state RUNNING | q_data '.id') 2>/dev/null || R1=$(inv_get vm.r1)
inv_set vm.r1 "$R1"
echo "r1: $R1"

# attach the 500 GB pcap block volume (created separately)
# oci compute volume-attachment attach --instance-id "$R1" --type paravirtualized --volume-id "$PCAP_VOL"

# --- r2: standby (same WireGuard key, 2 OCPU, no capture units) ---
R2=$(oci compute instance launch \
  --compartment-id "$C" --availability-domain "$AD" \
  --shape VM.Standard.E4.Flex --shape-config '{"ocpus":2,"memoryInGBs":16}' \
  --subnet-id "$EDGE" --private-ip 10.60.250.11 \
  --assign-public-ip true --skip-source-dest-check true \
  --nsg-ids "[\"$NSG_ROUTER\"]" \
  --image-id "$IMG_UBUNTU" --boot-volume-size-in-gbs 50 \
  --display-name r2 --hostname-label r2 \
  --user-data-file "$(dirname "$0")/cloud-init/router.yaml" \
  --ssh-authorized-keys-file "$(dirname "$0")/keys/orga.pub" \
  --instance-options '{"areLegacyImdsEndpointsDisabled":true}' \
  --wait-for-state RUNNING | q_data '.id') 2>/dev/null || R2=$(inv_get vm.r2)
inv_set vm.r2 "$R2"
echo "r2: $R2"

# --- floating secondary IP on r1's VNIC ---
R1_VNIC=$(oci compute vnic-attachment list \
  --compartment-id "$C" --instance-id "$R1" | q_data '.[0]."vnic-id"')
inv_set vnic.r1 "$R1_VNIC"

R2_VNIC=$(oci compute vnic-attachment list \
  --compartment-id "$C" --instance-id "$R2" | q_data '.[0]."vnic-id"')
inv_set vnic.r2 "$R2_VNIC"

# assign floating IP 10.60.250.100 to r1
oci network vnic assign-private-ip \
  --vnic-id "$R1_VNIC" --ip-address 10.60.250.100 --display-name h7f-float 2>/dev/null || true

FLOAT=$(oci network private-ip list \
  --subnet-id "$(inv_get subnet.edge)" --ip-address 10.60.250.100 | q_data '.[0].id')
inv_set float "$FLOAT"

# --- reserved public IP on the floating secondary ---
PUB=$(oci network public-ip create \
  --compartment-id "$C" --lifetime RESERVED \
  --private-ip-id "$FLOAT" --display-name h7f-wg \
  --wait-for-state ASSIGNED | q_data '."ip-address"') 2>/dev/null || \
PUB=$(oci network public-ip list \
  --compartment-id "$C" --lifetime RESERVED \
  --scope REGION | q_data '.[] | select(."display-name"=="h7f-wg") | ."ip-address"')
inv_set public-ip "$PUB"
echo "reserved public IP: $PUB  (give this to SRMIST IT and the hall gateway)"

# --- point all route tables at the floating IP ---
FLOAT_ID=$(inv_get float)
GAME_RULE="[{\"destination\":\"10.60.0.0/15\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$FLOAT_ID\"}]"
NAT_ID=$(inv_get nat)
SVC_RULE="[{\"destination\":\"10.60.0.0/15\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$FLOAT_ID\"},{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$NAT_ID\"}]"
MIRROR_RULE="$SVC_RULE"  # mirror also gets NAT during warm-up; dropped at T-0 by ops/teardown-nat.sh

for rt_key in rt.rt-game rt.rt-core; do
  oci network route-table update --rt-id "$(inv_get $rt_key)" --force --route-rules "$GAME_RULE"
done
for rt_key in rt.rt-svc; do
  oci network route-table update --rt-id "$(inv_get $rt_key)" --force --route-rules "$SVC_RULE"
done
for rt_key in rt.rt-mirror; do
  oci network route-table update --rt-id "$(inv_get $rt_key)" --force --route-rules "$MIRROR_RULE"
done

echo "route tables updated. configure r1 OS next (deploy cloud-init/router-provision.sh over SSH)."
echo "done."
