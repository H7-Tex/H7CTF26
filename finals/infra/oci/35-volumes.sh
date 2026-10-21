#!/usr/bin/env bash
# 35-volumes.sh - create and attach data block volumes
# run after 30-infra.sh, before 60-fleet.sh
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[[ -n $C ]] || { echo "H7F_COMPARTMENT_ID not set"; exit 1; }

make_vol() {
  local name=$1 size_gb=$2
  local id; id=$(inv_get "vol.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci bv volume create \
    --compartment-id "$C" --availability-domain "$AD" \
    --display-name "$name" --size-in-gbs "$size_gb" \
    --vpus-per-gb 10 \
    --wait-for-state AVAILABLE | q_data '.id')
  inv_set "vol.$name" "$id"
  echo "$id"
}

attach_vol() {
  local instance_id=$1 vol_id=$2 name=$3
  local id; id=$(inv_get "volattach.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci compute volume-attachment attach \
    --instance-id "$instance_id" \
    --type paravirtualized \
    --volume-id "$vol_id" \
    --display-name "$name" \
    --is-shareable false \
    --wait-for-state ATTACHED | q_data '.id')
  inv_set "volattach.$name" "$id"
  echo "$id"
}

R1=$(inv_get vm.r1)
GITEA_VM=$(inv_get vm.gitea)
MIRROR_VM=$(inv_get vm.mirror)

# r1: 500 GB for rolling pcap ring (tcpdump -G 60 -W 480 = 8 h per team slot)
PCAP_VOL=$(make_vol h7f-pcap 500)
attach_vol "$R1" "$PCAP_VOL" pcap-r1
echo "pcap volume attached to r1: $PCAP_VOL"

# Gitea: 100 GB for bare repos (16 teams × ~5 services × revisions)
GITEA_VOL=$(make_vol h7f-gitea-data 100)
attach_vol "$GITEA_VM" "$GITEA_VOL" gitea-data
echo "gitea data volume attached: $GITEA_VOL"

# mirror: 300 GB for apt/docker/pip/npm caches + archive registry
MIRROR_VOL=$(make_vol h7f-mirror-cache 300)
attach_vol "$MIRROR_VM" "$MIRROR_VOL" mirror-cache
echo "mirror cache volume attached: $MIRROR_VOL"

echo "done. volumes provisioned; mount on boot via /etc/fstab UUID entries (cloud-init handles this)."
