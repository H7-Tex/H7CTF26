#!/usr/bin/env bash
# h7ctf'26 finals - shared helpers
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# oci wrapper: always use instance_principal
oci() { command oci --auth instance_principal "$@"; }

q()       { jq -r "$1"; }
q_data()  { jq -r ".data$1"; }

inv_set() {
  local k=$1 v=$2
  ( flock 9
    tmp=$(mktemp /home/abu/.cache/inv-XXXXXX.json)
    jq --arg k "$k" --arg v "$v" '.[$k]=$v' "$INVENTORY" > "$tmp" && mv "$tmp" "$INVENTORY"
  ) 9>"${INVENTORY}.lock"
}
inv_get() { jq -r --arg k "$1" '.[$k] // empty' "$INVENTORY"; }

# get or create a subnet
subnet() {
  local name=$1 cidr=$2 rt_id=$3 public=${4:-false}
  local id; id=$(inv_get "subnet.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci network subnet create \
        --compartment-id "$C" --vcn-id "$(inv_get vcn)" \
        --cidr-block "$cidr" --display-name "$name" --dns-label "${name//-/}" \
        --route-table-id "$rt_id" \
        --security-list-ids "[\"$(inv_get sl-empty)\"]" \
        --prohibit-public-ip-on-vnic "$([[ $public == true ]] && echo false || echo true)" \
        --wait-for-state AVAILABLE | q_data '.id')
  inv_set "subnet.$name" "$id"
  echo "$id"
}

# launch a VM; idempotent on name. optional 9th arg overrides boot volume size (default 150 GB).
launch() {
  local name=$1 subnet_id=$2 ip=$3 ocpus=$4 mem=$5 image=$6 nsg_id=$7 userdata=$8 bootsz=${9:-150}
  shift 9
  local id; id=$(inv_get "vm.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci compute instance launch \
        --compartment-id "$C" --availability-domain "$AD" \
        --shape VM.Standard.E4.Flex \
        --shape-config "{\"ocpus\":$ocpus,\"memoryInGBs\":$mem}" \
        --subnet-id "$subnet_id" --private-ip "$ip" \
        --assign-public-ip false --nsg-ids "[\"$nsg_id\"]" \
        --image-id "$image" --boot-volume-size-in-gbs "$bootsz" \
        --display-name "$name" --hostname-label "$name" \
        --user-data-file "$userdata" \
        --ssh-authorized-keys-file "$SCRIPT_DIR/keys/orga.pub" \
        --instance-options '{"areLegacyImdsEndpointsDisabled":true}' \
        "$@" \
        --wait-for-state RUNNING | q_data '.id')
  inv_set "vm.$name" "$id"
  echo "$id"
}

# like launch but for A1 (ARM) instances
launch_a1() {
  local name=$1 subnet_id=$2 ip=$3 ocpus=$4 mem=$5 image=$6 nsg_id=$7 userdata=$8
  shift 8
  local id; id=$(inv_get "vm.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci compute instance launch \
        --compartment-id "$C" --availability-domain "$AD" \
        --shape VM.Standard.A1.Flex \
        --shape-config "{\"ocpus\":$ocpus,\"memoryInGBs\":$mem}" \
        --subnet-id "$subnet_id" --private-ip "$ip" \
        --assign-public-ip false --nsg-ids "[\"$nsg_id\"]" \
        --image-id "$image" --boot-volume-size-in-gbs 100 \
        --display-name "$name" --hostname-label "$name" \
        --user-data-file "$userdata" \
        --ssh-authorized-keys-file "$SCRIPT_DIR/keys/orga.pub" \
        --instance-options '{"areLegacyImdsEndpointsDisabled":true}' \
        "$@" \
        --wait-for-state RUNNING | q_data '.id')
  inv_set "vm.$name" "$id"
  echo "$id"
}
