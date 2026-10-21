#!/usr/bin/env bash
# 60-fleet.sh - launch 16 prod + 15 workbench VMs in parallel
# run AFTER 30-infra.sh and AFTER golden images are built (35-volumes.sh must run first).
# requires IMG_PROD and IMG_WB set in env.sh or exported.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

is_ocid() { [[ $1 =~ ^ocid1\.image\.oc1\. ]]; }
[[ -n ${IMG_PROD:-} ]] || { echo "IMG_PROD not set (run images/build-prod.sh first, then export H7F_IMG_PROD=...)"; exit 1; }
[[ -n ${IMG_WB:-} ]]   || { echo "IMG_WB not set (run images/build-wb.sh first, then export H7F_IMG_WB=...)";   exit 1; }
is_ocid "$IMG_PROD" || { echo "IMG_PROD does not look like an OCI image OCID: $IMG_PROD"; exit 1; }
is_ocid "$IMG_WB"   || { echo "IMG_WB does not look like an OCI image OCID: $IMG_WB";   exit 1; }

NSG_GAME=$(inv_get nsg.nsg-game)

# max parallel launches; OCI rate-limits instance.launch to ~30 req/min
MAX_JOBS=12

launch_prod() {
  local t=$1 tt; tt=$(printf %02d "$t")
  local sn; sn=$(inv_get "subnet.p$tt")
  # primary IP .2, staging secondary IP .3 (Finals-3 requirement for checker-gated staging)
  local id; id=$(launch "prod-$tt" "$sn" "10.60.$t.2" 2 12 "$IMG_PROD" "$NSG_GAME" \
    "$(dirname "$0")/cloud-init/prod.yaml")
  # assign staging secondary IP
  local vnic; vnic=$(oci compute vnic-attachment list \
    --compartment-id "$C" --instance-id "$id" | q_data '.[0]."vnic-id"')
  oci network vnic assign-private-ip --vnic-id "$vnic" \
    --ip-address "10.60.$t.3" --display-name "prod-$tt-stg" 2>/dev/null || true
  inv_set "vnic.prod-$tt" "$vnic"
  echo "prod-$tt: $id (.2 primary, .3 staging)"
}

launch_wb() {
  local t=$1 tt; tt=$(printf %02d "$t")
  local sn; sn=$(inv_get "subnet.w$tt")
  # 9th arg = 100 GB boot (workbenches don't need 150 GB; saves ~$7 storage over 5 days)
  launch "wb-$tt" "$sn" "10.61.$t.2" 2 16 "$IMG_WB" "$NSG_GAME" \
    "$(dirname "$0")/cloud-init/wb.yaml" 100
  echo "wb-$tt: done"
}

# export for subshells
export -f launch_prod launch_wb launch
export C AD IMG_PROD IMG_WB NSG_GAME INVENTORY SCRIPT_DIR
export -f inv_get inv_set q q_data oci

echo "launching 16 prod + 15 workbench VMs (max $MAX_JOBS parallel)..."
(
  for t in $(seq 1 "$((N+1))"); do  # N=15 teams + NOP(16)
    (launch_prod "$t") &
    (( $(jobs -r | wc -l) >= MAX_JOBS )) && wait -n
  done
  for t in $(seq 1 "$N"); do
    (launch_wb "$t") &
    (( $(jobs -r | wc -l) >= MAX_JOBS )) && wait -n
  done
  wait
)
echo "all fleet VMs launched."
echo "run 70-gitea-seed.sh next to create repos, deploy keys, webhooks."
