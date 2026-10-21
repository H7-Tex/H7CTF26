#!/usr/bin/env bash
# 30-infra.sh - ops, Anvil, checker runner, Gitea, mirror, hills VMs
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[[ -n $C ]] || { echo "H7F_COMPARTMENT_ID not set"; exit 1; }

NSG_INFRA=$(inv_get nsg.nsg-infra)
NSG_GAME=$(inv_get nsg.nsg-game)

# --- ops VM (A1, reset API, automation) ---
launch_a1 ops \
  "$(inv_get subnet.svc)" 10.60.200.5 \
  2 8 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/cloud-init/ops.yaml"

# --- Anvil + DB (finals.h7tex.com) ---
launch anvil \
  "$(inv_get subnet.svc)" 10.60.200.10 \
  4 16 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/cloud-init/anvil.yaml"

# --- checker runner (8/32: runs tick scripts, Outbreak wave, gate pool concurrently) ---
launch checker \
  "$(inv_get subnet.core)" 10.60.201.20 \
  8 32 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/cloud-init/checker.yaml"

# --- Gitea (A1) ---
launch_a1 gitea \
  "$(inv_get subnet.core)" 10.60.201.30 \
  2 8 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/cloud-init/gitea.yaml"

# --- offline mirror + archive registry + DNS sink (A1) ---
launch_a1 mirror \
  "$(inv_get subnet.mirror)" 10.60.202.10 \
  4 16 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/cloud-init/mirror.yaml"

# --- KotH hill VMs: each hill is a dedicated VM; never co-hosted ---
# hill-gw: GridWatch II (.2), hill-ht: Hostile Takeover II (.3), hill-hc: Harbor Master (.4)
# Hills have NSG_GAME rules: reachable from 10.60.0.0/15; router gates team-only access.
launch hill-gw \
  "$(inv_get subnet.hills)" 10.60.210.2 \
  2 16 "$IMG_UBUNTU" "$NSG_GAME" \
  "$(dirname "$0")/cloud-init/hill.yaml"

launch hill-ht \
  "$(inv_get subnet.hills)" 10.60.210.3 \
  2 16 "$IMG_UBUNTU" "$NSG_GAME" \
  "$(dirname "$0")/cloud-init/hill.yaml"

launch hill-hc \
  "$(inv_get subnet.hills)" 10.60.210.4 \
  2 16 "$IMG_UBUNTU" "$NSG_GAME" \
  "$(dirname "$0")/cloud-init/hill.yaml"

echo "infrastructure VMs launched."
echo "attach data volumes next (see 35-volumes.sh), then 40-dns.sh."
