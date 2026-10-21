#!/usr/bin/env bash
# 10-network.sh - VCN, gateways, route tables, NSGs, 37 subnets
# run from ops VM after 00-bootstrap.md creates the compartment.
# idempotent: existing resources are found by display-name and reused.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[[ -n $C ]] || { echo "set H7F_COMPARTMENT_ID first"; exit 1; }

# --- VCN ---
vcn_id=$(inv_get vcn)
if [[ -z $vcn_id ]]; then
  vcn_id=$(oci network vcn create \
    --compartment-id "$C" --cidr-blocks '["10.60.0.0/15"]' \
    --display-name h7f-vcn --dns-label h7f \
    --wait-for-state AVAILABLE | q_data '.id')
  inv_set vcn "$vcn_id"
fi
echo "vcn: $vcn_id"

# --- gateways ---
igw_id=$(inv_get igw)
if [[ -z $igw_id ]]; then
  igw_id=$(oci network internet-gateway create \
    --compartment-id "$C" --vcn-id "$vcn_id" --is-enabled true \
    --display-name h7f-igw --wait-for-state AVAILABLE | q_data '.id')
  inv_set igw "$igw_id"
fi

nat_id=$(inv_get nat)
if [[ -z $nat_id ]]; then
  nat_id=$(oci network nat-gateway create \
    --compartment-id "$C" --vcn-id "$vcn_id" \
    --display-name h7f-nat --wait-for-state AVAILABLE | q_data '.id')
  inv_set nat "$nat_id"
fi
echo "igw: $igw_id  nat: $nat_id"

# --- empty security list (replaces the default allow-all) ---
sl_id=$(inv_get sl-empty)
if [[ -z $sl_id ]]; then
  sl_id=$(oci network security-list create \
    --compartment-id "$C" --vcn-id "$vcn_id" \
    --display-name sl-empty --egress-security-rules '[]' --ingress-security-rules '[]' \
    --wait-for-state AVAILABLE | q_data '.id')
  inv_set sl-empty "$sl_id"
fi

# --- route tables ---
# helper: create route table with given rules json
make_rt() {
  local name=$1 rules=$2
  local id; id=$(inv_get "rt.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci network route-table create \
    --compartment-id "$C" --vcn-id "$vcn_id" \
    --display-name "$name" --route-rules "$rules" \
    --wait-for-state AVAILABLE | q_data '.id')
  inv_set "rt.$name" "$id"
  echo "$id"
}

# edge: 0/0 -> IGW (no game routes; router reaches VCN via local routing)
RT_EDGE=$(make_rt rt-edge \
  "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$igw_id\"}]")

# game: 10.60.0.0/15 -> float (updated by 20-router.sh once float IP exists)
# placeholder rule will be replaced; use a dummy route that matches nothing harmful
RT_GAME=$(make_rt rt-game '[]')

# svc: game range -> float (set by 20-router.sh) + 0/0 -> NAT
RT_SVC=$(make_rt rt-svc \
  "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$nat_id\"}]")

# core: game -> float (set later); no default route
RT_CORE=$(make_rt rt-core '[]')

# mirror: game -> float (set later) + NAT during warm-up (removed at T-0)
RT_MIRROR=$(make_rt rt-mirror \
  "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$nat_id\"}]")

echo "route tables created"

# --- NSGs ---
make_nsg() {
  local name=$1; local id; id=$(inv_get "nsg.$name")
  [[ -n $id ]] && { echo "$id"; return; }
  id=$(oci network nsg create \
    --compartment-id "$C" --vcn-id "$vcn_id" --display-name "$name" \
    --wait-for-state AVAILABLE | q_data '.id')
  inv_set "nsg.$name" "$id"
  echo "$id"
}

NSG_ROUTER=$(make_nsg nsg-router)
NSG_GAME=$(make_nsg nsg-game)
NSG_INFRA=$(make_nsg nsg-infra)

# nsg-router rules: all stateless from game range; UDP+TCP 443 from internet; SSH from atom
oci network nsg rules add --nsg-id "$NSG_ROUTER" --security-rules "[
  {\"direction\":\"INGRESS\",\"protocol\":\"all\",\"isStateless\":true,\"source\":\"10.60.0.0/15\",\"sourceType\":\"CIDR_BLOCK\"},
  {\"direction\":\"INGRESS\",\"protocol\":\"17\",\"isStateless\":true,\"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",\"udpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}}},
  {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":true,\"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}}},
  {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,\"source\":\"193.123.254.10/32\",\"sourceType\":\"CIDR_BLOCK\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}}},
  {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":true,\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\"}
]" 2>/dev/null || true

# nsg-game: stateless all from game range, egress only to game range
oci network nsg rules add --nsg-id "$NSG_GAME" --security-rules "[
  {\"direction\":\"INGRESS\",\"protocol\":\"all\",\"isStateless\":true,\"source\":\"10.60.0.0/15\",\"sourceType\":\"CIDR_BLOCK\"},
  {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":true,\"destination\":\"10.60.0.0/15\",\"destinationType\":\"CIDR_BLOCK\"}
]" 2>/dev/null || true

# nsg-infra: stateless all from game range, egress anywhere (NAT/IGW controls actual exit)
oci network nsg rules add --nsg-id "$NSG_INFRA" --security-rules "[
  {\"direction\":\"INGRESS\",\"protocol\":\"all\",\"isStateless\":true,\"source\":\"10.60.0.0/15\",\"sourceType\":\"CIDR_BLOCK\"},
  {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":false,\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\"}
]" 2>/dev/null || true

echo "NSGs created"

# --- subnets ---
# edge (public)
subnet edge  10.60.250.0/24 "$RT_EDGE"  true
# service (private, NAT)
subnet svc   10.60.200.0/24 "$RT_SVC"   false
# core (private, no internet)
subnet core  10.60.201.0/24 "$RT_CORE"  false
# mirror (private, NAT during warm-up, removed at T-0)
subnet mirror 10.60.202.0/24 "$RT_MIRROR" false
# hills (private, no internet - KotH hill VMs)
subnet hills  10.60.210.0/24 "$RT_GAME"  false

# 16 prod subnets (p01..p16, teams 1-15 + NOP 16)
for t in $(seq 1 16); do
  tt=$(printf %02d "$t")
  subnet "p$tt" "10.60.$t.0/24" "$RT_GAME" false
done

# 15 workbench subnets (w01..w15)
for t in $(seq 1 15); do
  tt=$(printf %02d "$t")
  subnet "w$tt" "10.61.$t.0/24" "$RT_GAME" false
done

echo "all 37 subnets created"
echo "done. run 20-router.sh next."
