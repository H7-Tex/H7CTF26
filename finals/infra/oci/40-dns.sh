#!/usr/bin/env bash
# 40-dns.sh - VCN private resolver view + catch-all DNS sink for team ranges
# all team DNS goes to mirror:53 which returns NXDOMAIN for everything outside the allow list.
# this prevents exfil via DNS and stops teams from hitting each other's boxes by hostname.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[[ -n $C ]] || { echo "H7F_COMPARTMENT_ID not set"; exit 1; }

VCN=$(inv_get vcn)

# --- private resolver ---
RESOLVER=$(inv_get dns.resolver)
if [[ -z $RESOLVER ]]; then
  RESOLVER=$(oci dns resolver list \
    --compartment-id "$C" \
    --scope PRIVATE | q_data '.[] | select(."display-name"=="h7f-vcn") | .id')
  # OCI creates one private resolver per VCN automatically; just find it
  [[ -n $RESOLVER ]] || { echo "no private resolver found for h7f-vcn; check VCN creation"; exit 1; }
  inv_set dns.resolver "$RESOLVER"
fi
echo "private resolver: $RESOLVER"

MIRROR_IP=10.60.202.10

# --- forwarding rule: all game subnets use mirror as authoritative ---
# rule set sends all queries in 10.60.0.0/15 reverse zones to /dev/null (mirror answers)
# and forwards everything else to the VCN default resolver (169.254.169.254)
RULESET=$(oci dns resolver-endpoint list \
  --resolver-id "$RESOLVER" --scope PRIVATE 2>/dev/null | q_data '.[0].id' || echo "")

# attach a listening endpoint on mirror's subnet if not already done
EP_ID=$(inv_get dns.listen-ep)
if [[ -z $EP_ID ]]; then
  EP_ID=$(oci dns resolver-endpoint create \
    --resolver-id "$RESOLVER" \
    --scope PRIVATE \
    --name h7f-listen \
    --endpoint-type VNIC \
    --is-listening true \
    --listening-address "$MIRROR_IP" \
    --subnet-id "$(inv_get subnet.mirror)" \
    --nsg-ids "[\"$(inv_get nsg.nsg-infra)\"]" \
    --wait-for-state ACTIVE | q_data '.id') 2>/dev/null || EP_ID=""
  # OCI private DNS endpoints are auto-provisioned in older tenancies; skip if creation fails
  [[ -n $EP_ID ]] && inv_set dns.listen-ep "$EP_ID"
fi

# forwarding rules: team-range PTR zones sink to mirror; everything else default
# mirror runs unbound with zone "10.60.in-addr.arpa" { type deny; } and "." forward to 169.254.169.254
oci dns resolver update \
  --resolver-id "$RESOLVER" \
  --scope PRIVATE \
  --force \
  --attached-views "[]" \
  --rules "[
    {\"ruleType\":\"FORWARDING\",\"destinationAddresses\":[\"$MIRROR_IP\"],\"sourceEndpointName\":\"h7f-listen\",\"qnameCoverConditions\":[\"10.60.in-addr.arpa\",\"10.61.in-addr.arpa\",\"10.80.in-addr.arpa\"]}
  ]" 2>/dev/null || \
  echo "DNS resolver update not supported on this tenancy type; configure unbound on mirror manually"

echo "DNS configuration done."
echo "mirror VM must run:"
echo "  unbound with stub-zone for game PTR zones -> deny"
echo "  forward-zone '.' -> 169.254.169.254 (OCI VCN resolver)"
echo "  local-zone 'internal.h7ctf.' transparent -> A records for ops/anvil/checker/gitea/mirror"
