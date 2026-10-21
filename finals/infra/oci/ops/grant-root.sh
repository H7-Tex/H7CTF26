#!/usr/bin/env bash
# ops/grant-root.sh - activate fallback A (team SSH on prod) for one or all teams.
# fallback A: enables SSH access and disables the deployer pipeline gate.
# [LIVE] run from ops VM. use only if a team's pipeline is broken and you want to give them a classic AD experience.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

TEAM=${1:?usage: grant-root.sh TEAM_NUMBER (or 'all')}
SSH_KEY="${H7F_SSH_KEY:-~/.ssh/h7f-orga}"

grant_one() {
  local t=$1 tt
  tt=$(printf %02d "$t")
  local prod_ip="10.60.$t.2"
  local wb_ip="10.61.$t.2"

  # get team's workbench public key
  local wb_pub
  wb_pub=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@$wb_ip" \
    "cat /home/ubuntu/.ssh/id_ed25519.pub" 2>/dev/null || echo "")

  if [[ -z $wb_pub ]]; then
    echo "WARN: could not get workbench key for team $tt; using orga key only"
    wb_pub=""
  fi

  # inject SSH access: add WB key + set deployer to pass-through mode
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@$prod_ip" <<SSH
sudo mkdir -p /root/.ssh
sudo chmod 700 /root/.ssh
echo "$wb_pub" | sudo tee /root/.ssh/authorized_keys > /dev/null
sudo chmod 600 /root/.ssh/authorized_keys
# tell sshd to listen (prod cloud-init may have disabled password auth but key auth should work)
sudo systemctl enable --now ssh
# put deployer in pass-through mode (deploy without gate check)
echo "GATE_BYPASS=1" | sudo tee -a /srv/deployer/config.env
echo "fallback A active on prod-$tt (10.60.$t.2)"
SSH

  # nftables SSH exemption: add prod.t.3 pair to ssh_ok set
  r1_ip=$(inv_get ip.r1)
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@$r1_ip" \
    "sudo nft add element inet h7 ssh_ok { 10.61.$t.2 . 10.60.$t.2 }" 2>/dev/null || \
    echo "WARN: could not add SSH nft rule; add manually: nft add element inet h7 ssh_ok { 10.61.$t.2 . 10.60.$t.2 }"
}

if [[ $TEAM == "all" ]]; then
  for t in $(seq 1 "$N"); do grant_one "$t"; done
else
  grant_one "$TEAM"
fi
echo "fallback A granted."
