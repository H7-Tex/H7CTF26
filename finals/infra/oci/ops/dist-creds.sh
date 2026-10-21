#!/usr/bin/env bash
# ops/dist-creds.sh - distribute credentials and configs to all VMs after provisioning.
# run from atom (via ssh to ops VM, or directly from atom if VPN is up).
# must run AFTER 60-fleet.sh and AFTER gen-peers.sh.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

WG_OUT="$SCRIPT_DIR/wg-out"
SSH_KEY=${H7F_SSH_KEY:-~/.ssh/h7f-orga}

ssh_to() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "ubuntu@$1" "$2"; }
scp_to() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$1" "ubuntu@$2:$3"; }

echo "==> r1: install WireGuard config + nftables"
R1_IP=$(oci compute instance get --instance-id "$(inv_get vm.r1)" | q_data '.["public-ip"]' || \
  oci compute vnic-attachment list --compartment-id "$C" \
    --instance-id "$(inv_get vm.r1)" | q_data '.[0]."public-ip"')
inv_set ip.r1 "$R1_IP"

# wg0.conf assembled from template + gen-peers.sh output
ssh_to "$R1_IP" "sudo tee /etc/wireguard/wg0.conf > /dev/null" < "$WG_OUT/wg0.conf"
ssh_to "$R1_IP" "sudo chmod 600 /etc/wireguard/wg0.conf && sudo systemctl enable --now wg-quick@wg0"

# nftables ruleset
bash "$SCRIPT_DIR/router/gen-nft.sh" "$N" > /tmp/h7.nft
ssh_to "$R1_IP" "sudo tee /etc/nftables.d/h7.nft > /dev/null" < /tmp/h7.nft
ssh_to "$R1_IP" "sudo nft -c -f /etc/nftables.d/h7.nft && sudo nft -f /etc/nftables.d/h7.nft"
echo "r1: WireGuard up, nftables loaded"

echo "==> r2: sync WireGuard config (same key, standby)"
R2_IP=$(oci compute vnic-attachment list --compartment-id "$C" \
  --instance-id "$(inv_get vm.r2)" | q_data '.[0]."public-ip"')
inv_set ip.r2 "$R2_IP"
ssh_to "$R2_IP" "sudo tee /etc/wireguard/wg0.conf > /dev/null" < "$WG_OUT/wg0.conf"
ssh_to "$R2_IP" "sudo chmod 600 /etc/wireguard/wg0.conf"
ssh_to "$R2_IP" "sudo tee /etc/nftables.d/h7.nft > /dev/null" < /tmp/h7.nft
echo "r2: config synced (do NOT start wg-quick on r2 until failover)"

echo "==> workbenches: install SSH keys"
WEBHOOK_SECRET=$(cat "$SCRIPT_DIR/secrets/webhook-secret")
for t in $(seq 1 "$N"); do
  tt=$(printf %02d "$t")
  wb_ip="10.61.$t.2"
  # team SSH keys: generated or supplied by each team; placeholder adds orga key
  ssh_to "$wb_ip" "sudo mkdir -p /home/ubuntu/.ssh && sudo chmod 700 /home/ubuntu/.ssh"
  scp_to "$SCRIPT_DIR/keys/orga.pub" "$wb_ip" "/tmp/orga.pub"
  ssh_to "$wb_ip" "cat /tmp/orga.pub | sudo tee /home/ubuntu/.ssh/authorized_keys > /dev/null"
  # Gitea SSH deploy key (per workbench)
  if [[ ! -f "$WG_OUT/wb-${tt}.key" ]]; then
    ssh-keygen -t ed25519 -f "$WG_OUT/wb-${tt}.key" -N "" -C "wb-$tt@h7ctf"
  fi
  scp_to "$WG_OUT/wb-${tt}.key" "$wb_ip" "/home/ubuntu/.ssh/id_ed25519"
  scp_to "$WG_OUT/wb-${tt}.key.pub" "$wb_ip" "/home/ubuntu/.ssh/id_ed25519.pub"
  ssh_to "$wb_ip" "chmod 600 /home/ubuntu/.ssh/id_ed25519"
  # write Gitea config
  ssh_to "$wb_ip" "sudo -u ubuntu git config --global core.sshCommand 'ssh -i /home/ubuntu/.ssh/id_ed25519 -o StrictHostKeyChecking=no'"
  echo "wb-$tt: keys installed"
done

echo "==> prod VMs: inject webhook secret + deployer env"
for t in $(seq 1 "$((N+1))"); do
  tt=$(printf %02d "$t")
  prod_ip="10.60.$t.2"
  ssh_to "$prod_ip" "sudo tee /srv/deployer/webhook-secret > /dev/null" <<< "$WEBHOOK_SECRET"
  ssh_to "$prod_ip" "sudo chmod 600 /srv/deployer/webhook-secret"
  echo "prod-$tt: webhook secret injected"
done

echo "==> Gitea: add workbench deploy keys"
GITEA_TOKEN=$(cat "$SCRIPT_DIR/secrets/gitea-admin-token" 2>/dev/null || { echo "GITEA_TOKEN file missing"; exit 1; })
for t in $(seq 1 "$N"); do
  tt=$(printf %02d "$t")
  PUB=$(cat "$WG_OUT/wb-${tt}.key.pub")
  curl -fsS -H "Authorization: token $GITEA_TOKEN" \
    -H "Content-Type: application/json" \
    "http://10.60.201.30:3000/api/v1/admin/users/team${tt}/keys" \
    -X POST -d "{\"title\":\"wb-$tt\",\"key\":\"$PUB\",\"read_only\":false}" 2>/dev/null || true
done

echo "==> ops: copy reset API + ops scripts"
OPS_IP=10.60.200.5
scp_to "$SCRIPT_DIR/ops/reset-api.py" "$OPS_IP" "/srv/ops/reset-api.py"
scp_to "$SCRIPT_DIR/ops/reset.sh"     "$OPS_IP" "/srv/ops/reset.sh"
scp_to "$SCRIPT_DIR/ops/failover.sh"  "$OPS_IP" "/srv/ops/failover.sh"

RESET_TOKEN=$(openssl rand -hex 32 | tee "$SCRIPT_DIR/secrets/reset-api-token")
ssh_to "$OPS_IP" "cat > /srv/ops/reset-api.env" <<< "RESET_TOKEN=$RESET_TOKEN
N=$N
SSH_KEY=/home/ubuntu/.ssh/id_ed25519"

ssh_to "$OPS_IP" "sudo systemctl start reset-api"
inv_set reset-token "$RESET_TOKEN"
echo "reset API started on ops:8090"

echo "all credentials distributed."
echo "reset API token saved to $SCRIPT_DIR/secrets/reset-api-token"
