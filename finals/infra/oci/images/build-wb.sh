#!/usr/bin/env bash
# images/build-wb.sh - build golden h7f-wb workbench image.
# same pattern as build-prod.sh: seed VM -> provision -> custom image -> terminate.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

[[ -n ${C:-} ]] || { echo "H7F_COMPARTMENT_ID not set"; exit 1; }

SEED_IP_PRIV=10.60.200.251
NSG_INFRA=$(inv_get nsg.nsg-infra)

echo "==> launching seed VM for wb image..."
SEED_ID=$(launch seed-wb \
  "$(inv_get subnet.svc)" "$SEED_IP_PRIV" \
  2 16 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/../cloud-init/wb.yaml")

sleep 120

SEED_PUBLIC_IP=$(oci compute vnic-attachment list \
  --compartment-id "$C" --instance-id "$SEED_ID" | q_data '.[0]."public-ip"')

ssh -i "${H7F_SSH_KEY:-~/.ssh/h7f-orga}" -o StrictHostKeyChecking=no \
  "ubuntu@${SEED_PUBLIC_IP}" bash -s <<'PROVISION'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# core tools
apt-get update -qq
apt-get install -y -q \
  git gdb python3 python3-pip python3-venv \
  pwndbg patchelf ncat netcat-openbsd \
  docker.io docker-buildx-plugin \
  tcpdump tshark wireshark-common \
  strace ltrace binutils file xxd \
  nmap curl wget jq \
  chrony

# Python exploit toolkit
pip3 install -q pwntools requests httpx ropper

# Tulip packet viewer (team-side, port 5000)
mkdir -p /srv/tulip
cat > /srv/tulip/docker-compose.yml <<'TC'
services:
  tulip:
    image: 10.60.202.10:5001/enowars/tulip:latest
    ports: ["10.61.0.0/16:5000:5000"]
    volumes: ["/srv/pcap:/data/pcaps:ro"]
    restart: unless-stopped
TC

# S4DFarm exploit runner: pre-configured for H7CTF finals
# - submitter: Anvil TCP 10.60.200.10:4141
# - attack-info: Anvil HTTP (Finals-3 supplies exact endpoint path)
# - flag regex: H7CTF\{[A-Z2-7]{32}\}
# - team numbers 1-15 + NOP(16); team T prod IP = 10.60.T.2
mkdir -p /srv/farm
git clone --depth=1 https://github.com/enowars/S4DFarm /srv/farm 2>/dev/null || true
cat > /srv/farm/client/config.json <<'FARMCFG'
{
  "server": "http://10.60.200.10",
  "flag_regex": "H7CTF\\{[A-Z2-7]{32}\\}",
  "flag_submit_tcp": "10.60.200.10:4141",
  "attack_info": "http://10.60.200.10/api/v1/attack-info",
  "teams": 16,
  "team_ip_template": "10.60.{team_id}.2",
  "nop_team_id": 16
}
FARMCFG
# farm server config (submits flags to TCP line and shows results in browser on :5001)
cat > /srv/farm/server/config.json <<'SRVCFG'
{
  "submit_flag_url": "tcp://10.60.200.10:4141",
  "flag_format": "H7CTF{[A-Z2-7]{32}}",
  "teams": 16
}
SRVCFG

# chrony NTP
echo "server 169.254.169.123 iburst prefer" >> /etc/chrony/chrony.conf
systemctl enable chrony

# key-sync timer: syncs team SSH key from Gitea API periodically (Finals-3 supplies key endpoint)
cat > /usr/local/bin/key-sync <<'KS'
#!/bin/bash
# placeholder: in real event, pull authorized_keys from ops API
KS
chmod +x /usr/local/bin/key-sync

# clean up
apt-get autoremove -y -q && apt-get clean
cloud-init clean --logs
rm -f /etc/machine-id /var/lib/dbus/machine-id
truncate -s 0 /etc/hostname
sync
PROVISION

echo "==> creating custom image h7f-wb..."
IMAGE_ID=$(oci compute image create \
  --compartment-id "$C" \
  --instance-id "$SEED_ID" \
  --display-name h7f-wb \
  --wait-for-state AVAILABLE | q_data '.id')
inv_set img.wb "$IMAGE_ID"
echo "h7f-wb image: $IMAGE_ID"
echo "set H7F_IMG_WB=$IMAGE_ID in env or shell before running 60-fleet.sh"

echo "==> terminating seed VM..."
oci compute instance terminate --instance-id "$SEED_ID" --force --wait-for-state TERMINATED
inv_set vm.seed-wb ""

echo "workbench image build complete."
