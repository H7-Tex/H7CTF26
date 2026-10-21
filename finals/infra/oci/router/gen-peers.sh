#!/usr/bin/env bash
# gen-peers.sh N PLAYERS_PER_TEAM
# generates wg0.conf for r1 + one peer config + QR per player.
# output directory: $SCRIPT_DIR/wg-out/ (gitignored; distribute out-of-band)
#
# hall gateway is a single site peer: 10.80.255.2, covers 10.80.1-15.0/24 each team's VLAN.
# fallback per-player peers: 10.80.T.200..239/32 (T = team 1-15, up to 40 players per team).
# staff peers: 10.80.250.0/24 (up to 40 staff WG slots at 10.80.250.200-239).
# wstunnel forward: plain-TCP 443 -> wg 51820 on the router, for captive-portal bypass.
set -euo pipefail
source "$(dirname "$(realpath "$0")")/../env.sh"

N=${1:-15}
PPT=${2:-6}  # players per team (fallback WG slots each)
STAFF_SLOTS=20

WG_OUT="$SCRIPT_DIR/wg-out"
mkdir -p "$WG_OUT"

# server keys (generated once, cached)
SERVER_KEY_FILE="$WG_OUT/server.key"
SERVER_PUB_FILE="$WG_OUT/server.pub"
if [[ ! -f $SERVER_KEY_FILE ]]; then
  wg genkey | tee "$SERVER_KEY_FILE" | wg pubkey > "$SERVER_PUB_FILE"
  chmod 600 "$SERVER_KEY_FILE"
fi
SERVER_PRIV=$(cat "$SERVER_KEY_FILE")
SERVER_PUB=$(cat "$SERVER_PUB_FILE")

# hall gateway keys
GW_KEY_FILE="$WG_OUT/hall-gw.key"
GW_PUB_FILE="$WG_OUT/hall-gw.pub"
if [[ ! -f $GW_KEY_FILE ]]; then
  wg genkey | tee "$GW_KEY_FILE" | wg pubkey > "$GW_PUB_FILE"
  chmod 600 "$GW_KEY_FILE"
fi
GW_PRIV=$(cat "$GW_KEY_FILE")
GW_PUB=$(cat "$GW_PUB_FILE")

PUBLIC_IP=$(cat "$SCRIPT_DIR/../wg-public-ip" 2>/dev/null || \
  inv_get public-ip 2>/dev/null || echo "FILL_ME_IN")

# --- wg0.conf for r1 ---
WG_CONF="$WG_OUT/wg0.conf"
{
  cat <<EOF
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.80.255.1/16
ListenPort = 51820
# MTU: VCN default 9000; set 1420 on WG for hall connectivity (campus MTU unknown)
MTU = 1420

# hall gateway site peer
[Peer]
PublicKey = $GW_PUB
AllowedIPs = 10.80.255.2/32$(for t in $(seq 1 "$N"); do printf ",10.80.%d.0/24" "$t"; done)
PersistentKeepalive = 25

EOF

  # per-player fallback peers
  for t in $(seq 1 "$N"); do
    for p in $(seq 1 "$PPT"); do
      idx=$(( (t-1)*PPT + p ))
      PKEY_FILE="$WG_OUT/player-t${t}-p${p}.key"
      PPUB_FILE="$WG_OUT/player-t${t}-p${p}.pub"
      [[ -f $PKEY_FILE ]] || { wg genkey | tee "$PKEY_FILE" | wg pubkey > "$PPUB_FILE"; chmod 600 "$PKEY_FILE"; }
      peer_ip="10.80.$t.$((199+p))"
      echo "[Peer]"
      echo "PublicKey = $(cat "$PPUB_FILE")"
      echo "AllowedIPs = ${peer_ip}/32"
      echo
    done
  done

  # staff peers
  for p in $(seq 1 "$STAFF_SLOTS"); do
    PKEY_FILE="$WG_OUT/staff-${p}.key"
    PPUB_FILE="$WG_OUT/staff-${p}.pub"
    [[ -f $PKEY_FILE ]] || { wg genkey | tee "$PKEY_FILE" | wg pubkey > "$PPUB_FILE"; chmod 600 "$PKEY_FILE"; }
    echo "[Peer]"
    echo "PublicKey = $(cat "$PPUB_FILE")"
    echo "AllowedIPs = 10.80.250.$((199+p))/32"
    echo
  done
} > "$WG_CONF"
chmod 600 "$WG_CONF"
echo "wg0.conf written ($((N*PPT + STAFF_SLOTS + 1)) peers)"

# --- per-player client configs + QR ---
gen_player_cfg() {
  local t=$1 p=$2
  local peer_ip="10.80.$t.$((199+p))"
  local tt; tt=$(printf %02d "$t")
  local PKEY_FILE="$WG_OUT/player-t${t}-p${p}.key"
  local PPUB_FILE="$WG_OUT/player-t${t}-p${p}.pub"
  local cfg="$WG_OUT/player-team${tt}-slot${p}.conf"

  cat > "$cfg" <<EOF
[Interface]
PrivateKey = $(cat "$PKEY_FILE")
Address = ${peer_ip}/32
DNS = 10.60.202.10
MTU = 1380

[Peer]
PublicKey = $SERVER_PUB
Endpoint = ${PUBLIC_IP}:443
AllowedIPs = 10.60.0.0/15, 10.80.0.0/16
PersistentKeepalive = 25
EOF
  chmod 600 "$cfg"
  qrencode -t ansiutf8 -r "$cfg" > "${cfg%.conf}.qr.txt" 2>/dev/null || true
  qrencode -t PNG -o "${cfg%.conf}.qr.png" -r "$cfg" 2>/dev/null || true
}

for t in $(seq 1 "$N"); do
  for p in $(seq 1 "$PPT"); do
    gen_player_cfg "$t" "$p" &
  done
done
wait

# --- hall gateway config (printed for site team) ---
cat > "$WG_OUT/hall-gateway.conf" <<EOF
# OPNsense WireGuard peer config
# add to OPNsense: VPN -> WireGuard -> Peers
# AllowedIPs covers the full OCI VCN + 10.80.255.x
[Interface]
PrivateKey = $GW_PRIV
Address = 10.80.255.2/16

[Peer]
PublicKey = $SERVER_PUB
Endpoint = ${PUBLIC_IP}:443
AllowedIPs = 10.60.0.0/15
PersistentKeepalive = 25
EOF

echo "player configs + QR codes in $WG_OUT/"
echo "hall gateway config: $WG_OUT/hall-gateway.conf"
echo "send per-team slot configs to team contacts; hand QRs to players at check-in."
