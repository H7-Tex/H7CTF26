#!/usr/bin/env bash
# ops/check-snat.sh - verify SNAT, TTL normalization and MSS clamping from a WG client.
# run from a workbench or laptop that is connected via WireGuard.
# checks: source IP seen at prod matches 10.60.250.100, TTL=48, MSS<=1240, no TS option.
set -euo pipefail

TARGET_PROD=${1:-10.60.1.2}
EXPECTED_SNAT=10.60.250.100

echo "=== SNAT check ==="
seen=$(curl -fsS --max-time 5 "http://$TARGET_PROD:9100/snat-echo" 2>/dev/null || echo "")
if [[ -n $seen ]]; then
  echo "prod saw connection from: $seen"
  if [[ $seen == "$EXPECTED_SNAT" ]]; then
    echo "PASS: SNAT to $EXPECTED_SNAT confirmed"
  else
    echo "FAIL: expected $EXPECTED_SNAT, got $seen"
  fi
else
  echo "WARN: /snat-echo not available (deployer not running or no service on port 9100)"
  echo "manual check: on prod box, run 'ss -tnp' during a curl from this host"
fi

echo ""
echo "=== TTL check (expect 48 at destination) ==="
# send a ping from here; the router sets TTL=48 on packets arriving at prod
# we can't observe TTL at the destination without a helper, so we check the round-trip TTL
ttl=$(ping -c 1 -q "$TARGET_PROD" 2>&1 | grep -oP 'ttl=\K[0-9]+' | head -1 || echo "?")
echo "TTL seen at this host (return path, not the normalized one): $ttl"
echo "  to verify TTL=48 at prod: ssh to prod and run 'ping -c 1 10.80.1.10' and observe ttl"

echo ""
echo "=== TCP MSS check ==="
# use tshark/tcpdump to verify MSS in SYN; requires tshark on this machine
if command -v tshark &>/dev/null; then
  timeout 3 tshark -i wg0 -f "host $TARGET_PROD and port 80 and tcp[tcpflags] & tcp-syn != 0" \
    -T fields -e tcp.options.mss_val -c 1 &
  TSHARK_PID=$!
  curl -fsS --max-time 2 "http://$TARGET_PROD/" &>/dev/null || true
  wait $TSHARK_PID 2>/dev/null
  echo "(if mss_val shown above is <=1240, MSS clamping works)"
else
  echo "SKIP: tshark not available; run 'tcpdump -i any -n -v host $TARGET_PROD and tcp[13]=2' on router"
fi

echo ""
echo "=== TCP timestamp check ==="
# SYN from WG client should have TS option; SYN-ACK from prod (via router) should not (stripped by norm_game)
if command -v tshark &>/dev/null; then
  timeout 3 tshark -i wg0 -f "host $TARGET_PROD and port 80 and tcp[tcpflags] & tcp-syn != 0" \
    -T fields -e tcp.options.timestamp -c 2 &
  TSHARK_PID=$!
  curl -fsS --max-time 2 "http://$TARGET_PROD/" &>/dev/null || true
  wait $TSHARK_PID 2>/dev/null
  echo "(SYN-ACK timestamp field should be blank/0 if TS stripping works)"
else
  echo "SKIP: tshark not available"
fi

echo ""
echo "=== WireGuard connectivity ==="
wg show wg0 2>/dev/null | grep -E "peer:|transfer:|last handshake" || echo "wg show: not available here"
