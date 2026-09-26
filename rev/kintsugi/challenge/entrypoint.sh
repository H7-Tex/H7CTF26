#!/bin/sh
set -e

APP=/srv/kintsugi
OUT=$APP/handout
TEAM_ID="${TEAM_ID:-team-local}"

rm -rf "$OUT"
mkdir -p "$OUT"
cp /opt/kintsugi/vmrun "$OUT/vmrun"
cp /opt/kintsugi/README.md "$OUT/README.md"

python3 /opt/kintsugi/gen.py --out "$OUT" --flag "$FLAG" --team "$TEAM_ID"

tar -C "$OUT" -czf "$APP/handout.tar.gz" .

export PUBKEY_PATH="$OUT/pubkey.bin"
export HANDOUT_PATH="$APP/handout.tar.gz"
exec gunicorn -w 2 -b 0.0.0.0:8000 --chdir /opt/kintsugi verifier:app
