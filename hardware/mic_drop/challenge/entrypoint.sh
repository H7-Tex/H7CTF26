#!/bin/sh
set -e
SRV="${SRV_DIR:-/srv}"
mkdir -p "$SRV"
python3 /app/gen.py "$SRV"
exec mediamtx /app/mediamtx.yml
