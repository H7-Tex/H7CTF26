#!/bin/bash
set -euo pipefail

OUT="${1:-gatecache}"

g++ -std=gnu++20 -O1 -pthread -fPIE -pie -Wall \
    gatecache.cpp -o "$OUT" \
    -lurcu-memb -lurcu-cds -lurcu-common -lsodium

strip "$OUT"
echo "built $OUT"
