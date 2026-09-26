#!/bin/bash
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=h7ctf26/sounding-line
docker build -t "$IMG" "$HERE"
CID=$(docker create "$IMG")
STAGE=$(mktemp -d)
docker cp "$CID":/usr/local/bin/sounding_line "$STAGE/sounding_line"
docker cp "$CID":/lib/x86_64-linux-gnu/libc.so.6 "$STAGE/libc.so.6"
docker cp "$CID":/lib64/ld-linux-x86-64.so.2 "$STAGE/ld-linux-x86-64.so.2"
docker rm "$CID" >/dev/null
cp "$HERE/handout_README.txt" "$STAGE/README.txt"
( cd "$STAGE" && zip -q -X "$HERE/sounding_line.zip" sounding_line libc.so.6 ld-linux-x86-64.so.2 README.txt )
rm -rf "$STAGE"
echo "wrote $HERE/sounding_line.zip"
