#!/bin/sh
# Bind the serving port FIRST, then generate + segment in the background.
# Anvil/Traefik readiness is a TCP probe. If serve.py only starts after the encode, the
# backend reads "not ready" during the encode and Traefik returns 503 (no available server).
# serve.py binds instantly and 404s missing files, so starting it first turns a hard 503 into
# a few-seconds 404 that clears the moment the encode publishes.
set -e
SRV="${SRV_DIR:-/srv}"
mkdir -p "$SRV/hls"

# Encode off the request path. Stage outside the served tree and publish with an atomic
# rename so a client never sees a half-written playlist.
(
  set -e
  STAGE="$SRV/.stage"
  rm -rf "$STAGE"; mkdir -p "$STAGE/boardroom"
  python3 /app/gen.py "$SRV"
  ffmpeg -nostdin -loglevel error -y -i "$SRV/boardroom.wav" \
    -c:a aac -b:a 128k \
    -f hls -hls_time 1 -hls_playlist_type vod -hls_flags independent_segments \
    -hls_segment_filename "$STAGE/boardroom/seg_%03d.ts" \
    "$STAGE/boardroom/index.m3u8"
  rm -rf "$SRV/hls/boardroom"; mv "$STAGE/boardroom" "$SRV/hls/boardroom"
  echo "[entrypoint] HLS published to $SRV/hls/boardroom"
) || echo "[entrypoint] ERROR: HLS encode failed; instance is reachable but will 404 until fixed" &

exec python3 /app/serve.py
