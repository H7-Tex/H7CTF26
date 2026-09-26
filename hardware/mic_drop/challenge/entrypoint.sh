#!/bin/sh
set -e
SRV="${SRV_DIR:-/srv}"
mkdir -p "$SRV/hls/boardroom"
python3 /app/gen.py "$SRV"
ffmpeg -nostdin -loglevel error -y -i "$SRV/boardroom.wav" \
  -c:a aac -b:a 128k \
  -f hls -hls_time 1 -hls_playlist_type vod -hls_flags independent_segments \
  -hls_segment_filename "$SRV/hls/boardroom/seg_%03d.ts" \
  "$SRV/hls/boardroom/index.m3u8"
exec python3 /app/serve.py
