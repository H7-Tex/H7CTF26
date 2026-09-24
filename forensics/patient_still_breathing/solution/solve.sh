#!/bin/bash
# Reference walkthrough for "The Patient Is Still Breathing" (run as the analyst; uses sudo
# for acquisition). Each stage's output unlocks the next - you cannot skip or grep ahead.
set -o pipefail
WS=/var/www/html/ci/uploads/build_status.php

echo "== Stage 1: foothold (the uploaded webshell) =="
# the live [ci-worker/php-fpm] process is really a shell spawned by the CI app; it led here.
K1=$(grep -oP 'OP_KEY = "\K[0-9a-f]+' "$WS")
V1=$(grep -oP 'base64_decode\("\K[^"]+' "$WS" | base64 -d)
echo "  webshell operator key K1=$K1"
echo "  FLAG 1 = $V1"

echo "== Stage 2: cloaked implant (spot the rootkit, pivot via the implant) =="
# /etc/ld.so.preload is a file-based readdir hook hiding .sys_* from `ls` (so `ls /tmp`
# doesn't show the staging dir). It's file-based, so LD_PRELOAD= won't disable it; to make
# ls honest you'd `sudo rm /etc/ld.so.preload`. But you don't need to: the implant leaks
# the path, and the dir's contents (not named .sys_*) aren't hidden, and open-by-path works.
cat /etc/ld.so.preload
PID=$(for p in $(pgrep -f '\.sys_agentd'); do sudo readlink /proc/$p/exe 2>/dev/null | grep -q 'deleted' && echo $p; done | head -1)
CACHE=$(sudo tr '\0' ' ' </proc/$PID/cmdline | grep -oP '/tmp/\.sys_cache')     # implant cmdline leaks the staging dir
echo "  implant pid=$PID (binary deleted; recover via /proc/$PID/exe), staging dir=$CACHE"
ls "$CACHE"
V2=$(openssl enc -d -aes-256-cbc -pbkdf2 -k "$K1" -in "$CACHE/agent.dat" | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG 2 = $V2"

echo "== Stage 3: the key that only lives in RAM =="
SK=$(sudo python3 - "$PID" <<'PY'
import sys,re
pid=sys.argv[1]; out=b""
maps=open(f"/proc/{pid}/maps").read()
mem=open(f"/proc/{pid}/mem","rb")
for line in maps.splitlines():
    m=re.match(r"([0-9a-f]+)-([0-9a-f]+) (..)",line)
    if not m or "r" not in m.group(3): continue
    a,b=int(m.group(1),16),int(m.group(2),16)
    try: mem.seek(a); out+=mem.read(b-a)
    except Exception: pass
m=re.search(rb"SESSIONKEY=([0-9a-f]+)",out)
print(m.group(1).decode() if m else "")
PY
)
echo "  session key recovered from process memory SK=$SK"
V3=$(openssl enc -d -aes-256-cbc -pbkdf2 -k "$SK" -in "$CACHE/exfil.enc" | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG 3 = $V3"

echo "== Stage 4: the log they forgot to wipe + the timestomp =="
# auth.log is clean, but the web access log still has the operator's foothold hit;
# and the backdoored artifact's mtime is faked while ctime matches the real intrusion.
IP=$(grep 'build_status.php' /var/log/nginx/access.log | grep -oP '^\d+\.\d+\.\d+\.\d+' | grep -v '^10\.' | sort -u | head -1)
echo "  real operator source IP (from nginx log) = $IP"
stat -c '  artifact mtime=%y ctime=%z' /opt/ci/artifacts/payment-sdk-1.4.2.jar
V4=$(openssl enc -d -aes-256-cbc -pbkdf2 -k "$IP" -in "$CACHE/closeout.enc" | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG 4 = $V4"
