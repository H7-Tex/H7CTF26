#!/usr/bin/env sh
# init-deployer.sh - seeds bare git repos + service roots for 5 rehearsal teams.
# runs once inside the deployer-init container; safe to re-run.
set -e

TEMPLATE=/template
GIT_ROOT=/srv/git
SVC_ROOT=/opt/h7

# notebook listens on 7000; checker reaches teams at 172.30.0.11-15
TEAM_IPS="172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 172.30.0.15"
T=1
for IP in $TEAM_IPS; do
    REPO="$GIT_ROOT/team$T/services.git"
    SVCDIR="$SVC_ROOT/team$T/notebook"

    # bare git repo seeded with the notebook template
    if [ ! -d "$REPO" ]; then
        git init --bare --initial-branch=main "$REPO"
        TMP=$(mktemp -d)
        git clone "$REPO" "$TMP/work" -q
        git -C "$TMP/work" checkout -b main 2>/dev/null || true
        mkdir -p "$TMP/work/notebook"
        cp -r "$TEMPLATE/service/." "$TMP/work/notebook/"
        cp "$TEMPLATE/gate.yml" "$TMP/work/notebook/"
        git -C "$TMP/work" config user.email "init@h7"
        git -C "$TMP/work" config user.name "init"
        git -C "$TMP/work" add .
        git -C "$TMP/work" commit -m "init" -q
        git -C "$TMP/work" push origin main -q
        rm -rf "$TMP"
        echo "init: team$T repo seeded"
    fi

    # service root: compose file that joins the rehearsal network at the team IP
    if [ ! -d "$SVCDIR" ]; then
        mkdir -p "$SVCDIR"
        cp "$TEMPLATE/gate.yml" "$SVCDIR/"
        cat > "$SVCDIR/docker-compose.yml" << COMPOSE
networks:
  rehearsal:
    external: true
    name: rehearsal_rehearsal

services:
  notebook:
    image: h7/notebook:current
    pull_policy: never
    networks:
      rehearsal:
        ipv4_address: $IP
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:7000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5
    cpus: "0.5"
    mem_limit: 256m
COMPOSE
        echo "init: team$T svc root at $SVCDIR (IP $IP)"
    fi

    T=$((T + 1))
done

echo "deployer-init: done"
