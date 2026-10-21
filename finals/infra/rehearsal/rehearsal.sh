#!/usr/bin/env bash
# rehearsal.sh — local full-stack rehearsal for H7CTF'26 finals.
# re-runnable: --clean tears down volumes before starting.
#
# usage:
#   ./rehearsal.sh              # up + seed + drive + verify (full run)
#   ./rehearsal.sh --clean      # tear down, then full run
#   ./rehearsal.sh seed         # seed only (compose must be up)
#   ./rehearsal.sh drive        # drive only
#   ./rehearsal.sh verify       # verify only
#   ./rehearsal.sh down         # tear down
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f $DIR/docker-compose.yml"

export ANVIL_API=${ANVIL_API:-http://127.0.0.1:8080/api/v1}
export ANVIL_GS=${ANVIL_GS:-127.0.0.1:4141}
export ANVIL_DB_HOST=${ANVIL_DB_HOST:-127.0.0.1}
export ANVIL_DB_PORT=${ANVIL_DB_PORT:-5432}
export TICK_INTERVAL=${TICK_INTERVAL:-32}
export TICKS=${TICKS:-22}

# ANVIL_SRC: path to the Anvil repo (used by docker-compose build context).
# default: sibling directory relative to H7CTF26 root.
export ANVIL_SRC=${ANVIL_SRC:-$(cd "$DIR/../../../.." && pwd)/Anvil-P2-Runner}

log() { echo "$(date -u +%T) rehearsal $*"; }

# ------------------------------------------------------------------
# generate patched notebook image source
# ------------------------------------------------------------------
gen_patched() {
    local src="$DIR/../../_template/service/notebook/app.py"
    local patch="$DIR/../../_template/patches/store0_correct.patch"
    local dest="$DIR/notebook-team4-app.py"
    if [[ ! -f "$dest" || "$src" -nt "$dest" ]]; then
        log "generating patched notebook for team4..."
        cp "$src" "$dest"
        # the patch is relative to service/; apply from a tempdir
        tmp=$(mktemp -d)
        mkdir -p "$tmp/notebook"
        cp "$src" "$tmp/notebook/app.py"
        patch -s -d "$tmp" -p1 < "$patch"
        cp "$tmp/notebook/app.py" "$dest"
        rm -rf "$tmp"
        log "patched notebook written to $dest"
    fi
}

# ------------------------------------------------------------------
# subcommands
# ------------------------------------------------------------------
cmd_up() {
    if [[ "${1:-}" == "--clean" ]]; then
        log "cleaning up volumes..."
        $COMPOSE down -v --remove-orphans 2>/dev/null || true
        rm -f "$DIR/notebook-team4-app.py"
    fi
    gen_patched
    log "building + starting compose (ANVIL_SRC=$ANVIL_SRC)..."
    $COMPOSE up --build -d
    HEALTH_URL="$(echo "$ANVIL_API" | sed 's|/api/v1||')/health"
    log "waiting for anvil-api health ($HEALTH_URL)..."
    for i in $(seq 1 60); do
        if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
            log "api healthy"
            break
        fi
        sleep 3
    done
    log "waiting for gameserver health..."
    for i in $(seq 1 60); do
        if curl -fsS "http://127.0.0.1:8081/health" >/dev/null 2>&1; then
            log "gameserver healthy"
            break
        fi
        sleep 3
    done
}

cmd_seed() {
    bash "$DIR/seed.sh"
}

cmd_drive() {
    bash "$DIR/drive.sh"
}

cmd_verify() {
    bash "$DIR/verify.sh"
    local rc=$?
    return $rc
}

cmd_down() {
    $COMPOSE down -v --remove-orphans 2>/dev/null || true
    log "compose down"
}

# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------
case "${1:-all}" in
    --clean)
        cmd_up --clean
        cmd_seed
        cmd_drive
        cmd_verify
        ;;
    all)
        cmd_up
        cmd_seed
        cmd_drive
        cmd_verify
        ;;
    up)    cmd_up "${2:-}" ;;
    seed)  cmd_seed ;;
    drive) cmd_drive ;;
    verify) cmd_verify ;;
    down)  cmd_down ;;
    *)
        echo "usage: $0 [--clean|all|up|seed|drive|verify|down]"
        exit 1
        ;;
esac
