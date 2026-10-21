#!/usr/bin/env bash
# eoe.sh — end-of-event post-game ops for H7CTF'26 finals.
# Run after the engine sets game.state=stopped and all flags are judged.
#
# Usage: eoe.sh export | eoe.sh vm-stop
#
# Required env (set in /etc/anvil/finals.env or export before running):
#   ANVIL_URL           — https://ctf.h7tex.com
#   ANVIL_ADMIN_TOKEN   — admin bearer token
#   DB_DSN              — postgres DSN (needed to poll game.state)
#   OCI_COMPARTMENT_ID  — OCI compartment containing team VMs (for vm-stop)
#   EXPORT_DIR          — where to write the score JSON (default /opt/anvil/exports)
set -euo pipefail

ACTION=${1:?usage: eoe.sh export | eoe.sh vm-stop}
ANVIL_URL=${ANVIL_URL:?ANVIL_URL not set}
ANVIL_ADMIN_TOKEN=${ANVIL_ADMIN_TOKEN:?ANVIL_ADMIN_TOKEN not set}
EXPORT_DIR=${EXPORT_DIR:-/opt/anvil/exports}
TAG="eoe[$ACTION]"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $TAG $*"; logger -t "$TAG" "$*" 2>/dev/null || true; }

api_get() {
    curl -fsS --max-time 30 \
        -H "Authorization: Bearer $ANVIL_ADMIN_TOKEN" \
        "${ANVIL_URL}${1}"
}

case "$ACTION" in
export)
    # wait for engine to settle: game.state must be 'stopped' before exporting
    log "waiting for game.state=stopped"
    for i in $(seq 1 24); do
        STATE=$(api_get /api/v1/admin/platform/settings 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('game',{}).get('state','unknown'))" 2>/dev/null || echo unknown)
        if [[ "$STATE" == "stopped" ]]; then
            log "game.state=stopped confirmed"
            break
        fi
        log "game.state=$STATE, waiting 5s ($i/24)"
        sleep 5
    done

    log "exporting scores"
    mkdir -p "$EXPORT_DIR"
    EXPORT_FILE="$EXPORT_DIR/scores-$(date -u +%Y%m%dT%H%M%SZ).json"
    api_get /api/v1/admin/scores/export > "$EXPORT_FILE"
    BYTES=$(wc -c < "$EXPORT_FILE")
    log "scores written to $EXPORT_FILE ($BYTES bytes)"
    ;;

vm-stop)
    # stop all team instances tagged for this event; run after export
    log "stopping team VMs"
    if ! command -v oci &>/dev/null; then
        log "WARNING: oci CLI not found; team VM stop must be done manually"
        exit 1
    fi
    OCI_COMPARTMENT_ID=${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID not set}

    INSTANCE_IDS=$(oci compute instance list \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --lifecycle-state RUNNING \
        --query 'data[?defined-tags."h7ctf26"."role"==`team`].id' \
        --raw-output 2>/dev/null | python3 -c "import sys,json; print('\n'.join(json.load(sys.stdin)))" 2>/dev/null || true)

    if [[ -z "$INSTANCE_IDS" ]]; then
        log "no running team instances found (already stopped or wrong tag)"
    else
        while IFS= read -r iid; do
            [[ -z "$iid" ]] && continue
            log "stopping OCI instance $iid"
            oci compute instance action --instance-id "$iid" --action STOP
        done <<< "$INSTANCE_IDS"
        log "vm-stop dispatched"
    fi
    ;;

*)
    echo "unknown action: $ACTION" >&2
    echo "usage: eoe.sh export | eoe.sh vm-stop" >&2
    exit 1
    ;;
esac

log "done"
