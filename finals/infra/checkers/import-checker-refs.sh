#!/usr/bin/env bash
# import-checker-refs.sh — set checker_ref on game_services from checker-refs.env.
# Run after gen-compose.sh and after the services are registered in the DB.
#
# Usage:
#   PGPASSWORD=... ./import-checker-refs.sh [checker-refs.env] [--dry-run]

set -euo pipefail

REFS_FILE="${1:-checker-refs.env}"
DRY_RUN=0
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1

if [[ ! -f "$REFS_FILE" ]]; then
  echo "refs file not found: $REFS_FILE" >&2
  exit 1
fi

PG="${PGHOST:-10.60.200.10}"
PG_PORT="${PGPORT:-5432}"
PG_DB="${PGDATABASE:-anvil_finals}"
PG_USER="${PGUSER:-anvil}"

while IFS='=' read -r key val; do
  [[ "$key" =~ ^# ]] && continue
  [[ -z "$key" ]] && continue
  # key format: checker_ref_<slug_with_underscores>
  slug="${key#checker_ref_}"
  slug="${slug//_/-}"   # slug uses hyphens in game_services
  url="$val"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "DRY: UPDATE game_services SET checker_ref = '$url' WHERE slug = '$slug'"
  else
    psql -h "$PG" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
      -c "UPDATE game_services SET checker_ref = '$url' WHERE slug = '$slug';" 2>&1
    echo "  set checker_ref for $slug -> $url"
  fi
done < "$REFS_FILE"
