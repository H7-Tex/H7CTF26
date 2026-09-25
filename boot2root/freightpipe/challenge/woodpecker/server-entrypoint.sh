#!/bin/sh
# Wait for Gitea to seed the per-instance OAuth application, then export the
# generated credentials into the Woodpecker server process.
set -eu

readonly OAUTH_ENV=/oauth/woodpecker.env

log() { printf '[woodpecker-bootstrap] %s\n' "$*"; }

attempt=0
until [ -s "$OAUTH_ENV" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 180 ]; then
    log "timeout waiting for $OAUTH_ENV"
    exit 1
  fi
  [ "$attempt" -eq 1 ] && log "waiting for $OAUTH_ENV"
  sleep 1
done

set -a
# The Gitea entrypoint restricts both values to shell-safe characters before
# atomically publishing this rootless-server-readable file.
. "$OAUTH_ENV"
set +a

: "${WOODPECKER_GITEA_CLIENT:?missing WOODPECKER_GITEA_CLIENT}"
: "${WOODPECKER_GITEA_SECRET:?missing WOODPECKER_GITEA_SECRET}"

log 'OAuth credentials loaded; starting Woodpecker server'
exec /bin/woodpecker-server "$@"
