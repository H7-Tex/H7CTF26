#!/bin/sh
# One tier of The Ladder (graded). Waits for the grader to PUSH this tier's token over the
# internal net (one-shot, before the public port opens), writes it as the value a successful
# exploit exfiltrates, then serves the rung. A player who pops THIS tier reads only THIS token;
# separate containers keep token_{k+1} and GRADER_SECRET out of reach.
set -e
TIER="${TIER:-gateway_v2.0}"
CTRL_PORT="${CTRL_PORT:-9100}"

# one-shot receive of our token from the grader (internal only). socat exits after one conn,
# so the control port is closed before any player can connect -> a popped tier can't re-push.
TOKEN="$(socat -u TCP-LISTEN:${CTRL_PORT},reuseaddr,bind=0.0.0.0 STDOUT | head -c 128 | tr -d '\r\n')"
[ -n "$TOKEN" ] || { echo "no token pushed" >&2; exit 1; }
printf '%s\n' "$TOKEN" > /flag
chmod 644 /flag

# now open the public rung; per-connection fresh process, exploit exfiltrates /flag = our token
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/tiers/${TIER}",stderr
