#!/bin/sh
# serve the sign-off tool over TCP, one python process per connection.
# the per-instance dynamic flag arrives as $FLAG and is inherited by the child.
set -e
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"python3 -u /app/server.py"
