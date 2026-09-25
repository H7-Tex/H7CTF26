#!/bin/sh
# instance entrypoint: seal this team's injected $FLAG into /flag.txt (world-readable so the
# escape can read it), then serve the jail over TCP, one python process per connection.
set -e
DEFAULT_FLAG='H7CTF{local_test_flag}'
printf '%s' "${FLAG:-$DEFAULT_FLAG}" > /flag.txt
chmod 644 /flag.txt
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"python3 -u /app/jail.py"
