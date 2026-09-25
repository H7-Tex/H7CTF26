#!/bin/sh
# instance entrypoint: seal this team's injected $FLAG into /flag.txt (world-readable so the
# escape can read it), then serve the jail over TCP, one python process per connection.
set -e
printf '%s' "${FLAG:-H7CTF{local_test_flag}}" > /flag.txt
chmod 644 /flag.txt
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"python3 -u /app/jail.py"
