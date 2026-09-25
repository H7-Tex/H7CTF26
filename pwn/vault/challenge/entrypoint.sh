#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{s3cc0mp_0rw_sh3llc0d3_v4ult}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/vault",stderr
