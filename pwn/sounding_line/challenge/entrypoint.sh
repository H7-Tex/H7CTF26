#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{s0und1ng_l1ne_pl4ceh0lder}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 0444 /flag
unset FLAG
exec socat TCP-LISTEN:${PORT:-5000},reuseaddr,fork EXEC:"/usr/local/bin/sounding_line",stderr
