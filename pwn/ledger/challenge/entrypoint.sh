#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{us3_4ft3r_fr33_t04ch3_p01s0n_g0t}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/ledger",stderr
