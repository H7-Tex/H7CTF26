#!/bin/sh
set -e
printf '%s\n' "${FLAG:-H7CTF{f0rm4t_str1ng_0v3rwr1t3_4dm1n}}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/manifest",stderr
