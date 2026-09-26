#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{hothouse_local_test_flag}'
FLAG="${FLAG:-$DEFAULT_FLAG}"
SUFFIX="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FLAGPATH="/flag_${SUFFIX}"
printf '%s' "$FLAG" > "$FLAGPATH"
chmod 0400 "$FLAGPATH"
unset FLAG
export FLAGPATH
exec socat TCP-LISTEN:"${PORT:-1337}",reuseaddr,fork EXEC:"/usr/local/bin/hothouse",stderr
