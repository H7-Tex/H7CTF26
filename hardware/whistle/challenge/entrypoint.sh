#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{dog_whistle_local_test_flag}'
export FLAG="${FLAG:-$DEFAULT_FLAG}"
cd /srv
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/aria",stderr
