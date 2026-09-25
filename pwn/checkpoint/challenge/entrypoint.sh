#!/bin/sh
# seal the flag and serve the binary over TCP, one process per connection.
set -e
DEFAULT_FLAG='H7CTF{r3t2w1n_ch3ckp01nt_0v3rfl0w}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/checkpoint",stderr
