#!/bin/sh
# seal the flag and serve the binary over TCP, one process per connection.
set -e
printf '%s\n' "${FLAG:-H7CTF{r3t2w1n_ch3ckp01nt_0v3rfl0w}}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/checkpoint",stderr
