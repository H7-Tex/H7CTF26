#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{r3t2l1bc_l34k_th3n_sh3ll_d1sp4tch}'
printf '%s\n' "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag
exec socat TCP-LISTEN:${PORT:-9999},reuseaddr,fork EXEC:"/usr/local/bin/dispatch",stderr
