#!/bin/sh
set -e
DEFAULT_FLAG='H7CTF{sp33d_run_th3_4ss3mbly_l1n3_w1th_c0d3}'
export FLAG="${FLAG:-$DEFAULT_FLAG}"
exec python3 -u /app/server.py
