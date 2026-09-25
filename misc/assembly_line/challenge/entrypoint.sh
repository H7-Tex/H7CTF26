#!/bin/sh
set -e
export FLAG="${FLAG:-H7CTF{sp33d_run_th3_4ss3mbly_l1n3_w1th_c0d3}}"
exec python3 -u /app/server.py
