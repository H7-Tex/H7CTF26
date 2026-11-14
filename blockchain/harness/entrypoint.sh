#!/bin/sh
haveged -w 1024 >/dev/null 2>&1 &
exec python3 /harness.py
