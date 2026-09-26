#!/bin/sh
set -e
OUT="${1:-hothouse}"
gcc -O2 -static -s -fno-stack-protector -o "$OUT" hothouse.c
