#!/bin/sh
set -e
OUT="${1:-attest}"
clang++ -std=c++20 -O2 -fno-strict-aliasing -fPIE -pie -Wl,-z,relro,-z,now -o "$OUT" attest.cpp
