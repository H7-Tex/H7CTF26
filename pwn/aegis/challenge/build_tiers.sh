#!/bin/bash
# Build every Aegis Gateway release from the one source with its release-era flags.
# Run inside ubuntu:24.04 (glibc 2.39) so FILE/FSOP offsets are pinned.
set -e
cd "$(dirname "$0")"
mkdir -p build
SRC=src/gateway.c

# RELRO is controlled explicitly: the Ubuntu toolchain defaults to Full RELRO (-z now),
# so the early releases are forced back to Partial (-z relro -z lazy). -fcf-protection=none
# keeps CET off until v3.4 (the toolchain may default it on). Bug-security warning on the
# intentional printf(name) is expected; -Wno-format-security silences it (not -Werror).

# v1.0 (2021): NX baseline, no canary, no PIE, Partial RELRO
gcc -Wno-format-security -fcf-protection=none -fno-stack-protector -no-pie \
    -Wl,-z,relro,-z,lazy                                           -o build/gateway_v1.0 "$SRC"
# v1.4 (2022): + stack canary  (still no PIE, Partial RELRO, no FORTIFY)
gcc -Wno-format-security -fcf-protection=none -fstack-protector-all -no-pie \
    -Wl,-z,relro,-z,lazy                                           -o build/gateway_v1.4 "$SRC"
# v2.0 (2023): + PIE  (Partial RELRO, no FORTIFY)
gcc -Wno-format-security -fcf-protection=none -fstack-protector-all -fPIE -pie \
    -Wl,-z,relro,-z,lazy                                           -o build/gateway_v2.0 "$SRC"
# v2.6 (2024): + Full RELRO + FORTIFY_SOURCE=2; fmt %n blocked (no PATCH_FMT: %p leaks survive);
# -DWITH_FORTIFY: volatile-pointer bypass keeps DIAG overflow alive despite __read_chk
gcc -Wno-format-security -fcf-protection=none -O2 -D_FORTIFY_SOURCE=2 -DWITH_FORTIFY \
    -fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now           -o build/gateway_v2.6 "$SRC"
# v3.0 (2025): + seccomp; fmt leak still present (%n blocked by FORTIFY, %p chains work)
gcc -Wno-format-security -fcf-protection=none -O2 -D_FORTIFY_SOURCE=2 -DWITH_FORTIFY \
    -DWITH_SECCOMP \
    -fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now           -o build/gateway_v3.0 "$SRC"
# v3.4 (2026): + Intel CET (SHSTK+IBT). Build here; ENFORCEMENT needs the CET box.
gcc -Wno-format-security -fcf-protection=full -O2 -D_FORTIFY_SOURCE=2 -DWITH_FORTIFY \
    -DWITH_SECCOMP \
    -fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now           -o build/gateway_v3.4 "$SRC"

echo "built:"; ls -1 build/
