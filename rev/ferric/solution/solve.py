#!/usr/bin/env python3
# Static solve for Ferric (Rust crackme). Recover the per-byte transform constants (XK/ROT/YA/TARGET)
# by reversing the Rust binary's check() - here parsed from the generated data.rs, but in the binary
# they sit in .rodata. Each byte is invertible: license[i] = ror8(TARGET[i]-YA[i], ROT[i]) ^ XK[i].
# Then the flag is BLOB[i] ^ license[i%16] ^ ((i*131+7)&0xff).
import re, sys
def ror8(v, r): return ((v >> r) | (v << (8 - r))) & 0xff
def load(path):
    t = open(path).read()
    g = lambda n: [int(x) for x in re.search(n + r": \[u8; \d+\] = \[([^\]]*)\]", t).group(1).split(",")]
    return g("XK"), g("ROT"), g("YA"), g("TARGET"), g("BLOB")
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/abu/Main/Projects/CTF26/H7CTF26/rev/ferric/challenge/data.rs"
    XK, ROT, YA, TARGET, BLOB = load(path)
    lic = bytes(((ror8((TARGET[i] - YA[i]) & 0xff, ROT[i])) ^ XK[i]) for i in range(16))
    print("recovered license:", lic.decode(errors="replace"))
    flag = bytes(BLOB[i] ^ lic[i % 16] ^ ((i * 131 + 7) & 0xff) for i in range(len(BLOB)))
    print("flag:", flag.decode())
if __name__ == "__main__":
    main()
