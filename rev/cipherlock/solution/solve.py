#!/usr/bin/env python3
# Static solve for Cipherlock with z3. The key check is a tangle of mixed constraints recovered by
# reversing check():  XOR couplings, byte products (mod 256, non-linear), rotate+add. The products
# break hand linear algebra, so model the 16 key bytes as 8-bit BitVecs and let z3 solve; then
# MD5(key) -> AES-128-CBC decrypt the flag blob.
import re, sys, hashlib
import z3
from Crypto.Cipher import AES

N = 16

def load(path):
    # constants live in .rodata (read them with a disassembler); here we parse the generated header
    t = open(path).read()
    g = lambda n: [int(x) for x in re.search(n + r"\[\d+\]\s*=\s*\{([^}]*)\}", t).group(1).split(",")]
    return g("CX"), g("CY"), g("CZ"), bytes(g("FLAGBLOB"))

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/abu/Main/Projects/CTF26/H7CTF26/rev/cipherlock/challenge/cipherlock_data.h"
    CX, CY, CZ, blob = load(path)

    b = [z3.BitVec(f"b{i}", 8) for i in range(N)]
    s = z3.Solver()
    for i in range(N):
        s.add(b[i] ^ b[(i + 3) % N] == CX[i])
    for i in range(N // 2):
        s.add(b[2 * i] * b[2 * i + 1] == CY[i])
    for i in range(N):
        s.add(z3.RotateLeft(b[i], 3) + b[(i + 5) % N] == CZ[i])
    for i in range(N):
        s.add(b[i] >= 0x20, b[i] < 0x7f)
    assert s.check() == z3.sat, "unsat?!"
    m = s.model()
    key = bytes(m[b[i]].as_long() for i in range(N))
    print("recovered key:", key.decode())

    aeskey = hashlib.md5(key).digest()
    flag = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16).decrypt(blob)
    flag = flag[:-flag[-1]]
    print("flag:", flag.decode())

if __name__ == "__main__":
    main()
