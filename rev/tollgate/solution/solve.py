#!/usr/bin/env python3
# Static solve for Tollgate (stripped Go crackme). The check() function validates the 16-byte
# admin token as four big-endian uint32 words, each transformed  rotl32(w ^ K, C) + A == TARGET.
# The four constant arrays (xorK / rot / addA / target) are read out of check()'s disassembly
# (they live contiguously in the Go data section, right before the ciphertext); every step is
# invertible, so there's one token. Then sha256(token) -> AES-256-CBC decrypt the flag blob.
import sys, struct, hashlib
from Crypto.Cipher import AES

M = 0xffffffff
def rotr32(v, r): return ((v >> r) | (v << (32 - r))) & M

# recovered by reversing check() in the stripped binary (immediates / data loads):
xorK   = [0x7c5afe6c, 0x1ddf8cdb, 0x9362ba25, 0xa689a4ca]
rot    = [22, 12, 3, 20]
addA   = [0xb441f5cf, 0x3fbcb9d9, 0x10ceff09, 0x7b7f535f]
target = [0x824f1143, 0x7bc67cb2, 0x4a86f74e, 0x5b3e302e]

def find_flag(path, key):
    # the flag ciphertext is somewhere in the data section; find it with a decryption oracle -
    # slide a 48-byte window, decrypt with the recovered key + zero IV, accept the one whose
    # plaintext is our flag with valid PKCS7. Deterministic, no guessing where the blob sits.
    data = open(path, "rb").read()
    for off in range(0, len(data) - 48):
        pt = AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(data[off:off + 48])
        n = pt[-1]
        if 1 <= n <= 16 and pt.startswith(b"H7CTF{") and pt.endswith(bytes([n]) * n):
            return pt[:-n].decode()
    return None

def main():
    binpath = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/abu/Main/Projects/CTF26/H7CTF26/rev/tollgate/challenge/tollgate"

    # invert the per-word transform:  w = rotr32(target - A, C) ^ K
    tok = b""
    for i in range(4):
        w = rotr32((target[i] - addA[i]) & M, rot[i]) ^ xorK[i]
        tok += struct.pack(">I", w & M)
    print("recovered token:", tok.decode(errors="replace"))

    key = hashlib.sha256(tok).digest()
    flag = find_flag(binpath, key)
    print("flag:", flag)

if __name__ == "__main__":
    main()
