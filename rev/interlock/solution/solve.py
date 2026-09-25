#!/usr/bin/env python3
# Static solve for Interlock (works off the handout binary). The check is linear over Z/256:
# A*key == B (mod 256). Recover A (16x16) and B (16) from .rodata, solve the system (A is invertible
# mod 2, so pivots are units mod 256), then MD5(key) -> AES-128-CBC decrypt the flag blob.
import sys, struct, hashlib
from Crypto.Cipher import AES

N = 16

def rodata(path):
    d = open(path, "rb").read()
    # minimal ELF64 section walk to bound the scan to .rodata
    if d[:4] == b"\x7fELF" and d[4] == 2:
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3a)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3c)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3e)[0]
        stroff = struct.unpack_from("<Q", d, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            name_off = struct.unpack_from("<I", d, base)[0]
            off = struct.unpack_from("<Q", d, base + 0x18)[0]
            size = struct.unpack_from("<Q", d, base + 0x20)[0]
            name = d[stroff + name_off: d.index(b"\0", stroff + name_off)]
            if name == b".rodata":
                return d, off, size
    return d, 0, len(d)

def gf2_invertible(A):
    m = [[A[i][j] & 1 for j in range(N)] for i in range(N)]
    r = 0
    for c in range(N):
        piv = next((i for i in range(r, N) if m[i][c]), None)
        if piv is None:
            return False
        m[r], m[piv] = m[piv], m[r]
        for i in range(N):
            if i != r and m[i][c]:
                m[i] = [m[i][k] ^ m[r][k] for k in range(N)]
        r += 1
    return True

def solve_mod256(A, B):
    # gaussian elimination over Z/256 using odd (unit) pivots
    M = [[A[i][j] for j in range(N)] + [B[i]] for i in range(N)]
    for c in range(N):
        piv = next((i for i in range(c, N) if M[i][c] & 1), None)
        if piv is None:
            return None
        M[c], M[piv] = M[piv], M[c]
        inv = pow(M[c][c], -1, 256)
        M[c] = [(v * inv) & 0xff for v in M[c]]
        for i in range(N):
            if i != c and M[i][c]:
                f = M[i][c]
                M[i] = [(M[i][k] - f * M[c][k]) & 0xff for k in range(N + 1)]
    return bytes(M[i][N] for i in range(N))

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/abu/Main/Projects/CTF26/H7CTF26/rev/interlock/challenge/interlock"
    d, off, size = rodata(path)
    end = off + size
    # region is contiguous: blob(48) | B(16) | A(256). scan for A, take B/blob before it.
    for o in range(off, end - 256 + 1):
        A = [list(d[o + i * N: o + i * N + N]) for i in range(N)]
        if not gf2_invertible(A):
            continue
        if o - 16 < off:
            continue
        B = list(d[o - 16:o])
        key = solve_mod256(A, B)
        if key is None or not all(0x20 <= b < 0x7f for b in key):
            continue
        blob = d[o - 64:o - 16]
        aeskey = hashlib.md5(key).digest()
        pt = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16).decrypt(blob)
        n = pt[-1]
        if 1 <= n <= 16 and pt[:6] == b"H7CTF{" and pt.endswith(bytes([n]) * n):
            print("recovered key:", key.decode())
            print("flag:", pt[:-n].decode())
            return
    print("not found")

if __name__ == "__main__":
    main()
