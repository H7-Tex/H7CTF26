#!/usr/bin/env python3
# reference solve for polynonce. pure python (no sage): recover the private key
# from ecdsa signatures whose nonces follow a degree-2 polynomial recurrence,
# then decrypt the sealed flag.
#
#   k_i = s_i^-1 (z_i + r_i d) = A_i d + B_i   (mod n)
#   k_{i+1} = c2 k_i^2 + c1 k_i + c0            (mod n, unknown c*)
#
# stacking rows [k_i^2, k_i, 1, k_{i+1}] the vector (c2,c1,c0,-1) is a null
# vector, so any 4x4 block determinant vanishes at the true d. each det is a
# polynomial in d (the k_i are affine in d); find its roots mod n and keep the
# one whose d*G == Q. sweep degree if you don't know it (here: 2).
import json, hashlib, random, pathlib, sys
import gmpy2
from sympy import symbols, Matrix, Poly
from ecdsa import SECP256k1
from Crypto.Cipher import AES

G = SECP256k1.generator
n = int(SECP256k1.order)

# ---- GF(n)[x] root finding: gcd(f, x^n - x) then equal-degree splitting ----
def _trim(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a
def _mul(a, b, p):
    r = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        if ca:
            for j, cb in enumerate(b):
                r[i + j] = (r[i + j] + ca * cb) % p
    return _trim(r)
def _sub(a, b, p):
    r = [0] * max(len(a), len(b))
    for i, c in enumerate(a): r[i] = (r[i] + c) % p
    for i, c in enumerate(b): r[i] = (r[i] - c) % p
    return _trim(r)
def _divmod(a, b, p):
    a = a[:]; b = _trim(b[:])
    inv = int(gmpy2.invert(b[-1], p))
    q = [0] * max(len(a) - len(b) + 1, 1)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        deg = len(a) - len(b)
        coef = (a[-1] * inv) % p
        q[deg] = coef
        for i, cb in enumerate(b):
            a[deg + i] = (a[deg + i] - coef * cb) % p
        a = _trim(a)
    return _trim(q), _trim(a)
def _gcd(a, b, p):
    a = _trim([c % p for c in a]); b = _trim([c % p for c in b])
    while not (len(b) == 1 and b[0] == 0):
        a, b = b, _divmod(a, b, p)[1]
    if a[-1] != 1:
        inv = int(gmpy2.invert(a[-1], p)); a = [(c * inv) % p for c in a]
    return _trim(a)
def _powmod(base, e, mod, p):
    res = [1]; base = _divmod(base, mod, p)[1]
    while e > 0:
        if e & 1: res = _divmod(_mul(res, base, p), mod, p)[1]
        base = _divmod(_mul(base, base, p), mod, p)[1]
        e >>= 1
    return _trim(res)
def _edf(g, p, out):
    g = _trim(g[:])
    if len(g) <= 1: return
    if len(g) == 2:
        out.append((-g[0] * int(gmpy2.invert(g[1], p))) % p); return
    while True:
        h = _powmod([random.randrange(p), 1], (p - 1) // 2, g, p)
        h = _sub(h, [1], p)
        t = _gcd(g, h, p)
        if 1 < len(t) < len(g):
            _edf(t, p, out); _edf(_divmod(g, t, p)[0], p, out); return
def roots_mod_p(coeffs_low_high, p):
    f = _trim([c % p for c in coeffs_low_high])
    if len(f) <= 1: return []
    g = _gcd(f, _sub(_powmod([0, 1], p, f, p), [0, 1], p), p)  # gcd(f, x^p - x)
    out = []; _edf(g, p, out); return out

def recover(handout):
    Qx = int(handout["pubkey"]["x"]); Qy = int(handout["pubkey"]["y"])
    A, B = [], []
    for sig in handout["signatures"]:
        r, s = int(sig["r"]), int(sig["s"])
        z = int.from_bytes(hashlib.sha256(sig["msg"].encode()).digest(), "big")
        si = pow(s, -1, n)
        A.append((si * r) % n); B.append((si * z) % n)
    d = symbols("d")
    for start in range(len(A) - 4):          # 4 rows i..i+3 use k up to i+4
        rows = []
        for i in range(start, start + 4):
            ki = A[i] * d + B[i]
            kj = A[i + 1] * d + B[i + 1]
            rows.append([ki * ki, ki, 1, kj])
        det = Matrix(rows).det()
        P = Poly(det, d)
        if P.is_zero: continue
        coeffs = [int(c) % n for c in reversed(P.all_coeffs())]  # low -> high
        for cand in roots_mod_p(coeffs, n):
            R = cand * G
            if int(R.x()) == Qx and int(R.y()) == Qy:
                return cand
    raise RuntimeError("private key not recovered")

def main():
    # point this at the directory holding the signatures.json + flag.enc you
    # downloaded from your instance (default: ./handout).
    d_arg = sys.argv[1] if len(sys.argv) > 1 else "handout"
    base = pathlib.Path(d_arg)
    handout = json.loads((base / "signatures.json").read_text())
    d = recover(handout)
    print(f"[solve] recovered d = {hex(d)}")
    Qx = int(handout["pubkey"]["x"]); Qy = int(handout["pubkey"]["y"])
    key = hashlib.sha256(d.to_bytes(32, "big")).digest()
    iv = hashlib.sha256(f"{Qx},{Qy}".encode()).digest()[:12]
    blob = (base / "flag.enc").read_bytes()
    ct, tag = blob[:-16], blob[-16:]
    flag = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
    print(f"[solve] FLAG = {flag.decode()}")

if __name__ == "__main__":
    main()
