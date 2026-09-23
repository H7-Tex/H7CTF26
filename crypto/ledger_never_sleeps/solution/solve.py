#!/usr/bin/env python3
# reference solve for "The Ledger Never Sleeps". query the signer for a handful
# of approvals, recover the private key from the LCG nonce relation, forge the
# ADMIN_TRANSFER signature, submit it, read the flag.
#
#   k_i = s_i^-1 (z_i + r_i d) = A_i d + B_i        (mod n)
#   k_{i+1} = a k_i + c   =>   (k2-k1)^2 = (k1-k0)(k3-k2)   (a, c eliminated)
# substitute the affine k_i => a quadratic in d; solve mod n; keep d*G == Q.
import sys, json, hashlib, secrets, urllib.request
from ecdsa import SECP256k1

G = SECP256k1.generator
n = int(SECP256k1.order)

def post(base, path, obj):
    req = urllib.request.Request(base.rstrip("/") + path,
                                 data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def get(base, path):
    return json.loads(urllib.request.urlopen(base.rstrip("/") + path, timeout=10).read())

def z_of(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")

def modsqrt(a, p):  # tonelli-shanks, p prime
    a %= p
    if a == 0: return 0
    if pow(a, (p - 1) // 2, p) != 1: return None
    if p % 4 == 3: return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0: q //= 2; s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1: z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p; i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r

def recover(A, B, Qx, Qy):
    for o in range(len(A) - 3):                 # window of 4 consecutive nonces
        a0, a1, a2, a3 = A[o:o + 4]
        b0, b1, b2, b3 = B[o:o + 4]
        # D1=k1-k0, D2=k2-k1, D3=k3-k2 ; eq: D2^2 - D1*D3 = 0
        pA = [(a1 - a0) % n, (b1 - b0) % n]     # D1 = pA[0]*d + pA[1]
        pB = [(a2 - a1) % n, (b2 - b1) % n]     # D2
        pC = [(a3 - a2) % n, (b3 - b2) % n]     # D3
        alpha = (pB[0] * pB[0] - pA[0] * pC[0]) % n
        beta = (2 * pB[0] * pB[1] - (pA[0] * pC[1] + pA[1] * pC[0])) % n
        gamma = (pB[1] * pB[1] - pA[1] * pC[1]) % n
        cands = []
        if alpha % n == 0:
            if beta % n:
                cands.append((-gamma * pow(beta, -1, n)) % n)
        else:
            disc = (beta * beta - 4 * alpha * gamma) % n
            sq = modsqrt(disc, n)
            if sq is not None:
                inv2a = pow(2 * alpha, -1, n)
                cands += [((-beta + sq) * inv2a) % n, ((-beta - sq) * inv2a) % n]
        for d in cands:
            R = d * G
            if int(R.x()) == Qx and int(R.y()) == Qy:
                return d
    raise RuntimeError("key not recovered")

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    info = get(base, "/")
    Qx, Qy = int(info["pubkey"]["x"]), int(info["pubkey"]["y"])
    admin = info["admin_msg"]
    msgs = [f"APPROVE routine settlement #{i}" for i in range(8)]
    A, B = [], []
    for m in msgs:
        resp = post(base, "/sign", {"msg": m})
        r, s = int(resp["r"]), int(resp["s"])
        si = pow(s, -1, n)
        A.append((si * r) % n); B.append((si * z_of(m)) % n)
    d = recover(A, B, Qx, Qy)
    print(f"[solve] recovered d = {hex(d)}")
    # forge the admin signature with a fresh nonce
    k = secrets.randbelow(n - 1) + 1
    r = int((k * G).x()) % n
    s = (pow(k, -1, n) * (z_of(admin) + r * d)) % n
    out = post(base, "/forge", {"msg": admin, "r": str(r), "s": str(s)})
    print(f"[solve] {out}")

if __name__ == "__main__":
    main()
