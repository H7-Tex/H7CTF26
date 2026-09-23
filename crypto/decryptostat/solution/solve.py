#!/usr/bin/env python3
# reference solve for DecryptoStat. CKKS approximate decryption returns m + noise,
# so from one issued ciphertext (b, a) and its returned decoding we recover the
# ring element b + a*s exactly (encode is the exact inverse of decode), hence
# a*s = (b+a*s) - b, a linear system for the secret key s. v2 adds fresh noise
# flooding per query, defeating a single query; average many queries to cancel it.
import sys, os, json, urllib.request
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge"))
import ckks

def post(base, path, obj):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def as_signed(v): return ((v + ckks.Q // 2) % ckks.Q) - ckks.Q // 2
def slots(result): return [complex(r[0], r[1]) for r in result]

def neg_matrix(a):                          # coeffs(s) -> coeffs(a*s mod x^N+1)
    M = [[0] * ckks.N for _ in range(ckks.N)]
    for i in range(ckks.N):
        for j in range(ckks.N):
            k = i + j
            M[k % ckks.N][j] = (M[k % ckks.N][j] + (a[i] if k < ckks.N else -a[i])) % ckks.Q
    return M

def solve_mod(M, rhs):                       # gaussian elimination over Z_Q
    n = ckks.N
    M = [row[:] + [rhs[i]] for i, row in enumerate(M)]
    for col in range(n):
        piv = next((r for r in range(col, n) if M[r][col] % ckks.Q), None)
        if piv is None: return None
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col], -1, ckks.Q); M[col] = [(x * inv) % ckks.Q for x in M[col]]
        for r in range(n):
            if r != col and M[r][col]:
                f = M[r][col]; M[r] = [(M[r][k] - f * M[col][k]) % ckks.Q for k in range(n + 1)]
    return [M[r][n] % ckks.Q for r in range(n)]

def recover_v1(base):
    r = post(base, "/v1/encrypt", {"values": [1.5, -2.0, 0.5, 3.25]})
    b, a = r["b"], r["a"]
    res = post(base, "/v1/decrypt", {"id": r["id"]})["result"]
    d = ckks.encode(slots(res))                          # exact b + a*s
    s = solve_mod(neg_matrix(a), ckks.ring_sub(d, b))
    return [as_signed(x) for x in s]

def recover_v2(base, T=600):
    r = post(base, "/v2/encrypt", {"values": [1.0, 2.0, 3.0, 4.0]})
    b, a = r["b"], r["a"]
    acc = np.zeros(ckks.N)
    for _ in range(T):
        res = post(base, "/v2/decrypt", {"id": r["id"]})["result"]
        d = ckks.encode(slots(res))                      # b + a*s + fresh smudge
        acc += np.array([as_signed(x) for x in d], dtype=float)
    davg = [int(round(v)) % ckks.Q for v in (acc / T)]   # smudge averages out
    s = solve_mod(neg_matrix(a), ckks.ring_sub(davg, b))
    return [as_signed(x) for x in s]

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    s1 = recover_v1(base)
    print(f"[solve] v1 key recovered (1 query): {post(base, '/v1/recover', {'s': s1})}")
    s2 = recover_v2(base)
    print(f"[solve] v2 key recovered (averaged): {post(base, '/v2/recover', {'s': s2})}")

if __name__ == "__main__":
    main()
