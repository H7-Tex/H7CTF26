#!/usr/bin/env python3
# reference solve for Shared Blood. the fleet's RSA keys share primes (weak RNG),
# so a GCD of the target modulus against the rest reveals a shared prime, which
# factors the target key. decrypt the intercepted PKCS1v1.5 payload -> the admin
# bootstrap token -> log into the camera cloud -> flag.
import sys, json, math, urllib.request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def get(base, path):
    return json.loads(urllib.request.urlopen(base.rstrip("/") + path, timeout=15).read())

def post(base, path, obj):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    fleet = get(base, "/fleet")
    e = int(fleet["e"])
    devices = {d["serial"]: int(d["n"]) for d in fleet["devices"]}
    cap = get(base, "/captured")
    target_serial = cap["serial"]
    N = devices[target_serial]
    ct = bytes.fromhex(cap["ciphertext"])

    # batch-GCD: the target shares a prime with exactly one sibling in the fleet
    p = None
    for s, n in devices.items():
        if n == N:
            continue
        g = math.gcd(N, n)
        if g > 1:
            p = g; break
    if not p:
        print("[solve] no shared prime found"); return
    q = N // p
    d = pow(e, -1, (p - 1) * (q - 1))
    key = RSA.construct((N, e, d, p, q))
    token = PKCS1_v1_5.new(key).decrypt(ct, None)
    print(f"[solve] factored target {target_serial}; admin token = {token.decode()}")
    print(f"[solve] {post(base, '/admin', {'token': token.decode()})}")

if __name__ == "__main__":
    main()
