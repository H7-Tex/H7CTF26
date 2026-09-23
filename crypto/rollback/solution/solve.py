#!/usr/bin/env python3
# reference solve for Rollback. the maintenance rollback resets the one-time
# signing counter, so we can make the notary sign many benign builds all on leaf
# 0. across enough reused signatures, for each Winternitz position we learn the
# chain value at the lowest digit seen (often the raw secret, digit 0). that lets
# us forge a WOTS signature for a chosen (backdoored) firmware on leaf 0; its
# Merkle auth path is unchanged, so it verifies against the device root.
import sys, os, json, secrets, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge"))
import lms

def post(base, path, obj):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def get(base, path):
    return json.loads(urllib.request.urlopen(base.rstrip("/") + path, timeout=15).read())

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    root = bytes.fromhex(get(base, "/root")["root"])

    # 1) reuse leaf 0: rollback + sign, many distinct benign builds
    K = 160
    min_d = [99] * lms.LEN
    best = [None] * lms.LEN
    leaf0_path = None
    for i in range(K):
        post(base, "/rollback", {})
        fw = f"benign build {i} {secrets.token_hex(4)}"
        r = post(base, "/sign", {"firmware": fw})
        sig = r["sig"]
        assert sig["leaf"] == 0, "expected reused leaf 0"
        if leaf0_path is None:
            leaf0_path = [bytes.fromhex(p) for p in sig["path"]]
        wots = [bytes.fromhex(w) for w in sig["wots"]]
        for j, d in enumerate(lms.msg_digits(fw.encode())):
            if d < min_d[j]:
                min_d[j] = d; best[j] = wots[j]
    print(f"[solve] collected {K} leaf-0 signatures; positions with min>0: "
          f"{sum(1 for d in min_d if d > 0)}/{lms.LEN} (max min {max(min_d)})")

    # 2) forge a backdoored firmware dominated by the recovered chain values
    forged = None
    for nonce in range(500000):
        fw = f"BACKDOOR update {nonce}"
        digs = lms.msg_digits(fw.encode())
        if all(digs[j] >= min_d[j] for j in range(lms.LEN)):
            forged = {"leaf": 0,
                      "wots": [lms.chain(best[j], digs[j] - min_d[j]).hex() for j in range(lms.LEN)],
                      "path": [p.hex() for p in leaf0_path]}
            target = fw
            break
    assert forged, "no dominated firmware found (collect more signatures)"
    # sanity check locally before deploying
    local = {"leaf": 0, "wots": [bytes.fromhex(w) for w in forged["wots"]],
             "path": leaf0_path}
    assert lms.verify(target.encode(), local, root), "local verify failed"
    print(f"[solve] forged {target!r}, verifies locally; deploying...")

    r = post(base, "/deploy", {"firmware": target, "sig": forged})
    print(f"[solve] {r}")

if __name__ == "__main__":
    main()
