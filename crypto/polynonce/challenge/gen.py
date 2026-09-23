#!/usr/bin/env python3
# per-instance handout generator for polynonce. fresh cryptographically-random
# key each call (never predictable), seals the platform-injected $FLAG. called
# by serve.py at instance launch; also runnable standalone for local testing.
import json, hashlib, secrets, os, sys, pathlib
from ecdsa import SECP256k1
from Crypto.Cipher import AES

G = SECP256k1.generator
n = int(SECP256k1.order)

MSGS = [
    "TRANSFER 12.5 BTC -> treasury cold wallet 0x9f2a",
    "TRANSFER 0.4 BTC -> ops petty cash 0x51bb",
    "APPROVE quarterly audit report Q3-2026",
    "TRANSFER 3.0 BTC -> vendor settlement 0xc417",
    "ROTATE signing epoch 7 -> 8",
    "TRANSFER 88.0 BTC -> escrow 0x2d90",
    "APPROVE firmware manifest v4.2.1",
    "TRANSFER 1.25 BTC -> payroll batch 0x77ee",
]

def _rand():
    return secrets.randbelow(n - 1) + 1

def z_of(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")

def make_handout(flag: bytes, outdir: pathlib.Path):
    d = _rand()
    Q = d * G
    Qx, Qy = int(Q.x()), int(Q.y())
    # nonce chain: k_{i+1} = c2*k_i^2 + c1*k_i + c0 (mod n). degree 2 => LCG/HNP fits fail.
    c2, c1, c0, k = _rand(), _rand(), _rand(), _rand()
    sigs, rs = [], set()
    for msg in MSGS:
        z = z_of(msg)
        r = int((k * G).x()) % n
        s = (pow(k, -1, n) * (z + r * d)) % n
        if r == 0 or s == 0 or r in rs:
            return make_handout(flag, outdir)  # degenerate: astronomically rare, retry
        rs.add(r)
        sigs.append({"msg": msg, "r": str(r), "s": str(s)})
        k = (c2 * k * k + c1 * k + c0) % n
    key = hashlib.sha256(d.to_bytes(32, "big")).digest()
    iv = hashlib.sha256(f"{Qx},{Qy}".encode()).digest()[:12]
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(flag)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "signatures.json").write_text(json.dumps({
        "curve": "secp256k1",
        "hash": "sha256",
        "z": "z = int.from_bytes(sha256(msg), 'big')  (no reduction)",
        "sealed_flag": "AES-256-GCM, key=SHA256(d_be32), iv=SHA256('Qx,Qy')[:12], flag.enc = ct||tag16",
        "pubkey": {"x": str(Qx), "y": str(Qy)},
        "signatures": sigs,
    }, indent=2) + "\n")
    (outdir / "flag.enc").write_bytes(ct + tag)
    return d

if __name__ == "__main__":
    flag = os.environ.get("FLAG", "H7CTF{local_test_flag}").encode()
    outdir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "handout")
    make_handout(flag, outdir)
    print(f"[gen] wrote per-instance handout to {outdir} (fresh key, flag sealed)")
