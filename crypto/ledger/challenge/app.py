#!/usr/bin/env python3
# the aurum treasury signer. signs arbitrary approvals over secp256k1 with a
# per-instance secret key; nonces come from a secret LCG k_{i+1}=a*k_i+c (mod n).
# it will not sign an ADMIN_TRANSFER. recover the key from the signatures it
# hands out, forge the admin approval yourself, and it releases the flag.
import os, json, hashlib, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

G = SECP256k1.generator
n = int(SECP256k1.order)
CURVE = SECP256k1.curve

FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag}")
ADMIN_MSG = "ADMIN_TRANSFER 1000000 BTC -> 0x0000dead"

def _rand():
    return secrets.randbelow(n - 1) + 1

D = _rand()                      # signing key (secret)
Q = D * G
QX, QY = int(Q.x()), int(Q.y())
A, C = _rand(), _rand()          # secret LCG multiplier / increment
K = _rand()                      # current nonce state

def z_of(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")

def sign(msg):
    global K
    while True:
        r = int((K * G).x()) % n
        s = (pow(K, -1, n) * (z_of(msg) + r * D)) % n
        K = (A * K + C) % n
        if r and s:
            return r, s

def verify(msg, r, s):
    if not (0 < r < n and 0 < s < n):
        return False
    z = z_of(msg)
    w = pow(s, -1, n)
    u1, u2 = (z * w) % n, (r * w) % n
    P = u1 * G + u2 * Point(CURVE, QX, QY)
    if P is None:
        return False
    return int(P.x()) % n == r

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, obj):
        body = (json.dumps(obj) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/pubkey") and self.path != "/":
            return self._send(200, {"curve": "secp256k1", "x": str(QX), "y": str(QY)})
        self._send(200, {
            "service": "Aurum treasury signer",
            "curve": "secp256k1",
            "pubkey": {"x": str(QX), "y": str(QY)},
            "endpoints": {
                "GET /pubkey": "signer public key",
                "POST /sign {msg}": "sign an approval (ADMIN_TRANSFER refused)",
                "POST /forge {msg,r,s}": "submit a signature; a valid ADMIN_TRANSFER releases the flag",
            },
            "admin_msg": ADMIN_MSG,
            "note": "z = int(sha256(msg)); nonces are a deterministic chain, not random",
        })

    def do_POST(self):
        p = self.path.rstrip("/")
        b = self._body()
        if p == "/sign":
            msg = b.get("msg")
            if not isinstance(msg, str):
                return self._send(400, {"error": "send {\"msg\": \"...\"}"})
            if msg.startswith("ADMIN_TRANSFER"):
                return self._send(403, {"error": "the signer refuses to authorize ADMIN_TRANSFER"})
            r, s = sign(msg)
            return self._send(200, {"msg": msg, "r": str(r), "s": str(s)})
        if p == "/forge":
            try:
                msg, r, s = b["msg"], int(b["r"]), int(b["s"])
            except Exception:
                return self._send(400, {"error": "send {\"msg\":\"...\",\"r\":\"...\",\"s\":\"...\"}"})
            if msg != ADMIN_MSG:
                return self._send(400, {"error": f"only a signed {ADMIN_MSG!r} releases the flag"})
            if verify(msg, r, s):
                return self._send(200, {"ok": True, "flag": FLAG})
            return self._send(400, {"ok": False, "error": "invalid signature"})
        self._send(404, {"error": "no such endpoint"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"[signer] listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
