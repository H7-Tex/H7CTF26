#!/usr/bin/env python3
# VoltEye camera cloud. every device gets an RSA identity cert at manufacture and
# the cloud RSA-encrypts an admin bootstrap token to each device's key during
# provisioning. the fleet's keys were generated with a weak RNG, so some devices
# share a prime. you have the fleet's public certs and one intercepted provisioning
# payload; recover the target device's key and read the token it protects.
import os, json, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag}")
E = 65537
FLEET_SIZE = 30

def rand_prime(bits=512):
    # 512-bit primes -> weak 1024-bit device keys (on-theme for IoT). gmpy2 here,
    # pycryptodome getPrime is ~50x slower in this environment.
    return int(gmpy2.next_prime(secrets.randbits(bits) | (1 << (bits - 1))))

# build the fleet: one shared prime links the target device to a sibling; the rest
# are independent. (batch-GCD is the only feasible way to find the shared prime.)
shared_p = rand_prime()
q_target, q_sibling = rand_prime(), rand_prime()
N_target = shared_p * q_target
N_sibling = shared_p * q_sibling

def serial():
    return "VE-" + secrets.token_hex(4).upper()

cams = []
target_serial = serial()
cams.append({"serial": target_serial, "n": N_target})
cams.append({"serial": serial(), "n": N_sibling})
for _ in range(FLEET_SIZE - 2):
    cams.append({"serial": serial(), "n": rand_prime() * rand_prime()})
secrets.SystemRandom().shuffle(cams)

ADMIN_TOKEN = "vlt_" + secrets.token_hex(12)
pub = RSA.construct((N_target, E))
CAPTURED = PKCS1_v1_5.new(pub).encrypt(ADMIN_TOKEN.encode()).hex()

PAGE = """<!doctype html><meta charset=utf-8><title>VoltEye Camera Cloud</title>
<h2>VoltEye Camera Cloud</h2>
<p>Device fleet console. Admin bootstrap required.</p>
<p>API: <code>GET /fleet</code> (device certs) &middot; <code>GET /captured</code>
(one intercepted provisioning payload) &middot; <code>POST /admin {"token":"..."}</code></p>
<form onsubmit="event.preventDefault();fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({token:document.getElementById('t').value})}).then(r=>r.json()).then(j=>document.getElementById('o').textContent=JSON.stringify(j))">
<input id=t placeholder="admin bootstrap token" size=48><button>unlock</button></form>
<pre id=o></pre>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = (json.dumps(obj) + "\n").encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        p = self.path.rstrip("/")
        if p == "/fleet":
            return self._json(200, {"e": E,
                "devices": [{"serial": c["serial"], "n": str(c["n"])} for c in cams]})
        if p == "/captured":
            return self._json(200, {
                "note": "intercepted provisioning payload (RSA/PKCS1v1.5, encrypted to the device cert)",
                "serial": target_serial, "e": E, "ciphertext": CAPTURED})
        body = PAGE.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != "/admin":
            return self._json(404, {"error": "no such endpoint"})
        ln = int(self.headers.get("Content-Length", 0) or 0)
        try:
            tok = json.loads(self.rfile.read(ln) or b"{}").get("token")
        except Exception:
            tok = None
        if tok == ADMIN_TOKEN:
            return self._json(200, {"authed": True, "flag": FLAG})
        self._json(401, {"authed": False, "error": "invalid admin bootstrap token"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"[volteye] camera cloud on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
