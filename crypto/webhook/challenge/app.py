#!/usr/bin/env python3
# orionpay merchant webhook receiver. the payment provider signs each webhook as
# X-Signature = SHA256(secret || body). a webhook that grants role=owner triggers
# an owner-only payout (the flag). you have one captured legitimate webhook; the
# secret is not known. /v2 uses HMAC and is the decoy.
import os, json, hashlib, hmac, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag}")
SECRET = secrets.token_bytes(secrets.choice(range(10, 21)))   # per-instance, length unknown to player
SAMPLE = b"event=payment.succeeded&amount=500&currency=usd&customer=cus_9f2a&role=guest"

def sig_v1(body: bytes) -> str:
    return hashlib.sha256(SECRET + body).hexdigest()

def sig_v2(body: bytes) -> str:
    return hmac.new(SECRET, body, hashlib.sha256).hexdigest()

def parse(body: bytes) -> dict:
    out = {}
    for part in body.split(b"&"):
        k, _, v = part.partition(b"=")
        out[k.decode("latin-1")] = v.decode("latin-1")   # last-value-wins
    return out

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, obj):
        b = (json.dumps(obj) + "\n").encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path.rstrip("/") == "/sample":
            return self._send(200, {
                "note": "captured production webhook (as delivered to /webhook)",
                "signing": "X-Signature: SHA256(secret || body)",
                "body": SAMPLE.decode(), "X-Signature": sig_v1(SAMPLE)})
        self._send(200, {
            "service": "OrionPay webhook receiver",
            "endpoints": {
                "GET /sample": "a captured legitimate webhook (body + signature)",
                "POST /webhook": "process a webhook; body raw, header X-Signature = SHA256(secret||body); role=owner pays out",
                "POST /v2/webhook": "next-gen signing (HMAC-SHA256)"},
            "hint": "an owner-role payout releases the flag"})

    def do_POST(self):
        p = self.path.rstrip("/")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        given = self.headers.get("X-Signature", "")
        if p == "/webhook":
            ok = hmac.compare_digest(given, sig_v1(body))
        elif p == "/v2/webhook":
            ok = hmac.compare_digest(given, sig_v2(body))
        else:
            return self._send(404, {"error": "no such endpoint"})
        if not ok:
            return self._send(401, {"error": "bad signature"})
        params = parse(body)
        if params.get("role") == "owner":
            return self._send(200, {"ok": True, "payout": "authorized", "flag": FLAG})
        return self._send(200, {"ok": True, "role": params.get("role", "guest"), "note": "no owner payout"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"[orionpay] webhook receiver on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
