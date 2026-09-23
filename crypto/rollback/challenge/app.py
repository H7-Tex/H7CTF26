#!/usr/bin/env python3
# Helios firmware code-signing notary + device update endpoint. firmware is signed
# with an LMS/WOTS+ hash-based scheme (see lms.py). each one-time leaf must sign
# exactly once; a maintenance "rollback" resets the signing counter (the bug),
# which lets a leaf be reused. the device boots any firmware that verifies against
# its burned-in root. sign benign builds only; a backdoored build is refused.
import os, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import lms

FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag}")
MARKER = "BACKDOOR"                      # a build carrying this is malicious

_rng = lambda k: secrets.token_bytes(k)
SIGNER = lms.Signer(_rng)
ROOT = SIGNER.root
LOCK = threading.Lock()

def enc_sig(sig):
    return {"leaf": sig["leaf"], "wots": [w.hex() for w in sig["wots"]],
            "path": [p.hex() for p in sig["path"]]}

def dec_sig(o):
    return {"leaf": int(o["leaf"]), "wots": [bytes.fromhex(w) for w in o["wots"]],
            "path": [bytes.fromhex(p) for p in o["path"]]}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, obj):
        b = (json.dumps(obj) + "\n").encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _body(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path.rstrip("/") == "/root":
            return self._send(200, {"root": ROOT.hex(), "tree_height": lms.TREE_H,
                                    "w": lms.W, "len": lms.LEN, "hash": "sha256"})
        self._send(200, {
            "service": "Helios firmware notary",
            "root": ROOT.hex(),
            "scheme": "LMS/WOTS+ (see lms.py); each leaf signs once",
            "endpoints": {
                "GET /root": "device trust anchor (Merkle root)",
                "POST /sign {firmware}": "notarize a benign firmware build (backdoored builds refused)",
                "POST /rollback": "maintenance: revert the signing counter",
                "POST /deploy {firmware, sig}": "device update; boots any firmware that verifies against the root",
            },
            "note": f"a build containing {MARKER!r} will not be signed"})

    def do_POST(self):
        p = self.path.rstrip("/")
        b = self._body()
        if p == "/rollback":
            with LOCK:
                SIGNER.ctr = 0
            return self._send(200, {"ok": True, "note": "signing counter reset to 0"})
        if p == "/sign":
            fw = b.get("firmware")
            if not isinstance(fw, str):
                return self._send(400, {"error": "send {\"firmware\": \"...\"}"})
            if MARKER in fw:
                return self._send(403, {"error": "refusing to sign a backdoored build"})
            with LOCK:
                if SIGNER.ctr >= (1 << lms.TREE_H):
                    return self._send(429, {"error": "all one-time leaves used; rollback to recover"})
                sig = SIGNER.sign(fw.encode())
            return self._send(200, {"firmware": fw, "sig": enc_sig(sig)})
        if p == "/deploy":
            try:
                fw = b["firmware"]; sig = dec_sig(b["sig"])
            except Exception:
                return self._send(400, {"error": "send {\"firmware\":\"...\",\"sig\":{leaf,wots,path}}"})
            if not lms.verify(fw.encode(), sig, ROOT):
                return self._send(400, {"ok": False, "error": "signature does not verify against the device root"})
            if MARKER in fw:
                return self._send(200, {"ok": True, "booted": True, "flag": FLAG})
            return self._send(200, {"ok": True, "booted": True, "note": "benign firmware deployed"})
        self._send(404, {"error": "no such endpoint"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"[helios] firmware notary on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
