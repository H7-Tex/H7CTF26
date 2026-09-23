#!/usr/bin/env python3
# DecryptoStat: a privacy-preserving analytics service on approximate (CKKS)
# homomorphic encryption. it decrypts ciphertexts it issued and returns the
# result. v1 returns the raw approximate decryption. v2 "hardens" it by adding
# noise flooding before returning. both leak the secret key (v2 needs averaging).
import os, json, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ckks

FLAG_V1 = os.environ.get("FLAG_V1", os.environ.get("FLAG", "H7CTF{local_v1}"))
FLAG_V2 = os.environ.get("FLAG_V2", "H7CTF{local_v2}")
SMUDGE = 4                       # v2 noise-flooding bound

S1 = ckks.keygen()               # v1 (naive) key
S2 = ckks.keygen()               # v2 (hardened) key
STORE = {}                       # id -> (version, ct)

def as_signed(v):
    return ((v + ckks.Q // 2) % ckks.Q) - ckks.Q // 2

def key_match(sub, key):
    try:
        s = [int(x) for x in sub]
    except Exception:
        return False
    return len(s) == ckks.N and all(as_signed(x % ckks.Q) == as_signed(k % ckks.Q)
                                    for x, k in zip(s, key))

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
        self._send(200, {
            "service": "DecryptoStat privacy-preserving analytics",
            "scheme": "CKKS-style approximate HE (see ckks.py): N=%d, Q=%d, DELTA=%d" % (ckks.N, ckks.Q, ckks.DELTA),
            "endpoints": {
                "POST /v1/encrypt {values}": "encrypt a length-%d vector; returns id + ciphertext (b, a)" % (ckks.N // 2),
                "POST /v1/decrypt {id}": "approximate decryption of an issued ciphertext (decoded slots)",
                "POST /v1/recover {s}": "submit the v1 secret key to claim flag 1",
                "POST /v2/encrypt {values}": "same, hardened service",
                "POST /v2/decrypt {id}": "decryption with noise flooding",
                "POST /v2/recover {s}": "submit the v2 secret key to claim flag 2",
            },
            "note": "the secret key is a length-%d ternary vector" % ckks.N})

    def _slots_json(self, slots):
        return [[c.real, c.imag] for c in slots]

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or parts[0] not in ("v1", "v2"):
            return self._send(404, {"error": "no such endpoint"})
        ver, op = parts
        s = S1 if ver == "v1" else S2
        b = self._body()
        if op == "encrypt":
            vals = b.get("values")
            if not isinstance(vals, list) or len(vals) != ckks.N // 2:
                return self._send(400, {"error": "values must be a length-%d list" % (ckks.N // 2)})
            try:
                vec = [complex(x[0], x[1]) if isinstance(x, list) else complex(x) for x in vals]
            except Exception:
                return self._send(400, {"error": "bad values"})
            ct = ckks.encrypt(vec, s)
            cid = secrets.token_hex(8); STORE[cid] = (ver, ct)
            return self._send(200, {"id": cid, "b": ct[0], "a": ct[1]})
        if op == "decrypt":
            rec = STORE.get(b.get("id"))
            if not rec or rec[0] != ver:
                return self._send(400, {"error": "unknown ciphertext id (encrypt one first)"})
            smudge = SMUDGE if ver == "v2" else 0
            return self._send(200, {"result": self._slots_json(ckks.decrypt(rec[1], s, smudge=smudge))})
        if op == "recover":
            if key_match(b.get("s", []), s):
                return self._send(200, {"ok": True, "flag": FLAG_V1 if ver == "v1" else FLAG_V2})
            return self._send(400, {"ok": False, "error": "that is not the secret key"})
        self._send(404, {"error": "no such endpoint"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"[decryptostat] analytics on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
