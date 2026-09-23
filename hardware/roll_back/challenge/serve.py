import os, json, http.server, socketserver
from gen import make_capture
from proto import is_valid_next, FS, N_PRESSES

PORT = int(os.environ.get("PORT", "8080"))
SRV = os.environ.get("SRV_DIR", "/srv/handout")
FLAG = os.environ.get("FLAG", "H7CTF{roll_back_test}")

os.makedirs(SRV, exist_ok=True)
_iq, DEV = make_capture(FLAG)
_iq.tofile(os.path.join(SRV, "capture.cf32"))

INDEX = f"""<!doctype html><meta charset=utf-8><title>garage receiver</title>
<h1>rolling-code garage remote :: capture</h1>
<p>We recorded {N_PRESSES} button presses of a cheap "rolling code" garage remote
(433 MHz, on-off keyed). The capture is raw complex baseband.</p>
<ul>
<li>file: <a href="capture.cf32">capture.cf32</a> (interleaved float32 I/Q,
little-endian, fs = {FS} Hz)</li>
</ul>
<h2>the receiver</h2>
<p>The garage receiver ignores any code it has already seen. Work out what the remote
would transmit on its next press, and send that code:</p>
<pre>POST /unlock    body: {{"code": "&lt;12 hex digits = the 48-bit frame&gt;"}}</pre>
<p>Get it right and the door opens.</p>
"""
with open(os.path.join(SRV, "index.html"), "w") as f:
    f.write(INDEX)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=SRV, **k)

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        if self.path.rstrip("/") != "/unlock":
            self._json(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            code = int(str(body["code"]), 16)
        except Exception:
            self._json(400, {"error": "send JSON {\"code\": \"<hex>\"}"})
            return
        if is_valid_next(DEV, code):
            self._json(200, {"status": "unlocked", "flag": FLAG})
        else:
            self._json(200, {"status": "denied"})


with socketserver.TCPServer(("", PORT), H) as httpd:
    httpd.serve_forever()
