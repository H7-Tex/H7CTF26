import os, http.server, socketserver
from gen import make_capture, FS

PORT = int(os.environ.get("PORT", "8080"))
SRV = os.environ.get("SRV_DIR", "/srv/handout")
FLAG = os.environ.get("FLAG", "H7CTF{signal_unknown_test}")

os.makedirs(SRV, exist_ok=True)
make_capture(FLAG).tofile(os.path.join(SRV, "capture.cf32"))

INDEX = f"""<!doctype html><meta charset=utf-8><title>field capture</title>
<h1>unknown transmission :: field capture</h1>
<p>One burst, pulled off the air near a device we could not identify. No datasheet,
no protocol notes. Whatever it says is in here.</p>
<ul>
<li>file: <a href="capture.cf32">capture.cf32</a> (complex baseband, interleaved
float32 I/Q, little-endian: I0 Q0 I1 Q1 ...)</li>
<li>sample rate: {FS} Hz</li>
</ul>
<p>Recover the message.</p>
"""
with open(os.path.join(SRV, "index.html"), "w") as f:
    f.write(INDEX)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=SRV, **k)

    def log_message(self, *a):
        pass


with socketserver.TCPServer(("", PORT), H) as httpd:
    httpd.serve_forever()
