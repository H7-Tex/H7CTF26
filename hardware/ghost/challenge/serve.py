#!/usr/bin/env python3
# instance entrypoint: generate this team's boot capture (with $FLAG XOR-split
# across the SPI and I2C reads) and serve it read-only over HTTP.
import os, pathlib, http.server, socketserver
from gen import make_capture, CH

SRV = pathlib.Path(os.environ.get("SRV_DIR", "/srv/handout"))
SRV.mkdir(parents=True, exist_ok=True)
(SRV / "capture.vcd").write_text(make_capture(os.environ.get("FLAG", "H7CTF{local_test}").encode()))
(SRV / "index.html").write_text(
    "<h1>NoiseGate boot capture</h1>"
    "<p>8-channel logic capture of the device boot (2 MHz). Open in PulseView / sigrok.</p>"
    "<p>Channels: " + ", ".join(CH) + "</p>"
    '<ul><li><a href="capture.vcd">capture.vcd</a></li></ul>\n')
os.chdir(SRV)
port = int(os.environ.get("PORT", "8080"))
with socketserver.TCPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler) as httpd:
    print(f"[ghost-on-the-bus] serving capture on :{port}", flush=True)
    httpd.serve_forever()
