#!/usr/bin/env python3
# instance entrypoint: generate this team's handout (sealing the injected $FLAG),
# then serve it read-only over HTTP for download.
import os, pathlib, http.server, socketserver
from gen import make_handout

SRV = pathlib.Path(os.environ.get("SRV_DIR", "/srv/handout"))
make_handout(os.environ.get("FLAG", "H7CTF{local_test_flag}").encode(), SRV)
(SRV / "index.html").write_text(
    "<h1>Aurum treasury signer</h1>"
    "<p>Recovered approvals for offline review:</p><ul>"
    '<li><a href="signatures.json">signatures.json</a></li>'
    '<li><a href="flag.enc">flag.enc</a></li></ul>\n"'
)
os.chdir(SRV)
port = int(os.environ.get("PORT", "8080"))
with socketserver.TCPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler) as httpd:
    print(f"[serve] polynonce handout on :{port}", flush=True)
    httpd.serve_forever()
