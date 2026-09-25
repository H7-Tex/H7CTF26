#!/usr/bin/env python3
# Per-team instance: generate a UNIQUE interlock binary sealing this team's injected $FLAG, then
# serve it for download. The flag is per-team (H7CTF{uuid}), so a shared flag string is useless.
import os, subprocess, shutil, pathlib, http.server, socketserver

FLAG = os.environ.get("FLAG", "H7CTF{local_test_interlock_dyn}")
B = "/build"
env = {**os.environ, "FLAG": FLAG}
subprocess.run(["python3", "gen.py"], cwd=B, check=True, env=env)                 # -> interlock_data.h
subprocess.run(["gcc", "interlock.c", "-o", "interlock", "-lcrypto", "-Os", "-s"], cwd=B, check=True)

srv = pathlib.Path("/srv"); srv.mkdir(exist_ok=True)
shutil.copy(f"{B}/interlock", srv / "interlock")
(srv / "index.html").write_text(
    '<h3>Interlock</h3><p>Your challenge binary: <a href="interlock">interlock</a></p>')
os.chdir(srv)

class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

socketserver.TCPServer.allow_reuse_address = True
port = int(os.environ.get("PORT", "8080"))
with socketserver.TCPServer(("0.0.0.0", port), H) as httpd:
    print(f"[interlock] serving unique binary on :{port}", flush=True)
    httpd.serve_forever()
