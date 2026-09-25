#!/usr/bin/env python3
# Per-team instance: generate a UNIQUE cipherlock binary sealing this team's injected $FLAG, serve it.
import os, subprocess, shutil, pathlib, http.server, socketserver

FLAG = os.environ.get("FLAG", "H7CTF{local_test_cipherlock_dyn}")
B = "/build"; env = {**os.environ, "FLAG": FLAG}
subprocess.run(["python3", "gen.py"], cwd=B, check=True, env=env)              # -> cipherlock_data.h
subprocess.run(["gcc", "cipherlock.c", "-o", "cipherlock", "-lcrypto", "-Os", "-s"], cwd=B, check=True)

srv = pathlib.Path("/srv"); srv.mkdir(exist_ok=True)
shutil.copy(f"{B}/cipherlock", srv / "cipherlock")
(srv / "index.html").write_text('<h3>Constraint Yourself</h3><p>Your binary: <a href="cipherlock">cipherlock</a></p>')
os.chdir(srv)

class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H) as httpd:
    print("[cipherlock] serving unique binary", flush=True); httpd.serve_forever()
