#!/usr/bin/env python3
# Per-team instance: generate a UNIQUE tollgate binary sealing this team's injected $FLAG, serve it.
import os, subprocess, shutil, pathlib, http.server, socketserver

FLAG = os.environ.get("FLAG", "H7CTF{local_test_tollgate_dyn}")
B = "/build"; env = {**os.environ, "FLAG": FLAG}
subprocess.run(["python3", "gen.py"], cwd=B, check=True, env=env)                        # -> data.go
subprocess.run(["go", "build", "-ldflags=-s -w", "-trimpath", "-o", "tollgate", "."],
               cwd=B, check=True, env={**os.environ, "GOFLAGS": "-mod=mod", "GOCACHE": "/tmp/gocache"})

srv = pathlib.Path("/srv"); srv.mkdir(exist_ok=True)
shutil.copy(f"{B}/tollgate", srv / "tollgate")
(srv / "index.html").write_text('<h3>Toll Story</h3><p>Your binary: <a href="tollgate">tollgate</a></p>')
os.chdir(srv)

class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H) as httpd:
    print("[tollgate] serving unique binary", flush=True); httpd.serve_forever()
