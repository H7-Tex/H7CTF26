#!/usr/bin/env python3
# Sparrow Freight "prod" — the production host for the prod-app service.
#
# It runs the current prod-app:latest as a managed sibling container and serves it
# to the world (reverse-proxy on the exposed port). Redeploys happen ONLY via a
# signed webhook: POST /deploy with X-Hub-Signature-256 = sha256=HMAC-SHA256(body,
# WEBHOOK_SECRET). Legit deploys come from the pipeline; an attacker who has looted
# WEBHOOK_SECRET (from the CI build env) can forge one and ship a backdoored :latest.
#
# The deployed container is UNPRIVILEGED and gets no docker socket — the only thing
# it receives that the attacker didn't already have is the production runtime config
# injected here (FLAG3 + a token with write access to the prod-app repo, the stage-4
# pivot). That's the point of reaching prod.
#
# Pulls from the insecure (http) registry with crane, then docker-load + run, so the
# host daemon needs no insecure-registries config.

import hashlib
import hmac
import os
import subprocess
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REGISTRY = os.environ.get("REGISTRY", "registry:5000")
IMAGE = os.environ.get("IMAGE", "prod-app:latest")
REF = f"{REGISTRY}/{IMAGE}"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "changeme").encode()
FLAG3 = os.environ.get("FLAG3", "H7CTF{placeholder_flag3}")
PROD_APP_WRITE_TOKEN = os.environ.get("PROD_APP_WRITE_TOKEN", "")
NET = os.environ.get("CI_NETWORK", "freightpipe-ci")
LIVE = os.environ.get("LIVE_NAME", "prod-app-live")
PORT = int(os.environ.get("PROD_PORT", "9000"))


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)


def deploy():
    r = sh("crane", "pull", "--insecure", REF, "/tmp/img.tar")
    if r.returncode != 0:
        return False, "pull failed: " + r.stderr
    if sh("docker", "load", "-i", "/tmp/img.tar").returncode != 0:
        return False, "load failed"
    sh("docker", "rm", "-f", LIVE)
    r = sh("docker", "run", "-d", "--name", LIVE, "--network", NET, "--restart", "no",
           "-e", "FLAG3=" + FLAG3,
           "-e", "PROD_APP_WRITE_TOKEN=" + PROD_APP_WRITE_TOKEN,
           REF)
    return (r.returncode == 0), (r.stdout + r.stderr).strip()


def proxy(method, path, body):
    try:
        req = urllib.request.Request("http://%s:8080%s" % (LIVE, path),
                                     data=body if body else None, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 502, ("prod-app upstream unavailable: %s\n" % e).encode()


class H(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        if self.path.split("?")[0] == "/deploy":
            body = self._read_body()
            sig = self.headers.get("X-Hub-Signature-256", "")
            expect = "sha256=" + hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expect):
                return self._send(403, b"invalid webhook signature\n")
            ok, out = deploy()
            return self._send(200 if ok else 500,
                              (b"deployed prod-app:latest\n" if ok else out.encode() + b"\n"))
        code, body = proxy("POST", self.path, self._read_body())
        self._send(code, body)

    def do_GET(self):
        code, body = proxy("GET", self.path, None)
        self._send(code, body)

    def log_message(self, *a):
        pass


def initial_deploy():
    for _ in range(60):
        ok, out = deploy()
        if ok:
            print("[prod] initial deploy ok", flush=True)
            return
        print("[prod] waiting for registry image...", out[:120], flush=True)
        time.sleep(3)
    print("[prod] initial deploy failed", flush=True)


if __name__ == "__main__":
    initial_deploy()
    print("[prod] serving on", PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
