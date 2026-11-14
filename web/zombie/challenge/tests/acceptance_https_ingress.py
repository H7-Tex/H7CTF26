"""Exercise the player-owned Service Worker solve through a TLS ingress."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent
REPOSITORY = CHALLENGE.parent
SOLVER = REPOSITORY / "solution" / "solve.py"
FLAG_PATTERN = re.compile(r"H7CTF\{[^}\r\n]*\}")


def redact(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return FLAG_PATTERN.sub("H7CTF{<redacted>}", value or "")


def write_evidence(path: str, evidence: dict[str, object]) -> None:
    serialized = json.dumps(evidence, indent=2) + "\n"
    if FLAG_PATTERN.search(serialized):
        raise RuntimeError("refusing to write flag-shaped data to ingress evidence")
    Path(path).write_text(serialized, encoding="utf-8")


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_solver(origin: str, *, cert_spki: str | None = None, timeout: int = 120) -> str:
    args = [sys.executable, str(SOLVER), "--url", origin, "--timeout", str(timeout)]
    if cert_spki:
        args.extend(["--ignore-cert-spki", cert_spki])
    result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f"browser solve failed:\n{redact(result.stdout)[-4000:]}\n{redact(result.stderr)[-3000:]}")
    required = ("player's fresh profile established active/controller=legacy before rollout",
                "genuine browser skew", "deliberate MessageChannel replay",
                "ordinary report export returned exactly one runtime flag")
    missing = [phrase for phrase in required if phrase not in result.stdout]
    if missing or "final flag: H7CTF{" not in result.stdout:
        raise RuntimeError(f"reference solve did not prove the player lifecycle and export flow; missing={missing}; output={redact(result.stdout)[-4000:]}")
    return result.stdout


def test_public_https_origin(origin: str) -> dict[str, object]:
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("public origin must use HTTPS")
    origin = f"https://{parsed.netloc}"
    with urlopen(origin + "/__release/manifest.json", timeout=15) as response:
        cookie = response.headers.get("Set-Cookie", "")
        if response.status != 200 or "relay_session=" not in cookie or "secure" not in cookie.lower() or "httponly" not in cookie.lower():
            raise RuntimeError("public ingress lacks the Secure HttpOnly Relay session cookie")
    output = run_solver(origin)
    evidence = {"origin": origin, "https": True, "secure_http_only_cookie": True,
                "player_owned_lifecycle": True, "stale_worker_replay": True, "final_export": True}
    print(f"[PASS] public HTTPS origin: {origin}")
    print("[PASS] certificate validation, Secure HttpOnly cookie, and player-owned legacy-to-current lifecycle")
    print("[PASS] player's stale worker replayed its own queued operation; normal export completed")
    print(redact(output))
    return evidence


def make_local_certificate(directory: str) -> tuple[Path, Path, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path, cert_path = (Path(directory) / filename for filename in ("localhost-key.pem", "localhost-cert.pem"))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert_path, key_path, base64.b64encode(hashlib.sha256(spki).digest()).decode()


def run_local_tls_ingress(evidence_path: str | None = None) -> None:
    project = f"zwhttps{secrets.token_hex(5)}"
    backend_port, ingress_port = unused_port(), unused_port()
    runtime_flag = f"H7CTF{{https-{secrets.token_hex(16)}}}"
    internal_token = secrets.token_hex(32)
    env = dict(os.environ, FLAG=runtime_flag, EXPORTER_TOKEN=internal_token,
               RELAY_HOST_PORT=str(backend_port), DISPATCH_COLLECTION_SECONDS="5", DISPATCH_COOLDOWN_SECONDS="2")
    for name in ("OPS_TOKEN", "BUILD_SHA", "LEGACY_BUILD_SHA"):
        env.pop(name, None)

    def compose(*args: str, check: bool = True):
        result = subprocess.run(
            ["docker", "compose", "-p", project, "-f", str(CHALLENGE / "docker-compose.yml"), *args],
            cwd=CHALLENGE, env=env, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, timeout=300,
        )
        return result

    observed: list[dict[str, object]] = []
    proxy = None
    thread = None

    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return

        def _proxy(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else None
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in {"connection", "transfer-encoding"}}
            headers["X-Forwarded-Proto"] = "https"
            headers["Connection"] = "close"
            upstream = http.client.HTTPConnection("127.0.0.1", backend_port, timeout=30)
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                response = upstream.getresponse()
                payload = response.read()
                response_headers = response.getheaders()
                observed.append({"path": self.path.split("?", 1)[0], "host": headers.get("Host", ""),
                                 "forwarded_proto": "https", "status": response.status,
                                 "relay_cookie": "relay_session=" in self.headers.get("Cookie", ""),
                                 "method": self.command})
                self.send_response(response.status)
                for key, value in response_headers:
                    if key.lower() in {"connection", "transfer-encoding", "content-length"}:
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
                self.close_connection = True
            finally:
                upstream.close()

        do_GET = _proxy
        do_POST = _proxy
        do_PUT = _proxy
        do_HEAD = _proxy

    class TLSServer(ThreadingHTTPServer):
        daemon_threads = True

    failed = False
    try:
        compose("up", "--build", "--detach")
        relay = f"http://127.0.0.1:{backend_port}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if httpx.get(relay + "/api/meta", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.5)
        else:
            raise AssertionError("Relay container did not become ready")

        with tempfile.TemporaryDirectory(prefix="relay-tls-") as tls_dir:
            cert, key, pin = make_local_certificate(tls_dir)
            proxy = TLSServer(("127.0.0.1", ingress_port), ProxyHandler)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            origin = f"https://localhost:{ingress_port}"
            output = run_solver(origin, cert_spki=pin)
            host = f"localhost:{ingress_port}"
            assert all(item["host"] == host and item["forwarded_proto"] == "https" for item in observed)
            pref = [item for item in observed if item["path"] == "/api/jobs/JOB-3887/report-preference"]
            export = [item for item in observed if "/api/jobs/JOB-3887/exports" in item["path"]]
            assert any(item["method"] == "PUT" and item["relay_cookie"] for item in pref), pref
            assert any(item["relay_cookie"] for item in export), export
            assert any(item["path"] == "/api/sync/worker-key" for item in observed)
            assert any(item["path"] == "/api/sync/outbox" for item in observed)
            assert any(item["path"] == "/api/sync/replay" for item in observed)
            logs = compose("logs", "--no-color", "relay").stdout
            assert runtime_flag not in logs
            evidence = {"origin": origin, "tls_terminated_at_ingress": True, "forwarded_host": host,
                        "x_forwarded_proto": "https", "secure_cookie": True,
                        "player_v1_install": True, "player_v2_frontend_api": True,
                        "legacy_controller_current_waiting": True, "signed_outbox_replay": True,
                        "preference_edit": True, "export_retrieved": True}
            if evidence_path:
                write_evidence(evidence_path, evidence)
            print("[PASS] local TLS ingress preserved the original Host and forwarded X-Forwarded-Proto=https")
            print("[PASS] public browser sent its Secure HttpOnly session cookie on same-origin preference/export requests")
            print("[PASS] same-origin HTTPS path carried worker-key enrollment, outbox staging, and replay requests")
            print("[PASS] HTTPS player flow retrieved final commissioning attachment")
            print(redact(output))
    except Exception:
        failed = True
        raise
    finally:
        if proxy:
            proxy.shutdown()
            proxy.server_close()
        if thread:
            thread.join(timeout=2)
        down = compose("down", "--rmi", "local", "--volumes", "--remove-orphans", check=False)
        if down.returncode:
            print(down.stdout, file=sys.stderr)
        if failed:
            print(compose("logs", "--no-color", check=False).stdout[-8000:], file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", action="append", help="fresh deployed Anvil HTTPS origin")
    parser.add_argument("--local-tls", action="store_true", help="run the complete solve through local TLS termination")
    parser.add_argument("--evidence", help="write redacted JSON evidence")
    args = parser.parse_args()
    if args.url:
        if len(set(args.url)) != len(args.url):
            parser.error("each --url must identify a distinct fresh instance")
        values = [test_public_https_origin(url) for url in args.url]
        evidence = {"fresh_instances": values}
        if args.evidence:
            write_evidence(args.evidence, evidence)
    elif args.local_tls:
        run_local_tls_ingress(args.evidence)
    else:
        parser.error("provide --url https://<Anvil-instance> or --local-tls")


if __name__ == "__main__":
    main()
