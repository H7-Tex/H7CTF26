import os, http.server, socketserver
from gen import make_capture
from scapy.all import wrpcap

PORT = int(os.environ.get("PORT", "8080"))
SRV = os.environ.get("SRV_DIR", "/srv/handout")
FLAG_V1 = os.environ.get("FLAG_V1", os.environ.get("FLAG", "H7CTF{ble_v1_test}"))
FLAG_V2 = os.environ.get("FLAG_V2", "H7CTF{ble_v2_test}")

os.makedirs(SRV, exist_ok=True)
wrpcap(os.path.join(SRV, "capture.pcap"), make_capture(FLAG_V1, FLAG_V2))

INDEX = """<!doctype html><meta charset=utf-8><title>ble sniff</title>
<h1>NoiseGate Buds :: BLE sniff</h1>
<p>We sniffed a pair of NoiseGate wireless earbuds coming up and talking to their
companion app over Bluetooth Low Energy. The capture is a standard BLE link-layer
recording.</p>
<ul>
<li>file: <a href="capture.pcap">capture.pcap</a> (open in Wireshark: it dissects
btle / btatt natively)</li>
</ul>
<p>There is more than one device in the air. Two secrets are in here: one the earbuds
leak in a config read, and one they only hand over after the app authenticates.</p>
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
