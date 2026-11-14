import os, http.server, socketserver
from gen import make_capture

PORT = int(os.environ.get("PORT", "8080"))
SRV = os.environ.get("SRV_DIR", "/srv/handout")
FLAG = os.environ.get("FLAG", "H7CTF{zero_day_highway_test}")

os.makedirs(SRV, exist_ok=True)
with open(os.path.join(SRV, "capture.log"), "w") as f:
    f.write(make_capture(FLAG))

INDEX = """<!doctype html><meta charset=utf-8><title>can capture</title>
<h1>Zero-Day Highway :: CAN bus capture</h1>
<p>We tapped the CAN bus of a connected vehicle through its OBD-II port during a
service session. Most of the traffic is routine powertrain chatter, but a diagnostic
tool was talking to an ECU at the same time, and the ECU handed back something it
should not have.</p>
<ul>
<li>file: <a href="capture.log">capture.log</a> (SocketCAN candump log:
<code>(timestamp) can0 ID#DATA</code>)</li>
</ul>
<p>Read it with candump/can-utils, Wireshark (SocketCAN), or python-can. Recover what
the ECU leaked.</p>
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
