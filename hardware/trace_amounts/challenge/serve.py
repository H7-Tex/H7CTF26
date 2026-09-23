import os, http.server, socketserver
import numpy as np
from gen import make_challenge

PORT = int(os.environ.get("PORT", "8080"))
SRV = os.environ.get("SRV_DIR", "/srv/handout")
FLAG = os.environ.get("FLAG", "H7CTF{trace_amounts_test}")

os.makedirs(SRV, exist_ok=True)
traces, pts, _key, ct = make_challenge(FLAG)
np.save(os.path.join(SRV, "traces.npy"), traces)
np.save(os.path.join(SRV, "plaintexts.npy"), pts)
with open(os.path.join(SRV, "secret.enc"), "wb") as f:
    f.write(ct)

INDEX = f"""<!doctype html><meta charset=utf-8><title>power capture</title>
<h1>Trace Amounts :: smart-card power capture</h1>
<p>A contactless payment card runs AES-128 to authorize each tap. We sat a current
probe on its power line and captured {traces.shape[0]} authorizations, logging the power
trace and the (known) challenge plaintext for each. The card never reveals its key. It
does not have to.</p>
<ul>
<li><a href="traces.npy">traces.npy</a> : float32 array, {traces.shape[0]} x {traces.shape[1]} (one power trace per authorization)</li>
<li><a href="plaintexts.npy">plaintexts.npy</a> : uint8 array, {traces.shape[0]} x 16 (the plaintext for each trace)</li>
<li><a href="secret.enc">secret.enc</a> : a secret the card encrypted with its AES-128 key (ECB)</li>
</ul>
<p>Recover the key and decrypt the secret.</p>
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
