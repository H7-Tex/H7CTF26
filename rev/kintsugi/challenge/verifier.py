import os
import secrets
import collections

from flask import Flask, request, Response, send_file
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag_0000}")
PUBKEY_PATH = os.environ.get("PUBKEY_PATH", "/srv/kintsugi/handout/pubkey.bin")
HANDOUT_PATH = os.environ.get("HANDOUT_PATH", "/srv/kintsugi/handout.tar.gz")
MAX_NONCES = 4096

app = Flask(__name__)
verify_key = VerifyKey(open(PUBKEY_PATH, "rb").read())
live = collections.OrderedDict()


def issue():
    n = secrets.token_hex(24)
    live[n] = True
    while len(live) > MAX_NONCES:
        live.popitem(last=False)
    return n


@app.get("/attest")
def get_nonce():
    return Response(issue() + "\n", mimetype="text/plain")


@app.post("/attest")
def check():
    nonce = request.form.get("nonce", "")
    sig = request.form.get("sig", "")
    if nonce not in live:
        return Response("attestation incomplete\n", status=400, mimetype="text/plain")
    del live[nonce]
    try:
        verify_key.verify(bytes.fromhex(nonce), bytes.fromhex(sig))
    except (BadSignatureError, ValueError):
        return Response("attestation incomplete\n", status=400, mimetype="text/plain")
    return Response(FLAG + "\n", mimetype="text/plain")


@app.get("/handout.tar.gz")
def handout():
    return send_file(HANDOUT_PATH, mimetype="application/gzip")


@app.get("/")
def index():
    return Response("kintsugi vault re-attestation endpoint\nGET /attest for a nonce, POST nonce+sig\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
