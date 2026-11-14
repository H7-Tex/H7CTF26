import os, time, jwt
from flask import Flask, request, jsonify

FLAG = os.environ.get("FLAG", "H7CTF{onyx_local_test_flag}")
JWT_SECRET = os.environ.get("ONYX_JWT_SECRET", "onyx-server-hs256-secret-32byteslong!")
CLIENT_HDR = os.environ.get("ONYX_CLIENT_TOKEN", "OnyxLocker-Android/2.4.0")

app = Flask(__name__)


def issue_token(uid):
    return jwt.encode({"sub": str(uid), "iat": int(time.time()), "exp": int(time.time()) + 86400},
                      JWT_SECRET, algorithm="HS256")


def auth_uid():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        return int(jwt.decode(h[7:], JWT_SECRET, algorithms=["HS256"])["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        return None


@app.post("/api/v1/auth/device")
def auth_device():
    if request.headers.get("X-Onyx-Client", "") != CLIENT_HDR:
        return jsonify(error="client attestation required"), 403
    b = request.get_json(silent=True) or {}
    if not b.get("device_id"):
        return jsonify(error="device_id required"), 400
    return jsonify(token=issue_token(9001), name="Priya Nair")


# the app pulls the user's vault and caches it locally; the per-team recovery code is
# the flag. the vault is returned in cleartext to the authenticated client - the bug is
# where the app then puts it.
@app.get("/api/v1/vault/sync")
def vault_sync():
    if auth_uid() is None:
        return jsonify(error="missing/invalid bearer"), 401
    return jsonify(items=[
        {"label": "Personal email", "username": "priya.nair@fastmail.example", "secret": "sunflower-canyon-7"},
        {"label": "Bank card PIN", "username": "", "secret": "4417"},
        {"label": "Router admin", "username": "admin", "secret": "Nair!home2025"},
        {"label": "Onyx account recovery code", "username": "", "secret": FLAG},
    ])


@app.get("/")
def root():
    return jsonify(service="Onyx Locker API", version="2.4.0")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
