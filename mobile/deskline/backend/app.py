import os, time, jwt
from flask import Flask, request, jsonify

FLAG = os.environ.get("FLAG", "H7CTF{deskline_local_test_flag}")
JWT_SECRET = os.environ.get("DESK_JWT_SECRET", "deskline-server-hs256-secret-32bytes!")
CLIENT_HDR = os.environ.get("DESK_CLIENT_TOKEN", "Deskline-Android/1.6.0")

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
    if request.headers.get("X-Deskline-Client", "") != CLIENT_HDR:
        return jsonify(error="client attestation required"), 403
    b = request.get_json(silent=True) or {}
    if not b.get("device_id"):
        return jsonify(error="device_id required"), 400
    return jsonify(token=issue_token(7700), agent="Marcus Hale")


# the agent's console syncs their queue: public tickets plus one internal, agent-only
# credential note. the app files the internal note into a separate local table that the
# UI never shows.
@app.get("/api/v1/sync")
def sync():
    if auth_uid() is None:
        return jsonify(error="missing/invalid bearer"), 401
    return jsonify(
        tickets=[
            {"subject": "Cannot reset password", "body": "Customer locked out after 3 tries."},
            {"subject": "Refund not received", "body": "Order #55120, refund pending 8 days."},
            {"subject": "App crashes on upload", "body": "Repro: attach >10MB photo, force close."},
            {"subject": "Change billing email", "body": "Requests move to new corporate domain."},
        ],
        internal={"label": "vault-unseal-code", "value": FLAG},
    )


@app.get("/")
def root():
    return jsonify(service="Deskline Agent API", version="1.6.0")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
