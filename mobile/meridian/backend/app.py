import os, time, jwt
from flask import Flask, request, jsonify, Response

FLAG_V1 = os.environ.get("FLAG_V1", os.environ.get("FLAG", "H7CTF{v1_deeplink_local}"))
FLAG_V2 = os.environ.get("FLAG_V2", "H7CTF{v2_provider_local}")
FLAG_V3 = os.environ.get("FLAG_V3", "H7CTF{v3_bola_local}")
FLAG_V4 = os.environ.get("FLAG_V4", "H7CTF{v4_massassign_local}")
JWT_SECRET = os.environ.get("MP_JWT_SECRET", "s3rv3r-s1de-hs256-secret-32byteslong!!")
CLIENT_HDR = os.environ.get("MP_CLIENT_TOKEN", "MeridianPay-Android/3.2.1 (attested)")

app = Flask(__name__)

USERS = {
    1001: {"id": 1001, "name": "Alicia Reyes", "role": "customer",
           "email": "alicia.reyes@meridianpay.io", "tier": "standard"},
}
ACCOUNTS = {
    1001: {"owner": 1001, "number": "MP-0041-8827", "type": "checking", "balance_cents": 418233,
           "memo": "personal checking"},
    1002: {"owner": 1002, "number": "MP-0001-0007", "type": "corporate-treasury",
           "balance_cents": 990425511, "memo": f"Q3 treasury reconciliation - audit note: {FLAG_V3}"},
}
LEDGER = {"generated": "2026-09-24", "corporate_master_key_rotation": FLAG_V4,
          "note": "admin-only consolidated ledger export"}


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


# Silent device auth - the app exchanges its attested client identity for a session
# JWT on first launch; there is no password. The attested client header is the app's
# (weak) integrity control.
@app.post("/api/v1/auth/device")
def auth_device():
    if request.headers.get("X-Meridian-Client", "") != CLIENT_HDR:
        return jsonify(error="client attestation required"), 403
    b = request.get_json(silent=True) or {}
    if not b.get("device_id"):
        return jsonify(error="device_id required"), 400
    return jsonify(token=issue_token(1001), user_id=1001, name=USERS[1001]["name"])


# Stage 1: internal endpoint gated on the attested client header the in-app WebView
# injects for meridian hosts -> unreachable by an ordinary browser navigation; ride
# the exported deep-link handler into the authenticated WebView.
@app.get("/api/v1/internal/promo")
def internal_promo():
    uid = auth_uid()
    if uid is None:
        return jsonify(error="missing/invalid bearer"), 401
    if request.headers.get("X-Meridian-Client", "") != CLIENT_HDR:
        return jsonify(error="endpoint restricted to the Meridian Pay app client"), 403
    return Response(
        f"<html><body><h3>Meridian Pay - Loyalty Enrollment</h3>"
        f"<p>Welcome back, member {uid}. Enrollment confirmation:</p>"
        f"<pre>{FLAG_V1}</pre></body></html>", mimetype="text/html")


# Stage 2: the app never calls this; with the session JWT stolen from the device
# (content-provider path traversal of shared_prefs/session.xml) the profile returns
# the onboarding memo.
@app.get("/api/v1/accounts/me")
def my_account():
    uid = auth_uid()
    if uid is None:
        return jsonify(error="missing/invalid bearer"), 401
    acct = next((a for a in ACCOUNTS.values() if a["owner"] == uid), None)
    return jsonify(user_id=uid, account=acct,
                   onboarding_memo=f"session verified from device - {FLAG_V2}")


# Stage 3: BOLA - statement by account id with no ownership check.
@app.get("/api/v1/accounts/<int:account_id>/statement")
def statement(account_id):
    if auth_uid() is None:
        return jsonify(error="missing/invalid bearer"), 401
    acct = ACCOUNTS.get(account_id)
    if not acct:
        return jsonify(error="no such account"), 404
    return jsonify(account_id=account_id, number=acct["number"],
                   balance_cents=acct["balance_cents"], memo=acct["memo"])


# Stage 4: mass-assignment - profile update blindly applies every field, including role.
@app.patch("/api/v1/profile")
def update_profile():
    uid = auth_uid()
    if uid is None:
        return jsonify(error="missing/invalid bearer"), 401
    user = USERS.get(uid)
    if not user:
        return jsonify(error="unknown user"), 404
    body = request.get_json(silent=True) or {}
    for k, v in body.items():
        user[k] = v
    return jsonify(updated=list(body.keys()),
                   profile={k: user.get(k) for k in ("name", "email", "tier", "role")})


@app.get("/api/v1/admin/ledger")
def admin_ledger():
    uid = auth_uid()
    if uid is None:
        return jsonify(error="missing/invalid bearer"), 401
    user = USERS.get(uid)
    if not user or user.get("role") != "admin":
        return jsonify(error="admin role required"), 403
    return jsonify(LEDGER)


@app.get("/api/v1/promo/public")
def public_promo():
    return Response("<html><body><h3>Meridian Pay - Seasonal Offers</h3>"
                    "<p>Refer a friend and earn 500 points. Terms apply.</p>"
                    "<p>Enrolled members can finish loyalty sign-up in the app: "
                    "<a href=\"/api/v1/internal/promo\">complete enrollment</a>.</p>"
                    "</body></html>", mimetype="text/html")


@app.get("/")
def root():
    return jsonify(service="Meridian Pay API", version="3.2.1")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
