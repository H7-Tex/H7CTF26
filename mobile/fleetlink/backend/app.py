import os, time, hmac, hashlib
from flask import Flask, request, jsonify

FLAG = os.environ.get("FLAG", "H7CTF{fleetlink_local_test_flag}")
APP_SECRET = os.environ.get("FLEET_APP_SECRET", "fleetlink_signing_pepper_v3")
SKEW = 300

app = Flask(__name__)


def canonical(method, path, args, ts):
    q = "&".join(f"{k}={v}" for k, v in sorted(args.items()))
    return f"{method}\n{path}\n{q}\n{ts}"


def verify_sig():
    dev = request.headers.get("X-Device-Id", "")
    ts = request.headers.get("X-Ts", "")
    sig = request.headers.get("X-Sig", "")
    if not dev or not ts or not sig:
        return False, "missing signature headers"
    try:
        if abs(int(time.time()) - int(ts)) > SKEW:
            return False, "stale timestamp"
    except ValueError:
        return False, "bad timestamp"
    key = hashlib.sha256((APP_SECRET + ":" + dev).encode()).digest()
    msg = canonical(request.method, request.path, request.args.to_dict(), ts)
    expect = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return False, "bad signature"
    return True, None


@app.get("/api/v1/trips")
def trips():
    ok, err = verify_sig()
    if not ok:
        return jsonify(error=err), 401
    return jsonify(trips=[
        {"id": "T-8801", "from": "Depot 4", "to": "Pier 12", "status": "assigned"},
        {"id": "T-8802", "from": "Pier 12", "to": "Yard A", "status": "en_route"},
    ])


# fleet manifest. a valid request signature is required. the app only ever asks for its
# own scope; listing the whole fleet needs the dispatcher scope.
@app.get("/api/v1/fleet/manifest")
def manifest():
    ok, err = verify_sig()
    if not ok:
        return jsonify(error=err), 401
    scope = request.args.get("scope", "mine")
    if scope != "all":
        return jsonify(error=f"scope '{scope}' cannot list the full fleet; requires scope=all (dispatcher)"), 403
    return jsonify(scope="all", dispatcher_manifest_signing_key=FLAG)


@app.get("/")
def root():
    return jsonify(service="FleetLink API", version="4.1.0")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
