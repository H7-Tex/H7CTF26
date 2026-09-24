import os, time, json, base64, hmac, hashlib, threading, html
from flask import Flask, request, jsonify, Response
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)

CLAIM_COOLDOWN = float(os.environ.get("KOTH_CLAIM_COOLDOWN", "3"))
ADMIN_TOKEN = os.environ.get("KOTH_ADMIN_TOKEN", "")   # engine-injected per instance; empty = dev/local (reset unauthenticated)
SELFHEAL = os.environ.get("KOTH_SELFHEAL", "").strip()  # seconds; empty/off = the engine drives resets via /koth/reset

_key = RSA.generate(2048)
PRIV = _key
PUB = _key.publickey()
PUB_PEM = PUB.export_key()

USERS = {"viewer": "viewer", "operator": "substation"}

state = {"holder": None, "since": None, "operator_name": None}
state_lock = threading.Lock()
last_claim = {}
claim_lock = threading.Lock()
buckets = {}
rl_lock = threading.Lock()


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "?")


def allow_ip(ip, rate=2.0, burst=10):
    now = time.time()
    with rl_lock:
        b = buckets.get(ip, {"t": float(burst), "ts": now})
        b["t"] = min(burst, b["t"] + (now - b["ts"]) * rate)
        b["ts"] = now
        ok = b["t"] >= 1
        if ok:
            b["t"] -= 1
        buckets[ip] = b
        return ok


def b64u(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=")


def b64ud(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(role, sub):
    hdr = {"alg": "RS256", "typ": "JWT"}
    pl = {"sub": sub, "role": role, "iat": int(time.time()), "exp": int(time.time()) + 3600}
    signing = b64u(json.dumps(hdr, separators=(",", ":")).encode()) + b"." + \
        b64u(json.dumps(pl, separators=(",", ":")).encode())
    sig = pkcs1_15.new(PRIV).sign(SHA256.new(signing))
    return (signing + b"." + b64u(sig)).decode()


def verify(tok):
    try:
        h_b64, p_b64, s_b64 = tok.split(".")
        signing = (h_b64 + "." + p_b64).encode()
        hdr = json.loads(b64ud(h_b64))
        pl = json.loads(b64ud(p_b64))
        sig = b64ud(s_b64)
        alg = hdr.get("alg")
        if alg == "RS256":
            pkcs1_15.new(PUB).verify(SHA256.new(signing), sig)
        elif alg == "HS256":
            if not hmac.compare_digest(hmac.new(PUB_PEM, signing, hashlib.sha256).digest(), sig):
                return None
        else:
            return None
        if pl.get("exp", 0) < time.time():
            return None
        return pl
    except Exception:
        return None


def bearer():
    h = request.headers.get("Authorization", "")
    return h[7:] if h.startswith("Bearer ") else ""


@app.get("/")
def index():
    with state_lock:
        holder = state["holder"]
        op = state["operator_name"]
    who = f"operator seat held by {html.escape(op)} (token {html.escape(holder[:8])}...)" if holder else "operator seat UNHELD"
    return Response(f"""<!doctype html><meta charset=utf-8><title>GridWatch</title>
<h1>GridWatch :: Substation Operator Console</h1>
<p>Feeder SS-14 / 33kV. Live SCADA operator console. Current: <b>{who}</b>.</p>
<h2>bus telemetry</h2>
<pre>see GET /api/telemetry</pre>
<h2>access</h2>
<ul>
<li>POST /api/login {{"user","pass"}} -> session token (operators get a viewer session)</li>
<li>GET  /api/operator/pubkey -> the console's token verification key</li>
<li>POST /api/operator/claim  {{"holder_token","operator_name"}} (Authorization: Bearer, admin only) -> take the operator seat</li>
<li>GET  /koth/status -> current operator seat holder</li>
</ul>""", mimetype="text/html")


@app.get("/api/telemetry")
def telemetry():
    t = time.time()
    import math
    return jsonify({
        "bus_kv": round(33.0 + 0.4 * math.sin(t / 30), 3),
        "feeder_amps": round(240 + 60 * math.sin(t / 17), 1),
        "breaker": "closed",
        "ts": int(t),
    })


@app.post("/api/login")
def login():
    if not allow_ip(client_ip()):
        return jsonify({"error": "rate limited"}), 429
    b = request.get_json(silent=True) or {}
    if USERS.get(b.get("user")) == b.get("pass"):
        return jsonify({"token": issue("viewer", b["user"])})
    return jsonify({"error": "bad credentials"}), 401


@app.get("/api/operator/pubkey")
def pubkey():
    if not allow_ip(client_ip(), rate=2.0, burst=20):
        return jsonify({"error": "rate limited"}), 429
    return Response(PUB_PEM, mimetype="text/plain")


@app.post("/api/operator/claim")
def claim():
    if not allow_ip(client_ip()):
        return jsonify({"error": "rate limited"}), 429
    pl = verify(bearer())
    if not pl or pl.get("role") != "admin":
        return jsonify({"error": "admin session required"}), 403
    b = request.get_json(silent=True) or {}
    token = b.get("holder_token")
    if not token or not isinstance(token, str) or len(token) > 128:
        return jsonify({"error": "holder_token required"}), 400
    now = time.time()
    with claim_lock:
        if now - last_claim.get(token, 0) < CLAIM_COOLDOWN:
            return jsonify({"error": "claim cooldown"}), 429
        last_claim[token] = now
    with state_lock:
        state["holder"] = token
        state["since"] = int(now)
        state["operator_name"] = str(b.get("operator_name", "unknown"))[:32]
    return jsonify({"status": "seat taken", "holder": token})


@app.get("/koth/status")
def status():
    with state_lock:
        return jsonify({"holder": state["holder"], "since": state["since"]})


def _clear_holder():
    with state_lock:
        state["holder"] = None
        state["since"] = None
        state["operator_name"] = None


@app.post("/koth/reset")
def reset():
    if ADMIN_TOKEN and bearer() != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    _clear_holder()
    return jsonify({"status": "reset"})


def self_heal(interval):
    while True:
        time.sleep(interval)
        _clear_holder()


if SELFHEAL:
    try:
        threading.Thread(target=self_heal, args=(int(SELFHEAL),), daemon=True).start()
    except ValueError:
        pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
