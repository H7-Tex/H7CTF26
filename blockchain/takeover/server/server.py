#!/usr/bin/env python3
# HOSTILE TAKEOVER KotH bridge. The shared Anvil node is never exposed; this is the only
# reachable service. Teams submit exploit transactions through a per-team-token JSON-RPC
# proxy (auth + rate-limit + attribution); the KotH engine polls /koth/status. Round resets
# rotate the governor epoch and clear the seat.
import os, time, json, subprocess, threading, urllib.request
from flask import Flask, request, jsonify, Response

RPC = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8545")
SYS_KEY = os.environ.get("SYS_KEY", "")
ADMIN_TOKEN = os.environ.get("KOTH_ADMIN_TOKEN", "")
THRONE = os.environ["THRONE_ADDR"]
GOVERNOR = os.environ["GOVERNOR_ADDR"]
TOKEN = os.environ["TOKEN_ADDR"]
LENDER = os.environ["LENDER_ADDR"]

app = Flask(__name__)

# JSON-RPC method allowlist: reads + raw tx submission only. no signing/admin on the node.
ALLOW = {"eth_chainId", "eth_blockNumber", "eth_call", "eth_estimateGas", "eth_gasPrice",
         "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getLogs",
         "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getTransactionCount",
         "eth_sendRawTransaction", "eth_getBlockByNumber", "eth_getBlockByHash",
         "eth_feeHistory", "eth_maxPriorityFeePerGas", "net_version", "web3_clientVersion"}

buckets, rl_lock = {}, threading.Lock()


def allow_rate(key, rate=5.0, burst=40):
    now = time.time()
    with rl_lock:
        b = buckets.get(key, {"t": float(burst), "ts": now})
        b["t"] = min(burst, b["t"] + (now - b["ts"]) * rate)
        b["ts"] = now
        ok = b["t"] >= 1
        if ok:
            b["t"] -= 1
        buckets[key] = b
        return ok


def cast_call(addr, sig, *args):
    out = subprocess.run(["cast", "call", addr, sig, *map(str, args), "--rpc-url", RPC],
                         capture_output=True, text=True, timeout=10)
    return out.stdout.strip()


def cast_send(addr, sig, *args):
    r = subprocess.run(["cast", "send", addr, sig, *map(str, args),
                        "--rpc-url", RPC, "--private-key", SYS_KEY],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        app.logger.error("cast send %s %s failed: %s", addr, sig, r.stderr.strip()[:200])
    return r.returncode == 0


def rpc_forward(body):
    req = urllib.request.Request(RPC, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())


VERIFY_URL = os.environ.get("KOTH_VERIFY_URL", "")   # POST {token, rpc_secret} -> {valid, public_tag}
REQUIRE_SECRET = os.environ.get("KOTH_REQUIRE_SECRET", "").lower() in ("1", "true", "yes")


def client_ip():
    # behind Cloudflare + the ingress; trust the edge-set client-IP headers, fall back to the peer.
    return (request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "?")


def authorize(tok, secret):
    # Returns (ok, reason). The buy-in token is the PUBLIC crown tag -- it shows up in /koth/status
    # -- so it can't gate writes on its own: a rival could harvest it and grief your RPC. The
    # platform issues a private per-team rpc_secret at buy-in; every write must carry it
    # (X-Koth-Secret). We verify {token, rpc_secret} with the engine and require the verified public
    # tag to match the path token, so a session can only ever act as its own team.
    if not tok or len(tok) > 128:
        return False, "invalid koth token"
    if not VERIFY_URL:
        # off-platform (local/dev): no secret plumbing. allow a sane token unless a secret is forced.
        return (True, "") if not REQUIRE_SECRET else ((True, "") if secret else (False, "missing rpc secret"))
    if not secret or len(secret) > 256:
        return False, "missing or invalid rpc secret"
    try:
        req = urllib.request.Request(
            VERIFY_URL, data=json.dumps({"token": tok, "rpc_secret": secret}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        d = json.loads(urllib.request.urlopen(req, timeout=4).read())
    except Exception:
        return False, "verify unavailable"
    if not d.get("valid") or d.get("public_tag") != tok:
        return False, "rpc secret rejected"
    return True, ""


@app.get("/")
def index():
    return Response(
        "<h1>GENESIS DAO :: hostile-takeover arena (King of the Hill)</h1>"
        "<p>The treasury is controlled by one Guardian seat (the Throne's <code>king</code>). "
        "Stage a governance takeover to seat your team, and hold it.</p>"
        "<ul>"
        "<li>GET  /koth/info -> chainId, contract addresses, current governor epoch</li>"
        "<li>POST /rpc/&lt;your-koth-token&gt; -> JSON-RPC to the arena (send your exploit txns here)</li>"
        "<li>GET  /koth/status -> the current Guardian (holder)</li>"
        "</ul>", mimetype="text/html")


@app.get("/koth/info")
def info():
    return jsonify({
        "chain_id": 31337,
        "rpc": "POST /rpc/<your-koth-token>",
        "contracts": {"token": TOKEN, "flashLender": LENDER, "governor": GOVERNOR, "throne": THRONE},
        "epoch": cast_call(GOVERNOR, "epochNonce()(uint256)").split()[0],
        "note": "voting power is read live at castVote; there is no timelock; execute is bound to the epoch you proposed in (re-read the epoch each round).",
    })


@app.post("/rpc/<token>")
def rpc(token):
    ok, reason = authorize(token, request.headers.get("X-Koth-Secret", ""))
    if not ok:
        return jsonify({"error": reason}), 403
    ip = client_ip()
    # rate-limit per (token, source IP): a rival submitting under a harvested token drains only its
    # own bucket, never the owner's ability to re-seize. The owner's (token, own-IP) bucket is
    # untouchable without knowing their IP, so targeted rate-exhaustion grief is closed.
    if not allow_rate(token + "|" + ip):
        return jsonify({"error": "rate limited"}), 429
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "bad json"}), 400
    items = body if isinstance(body, list) else [body]
    for it in items:
        if it.get("method") not in ALLOW:
            return jsonify({"jsonrpc": "2.0", "id": it.get("id"),
                            "error": {"code": -32601, "message": "method not allowed"}}), 200
    # audit every submission for grief/collusion forensics: who (token), from where (ip), what
    app.logger.info("rpc token=%s ip=%s methods=%s", token, ip,
                    ",".join(str(it.get("method")) for it in items))
    try:
        return jsonify(rpc_forward(body))
    except Exception as e:
        return jsonify({"error": "rpc error: %s" % e}), 502


@app.get("/koth/status")
def status():
    king = cast_call(THRONE, "king()(address)")
    if not king or int(king, 16) == 0:
        return jsonify({"holder": None, "since": None})
    tag_hex = cast_call(THRONE, "currentTag()(bytes)")
    try:
        holder = bytes.fromhex(tag_hex[2:]).decode("utf-8", "replace") if tag_hex.startswith("0x") else tag_hex
    except Exception:
        holder = tag_hex
    since = cast_call(THRONE, "since()(uint256)").split()[0]   # strip cast's "[1.79e9]" annotation
    return jsonify({"holder": holder, "since": int(since) if since.lstrip("-").isdigit() else None})


@app.post("/koth/reset")
def reset():
    if ADMIN_TOKEN and request.headers.get("Authorization", "")[7:] != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    cast_send(GOVERNOR, "rotateEpoch()")
    cast_send(THRONE, "abdicate()")
    return jsonify({"status": "reset", "epoch": cast_call(GOVERNOR, "epochNonce()(uint256)").split()[0]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
