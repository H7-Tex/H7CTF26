#!/usr/bin/env python3
# HOSTILE TAKEOVER II: Treasury KotH bridge.
# The shared Anvil node is never exposed; this is the only reachable service.
# Teams submit exploit transactions through a per-team-token JSON-RPC proxy
# (auth + rate-limit + attribution). The KotH engine polls /koth/status.
# Round resets rotate the governor epoch, abdicate the throne, and drain the vault.
import os, time, json, subprocess, threading, urllib.request
from flask import Flask, request, jsonify, Response

RPC             = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8545")
SYS_KEY         = os.environ.get("SYS_KEY", "")
ADMIN_TOKEN     = os.environ.get("KOTH_ADMIN_TOKEN", "")
THRONE          = os.environ["THRONE_ADDR"]
GOVERNOR        = os.environ["GOVERNOR_ADDR"]
VAULT           = os.environ["VAULT_ADDR"]
TOKEN           = os.environ["TOKEN_ADDR"]
LENDER          = os.environ["LENDER_ADDR"]
TIMELOCK        = os.environ.get("TIMELOCK_ADDR", "")
SETUP           = os.environ.get("SETUP_ADDR", "")

# D2: published bot delegation (set by entrypoint, exposed in /koth/info)
BOT_ACCOUNT   = os.environ.get("BOT_ACCOUNT", "")
BOT_DELEGATEE = os.environ.get("BOT_DELEGATEE", "")
BOT_NONCE     = os.environ.get("BOT_NONCE", "0")
BOT_EXPIRY    = os.environ.get("BOT_EXPIRY", "")
BOT_V         = os.environ.get("BOT_V", "")
BOT_R         = os.environ.get("BOT_R", "")
BOT_S         = os.environ.get("BOT_S", "")

VERIFY_URL     = os.environ.get("KOTH_VERIFY_URL", "")
REQUIRE_SECRET = os.environ.get("KOTH_REQUIRE_SECRET", "").lower() in ("1", "true", "yes")

app = Flask(__name__)

# JSON-RPC method allowlist: reads + raw tx submission only.
ALLOW = {
    "eth_chainId", "eth_blockNumber", "eth_call", "eth_estimateGas", "eth_gasPrice",
    "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getLogs",
    "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getTransactionCount",
    "eth_sendRawTransaction", "eth_getBlockByNumber", "eth_getBlockByHash",
    "eth_feeHistory", "eth_maxPriorityFeePerGas", "net_version", "web3_clientVersion",
}

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
    out = subprocess.run(
        ["cast", "call", addr, sig, *map(str, args), "--rpc-url", RPC],
        capture_output=True, text=True, timeout=10)
    return out.stdout.strip()


def cast_send(addr, sig, *args, quiet=False):
    r = subprocess.run(
        ["cast", "send", addr, sig, *map(str, args),
         "--rpc-url", RPC, "--private-key", SYS_KEY],
        capture_output=True, text=True, timeout=20)
    if r.returncode != 0 and not quiet:
        app.logger.error("TREASURY-RESET-01: cast send %s %s failed: %s",
                         addr, sig, r.stderr.strip()[:200])
    return r.returncode == 0


def rpc_forward(body):
    req = urllib.request.Request(
        RPC, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())


def client_ip():
    return (request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "?")


def authorize(tok, secret):
    if not tok or len(tok) > 128:
        return False, "TREASURY-AUTH-01: invalid koth token"
    if not VERIFY_URL:
        if REQUIRE_SECRET and not secret:
            return False, "TREASURY-AUTH-02: missing rpc secret"
        return True, ""
    if not secret or len(secret) > 256:
        return False, "TREASURY-AUTH-02: missing or invalid rpc secret"
    try:
        req = urllib.request.Request(
            VERIFY_URL, data=json.dumps({"token": tok, "rpc_secret": secret}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        d = json.loads(urllib.request.urlopen(req, timeout=4).read())
    except Exception:
        return False, "TREASURY-AUTH-03: verify unavailable"
    if not d.get("valid") or d.get("public_tag") != tok:
        return False, "TREASURY-AUTH-04: rpc secret rejected"
    return True, ""


@app.get("/")
def index():
    return Response(
        "<h1>GENESIS DAO :: hostile-takeover-ii Treasury arena</h1>"
        "<p>The treasury is controlled by one Guardian seat (the Throne's <code>king</code>). "
        "Stage a governance takeover to seat your team, and hold it.</p>"
        "<ul>"
        "<li>GET  /koth/info  -- chain id, addresses, epoch, published bot delegation</li>"
        "<li>POST /rpc/&lt;koth-token&gt; -- JSON-RPC proxy (exploit txns go here)</li>"
        "<li>GET  /koth/status -- current Guardian</li>"
        "</ul>", mimetype="text/html")


@app.get("/koth/info")
def info():
    epoch = cast_call(GOVERNOR, "epochNonce()(uint256)").split()[0]
    d4seed = cast_call(SETUP, "D4_SEED()(uint256)").split()[0] if SETUP else ""
    resp = {
        "chain_id": 31337,
        "rpc": "POST /rpc/<koth-token>",
        "contracts": {
            "token":      TOKEN,
            "flashLender": LENDER,
            "governor":   GOVERNOR,
            "throne":     THRONE,
            "vault":      VAULT,
            "timelock":   TIMELOCK,
            "setup":      SETUP,
        },
        "epoch": epoch,
        # D2: the bot pre-delegated these votes; the signed delegation is published
        # here so teams can use it (and replay it across rounds -- nonce is never consumed).
        "bot_delegation": {
            "account":   BOT_ACCOUNT,
            "delegatee": BOT_DELEGATEE,
            "nonce":     int(BOT_NONCE),
            "expiry":    int(BOT_EXPIRY) if BOT_EXPIRY else 0,
            "v":         int(BOT_V) if BOT_V else 0,
            "r":         BOT_R,
            "s":         BOT_S,
        },
        "d4_seed": d4seed,
        "quorum": str(500_001 * 10**18),
        "notes": [
            "castVote reads live token balance -- no snapshot",
            "delegateBySig nonce is checked but never consumed",
            "batch proposeBatch only allowlists targets[0]",
            "vault.getVotes is asset-weighted; first-depositor can inflate it",
            "Timelock.executeBatch does not verify predecessor is done",
        ],
    }
    return jsonify(resp)


@app.post("/rpc/<token>")
def rpc(token):
    ip = client_ip()
    # per-IP flood check before auth -- survive connection floods
    if not allow_rate("ip|" + ip, rate=20.0, burst=120):
        return jsonify({"error": "TREASURY-RPC-01: rate limited"}), 429
    ok, reason = authorize(token, request.headers.get("X-Koth-Secret", ""))
    if not ok:
        return jsonify({"error": reason}), 403
    # per-(token, IP) bucket: a rival with a harvested token drains only its own bucket
    if not allow_rate(token + "|" + ip):
        return jsonify({"error": "TREASURY-RPC-02: rate limited"}), 429
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "TREASURY-RPC-03: bad json"}), 400
    items = body if isinstance(body, list) else [body]
    for it in items:
        if it.get("method") not in ALLOW:
            return jsonify({
                "jsonrpc": "2.0", "id": it.get("id"),
                "error": {"code": -32601, "message": "method not allowed"},
            }), 200
    app.logger.info("rpc token=%s ip=%s methods=%s", token, ip,
                    ",".join(str(it.get("method")) for it in items))
    try:
        return jsonify(rpc_forward(body))
    except Exception as e:
        return jsonify({"error": "TREASURY-RPC-04: upstream error: %s" % e}), 502


@app.get("/koth/status")
def status():
    # unauthenticated, un-rate-limited (CONTRACT.md section 10)
    king = cast_call(THRONE, "king()(address)")
    if not king or int(king, 16) == 0:
        return jsonify({"holder": None, "since": None})
    tag_hex = cast_call(THRONE, "currentTag()(bytes)")
    try:
        holder = (bytes.fromhex(tag_hex[2:]).decode("utf-8", "replace")
                  if tag_hex.startswith("0x") else tag_hex)
    except Exception:
        holder = tag_hex
    since = cast_call(THRONE, "since()(uint256)").split()[0]
    return jsonify({
        "holder": holder,
        "since": int(since) if since.lstrip("-").isdigit() else None,
    })


@app.post("/koth/reset")
def reset():
    if ADMIN_TOKEN and request.headers.get("Authorization", "")[7:] != ADMIN_TOKEN:
        return jsonify({"error": "TREASURY-RESET-02: unauthorized"}), 401
    # 1. rotate epoch so stale proposals are invalid in the next round
    cast_send(GOVERNOR, "rotateEpoch()")
    # 2. clear the throne
    cast_send(THRONE, "abdicate()")
    # 3. drain vault back to lender so the D4 path is live again next round
    cast_send(VAULT, "reset(address)", LENDER)
    epoch = cast_call(GOVERNOR, "epochNonce()(uint256)").split()[0]
    return jsonify({"status": "reset", "epoch": epoch})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
