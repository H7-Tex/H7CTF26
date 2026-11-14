#!/usr/bin/env python3
# The Ladder grader (internal role, holds GRADER_SECRET). Boot: mint each tier's token and PUSH
# it to that tier's control port (one-shot, before players connect). Then serve an internal
# /grade endpoint: the portal relays the tokens a player pried out of the live tiers; we verify
# them (tokens.py) and report depth/5 to Anvil (report.py). No untrusted code, push-only, and
# GRADER_SECRET is never returned anywhere.
import os, socket, threading, time
from flask import Flask, request, jsonify
import tokens, report

# Pod containers do NOT share localhost -- reach each tier by its ROLE HOSTNAME (default = the
# role name in services.yaml), overridable via TIER_HOST_<VER> if Anvil's addressing differs.
# version -> (peer hostname, control port). Public rung port is separate + player-facing.
def _host(ver, default):
    return os.environ.get("TIER_HOST_" + ver.replace(".", "_"), default)

TIERS_NET = {
    "v1.0": (_host("v1.0", "tier-v1-0"), 9101),
    "v1.4": (_host("v1.4", "tier-v1-4"), 9102),
    "v2.0": (_host("v2.0", "tier-v2-0"), 9103),
    "v2.6": (_host("v2.6", "tier-v2-6"), 9104),
    "v3.0": (_host("v3.0", "tier-v3-0"), 9105),
}
PROVISIONED = {"done": False}


def _push_one(ver, host, port):
    tok = tokens.mint(ver).encode()
    for _ in range(240):                          # retry until the tier's control listener is up
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.sendall(tok); s.shutdown(socket.SHUT_WR); s.close()
            return True
        except OSError:
            time.sleep(0.5)
    print("WARN: could not push token to %s (%s:%d)" % (ver, host, port), flush=True)
    return False


def push_tokens():
    # push to every tier IN PARALLEL (by role hostname), so one slow tier can't starve the others
    ths = [threading.Thread(target=_push_one, args=(v, h, p), daemon=True)
           for v, (h, p) in TIERS_NET.items()]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    PROVISIONED["done"] = True
    print("all tier tokens pushed", flush=True)


app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify({"provisioned": PROVISIONED["done"], "tiers": tokens.N})


@app.post("/grade")
def grade():
    # internal only (portal relays here). body: {"tokens": ["H7T_...", ...]}
    body = request.get_json(silent=True) or {}
    subs = body.get("tokens") or []
    if not isinstance(subs, list):
        return jsonify({"error": "tokens must be a list"}), 400
    subs = [str(x) for x in subs][:64]              # cap submission size
    d = tokens.depth(subs)                          # always computable, primary feedback
    try:
        st, res = report.grade_submission(subs)     # /evaluate (charge) -> /report (best)
    except Exception as e:
        st, res = 503, {"error": "grader internal: %s" % e}
    # always 200 to the portal; the player's depth is the feedback, anvil carries charge/best/errors
    return jsonify({"depth": d, "of": tokens.N, "score": tokens.score(subs),
                    "eval_http": st, "anvil": res}), 200


if __name__ == "__main__":
    threading.Thread(target=push_tokens, daemon=True).start()
    # bind 0.0.0.0: the portal is a SEPARATE container (no shared localhost) and reaches us by hostname
    app.run(host="0.0.0.0", port=int(os.environ.get("GRADER_PORT", "9000")))
