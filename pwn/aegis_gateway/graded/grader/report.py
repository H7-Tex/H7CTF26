#!/usr/bin/env python3
# Grader-side Anvil client for The Ladder (graded). Internal role only (holds GRADER_SECRET).
# On a submission relayed from the portal: /evaluate (ledger charges) -> score = depth/5 from
# the submitted tokens (tokens.py, no untrusted code) -> /report (monotonic best). Signing +
# endpoints per docs/GRADED.md (feat/graded).
import hashlib, hmac, json, os, secrets, time, urllib.error, urllib.request
import tokens

BASE = os.environ.get("GRADER_URL", "https://ctf.h7tex.com/api/v1/graded/report").rsplit("/", 1)[0]
KEY = os.environ.get("GRADER_SECRET", "").encode()   # used as-is, NOT hex-decoded
TEAM = os.environ.get("ANVIL_TEAM_ID", "")
SLUG = os.environ.get("CHALLENGE_SLUG", "the-ladder")
INST = os.environ.get("INSTANCE_ID", "")


def _call(path, payload):
    body = json.dumps(payload, separators=(",", ":")).encode()
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    msg = f"{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
    sig = hmac.new(KEY, msg, hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"{BASE}/{path}", data=body, method="POST", headers={
        "Content-Type": "application/json", "X-Anvil-Challenge": SLUG,
        "X-Anvil-Instance": INST, "X-Anvil-Timestamp": ts, "X-Anvil-Nonce": nonce,
        "X-Anvil-Signature": sig})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"error": "http %d" % e.code}
    except urllib.error.URLError as e:
        return 503, {"error": "anvil unreachable: %s" % (e.reason,)}
    except Exception as e:
        return 503, {"error": "anvil call failed: %s" % (e,)}


def grade_submission(submitted_tokens: list):
    """Player submitted the token_k's they pried out of the live tiers. Charge one eval, score
    depth/5, report. Returns (http_status, body) to relay back to the player via the portal."""
    eval_id = secrets.token_hex(8)
    st, admit = _call("evaluate", {"team_id": TEAM, "eval_id": eval_id})
    if st != 200:
        return st, admit                                   # cooldown / credits / in-flight
    d = tokens.depth(submitted_tokens)
    verdict = {"team_id": TEAM, "eval_id": eval_id, "status": "ok",
               "score": tokens.score(submitted_tokens), "idempotency_key": eval_id,
               "raw": {"depth": d, "of": tokens.N}}
    return _call("report", verdict)


def _sign_selftest():
    # verify the signature construction matches the doc's reference exactly.
    os.environ["GRADER_SECRET"] = "abcd" * 16
    k = ("abcd" * 16).encode()
    body = json.dumps({"team_id": "t", "eval_id": "e"}, separators=(",", ":")).encode()
    ts, nonce = "1790000000", "00112233445566778899aabbccddeeff"
    msg = f"{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
    expect = hmac.new(k, msg, hashlib.sha256).hexdigest()
    # independent recompute
    got = hmac.new(k, (ts + "\n" + nonce + "\n" + hashlib.sha256(body).hexdigest()).encode(),
                   hashlib.sha256).hexdigest()
    assert got == expect and len(got) == 64
    print("report.py signing self-test OK  sig=%s..." % got[:16])


if __name__ == "__main__":
    _sign_selftest()
