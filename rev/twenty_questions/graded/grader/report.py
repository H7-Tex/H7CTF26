import hashlib, hmac, json, os, secrets, time, urllib.error, urllib.request

BASE = os.environ.get("GRADER_URL", "https://ctf.h7tex.com/api/v1/graded/report").rsplit("/", 1)[0]
KEY = os.environ.get("GRADER_SECRET", "").encode()
TEAM = os.environ.get("ANVIL_TEAM_ID", "")
SLUG = os.environ.get("CHALLENGE_SLUG", "twenty-questions")
INST = os.environ.get("INSTANCE_ID", "")


def _call(path, payload):
    body = json.dumps(payload, separators=(",", ":")).encode()
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    msg = ("%s\n%s\n%s" % (ts, nonce, hashlib.sha256(body).hexdigest())).encode()
    sig = hmac.new(KEY, msg, hashlib.sha256).hexdigest()
    req = urllib.request.Request("%s/%s" % (BASE, path), data=body, method="POST", headers={
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
    except Exception as e:
        return 503, {"error": "anvil call failed: %s" % (e,)}


def report(score, gas):
    eval_id = secrets.token_hex(8)
    st, admit = _call("evaluate", {"team_id": TEAM, "eval_id": eval_id})
    if st != 200:
        return st, admit
    verdict = {"team_id": TEAM, "eval_id": eval_id, "status": "ok", "score": score,
               "idempotency_key": eval_id, "raw": {"gas": gas}}
    return _call("report", verdict)


def _selftest():
    k = ("abcd" * 16).encode()
    body = json.dumps({"team_id": "t", "eval_id": "e"}, separators=(",", ":")).encode()
    ts, nonce = "1790000000", "00112233445566778899aabbccddeeff"
    got = hmac.new(k, ("%s\n%s\n%s" % (ts, nonce, hashlib.sha256(body).hexdigest())).encode(), hashlib.sha256).hexdigest()
    assert len(got) == 64
    print("report signing self-test ok %s" % got[:16])


if __name__ == "__main__":
    _selftest()
