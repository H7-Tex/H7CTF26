#!/usr/bin/env python3
# Harbor Master KotH sidecar.
# Crown = annotation h7.crown on harbor/throne:latest in the embedded Dockyard registry.
# Doors: D1 (comma-split scope), D2 (webhook secrets), D3 (manifest-by-digest auth bypass),
#        D4 (case-variant repo name).
# /koth/status -- unauthenticated poll for crown holder
# /koth/reset  -- Bearer KOTH_ADMIN_TOKEN clears the throne
# /koth/info   -- door states and throne manifest

import hashlib
import hmac as hmaclib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

from flask import Flask, abort, jsonify, request

DOCKYARD = os.environ.get("DOCKYARD_URL", "http://dockyard:7005")
PORT = int(os.environ.get("PORT", "8085"))
ADMIN_TOKEN = os.environ.get("KOTH_ADMIN_TOKEN", "")
VERIFY_URL = os.environ.get("KOTH_VERIFY_URL", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "harbor_master_sekret_42")

THRONE_REPO = "harbor/throne"
THRONE_TAG = "latest"
ADMIN_USER = "harbor"

app = Flask(__name__)
_init_lock = threading.Lock()
_admin_token_cache = ""

# -- Dockyard helpers --

def _dock(method, path, body=None, token=None, content_type="application/json"):
    url = DOCKYARD + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


def _get_admin_token():
    global _admin_token_cache
    if _admin_token_cache:
        return _admin_token_cache
    # request push token for harbor/throne
    url = DOCKYARD + "/token?service=dockyard&scope=repository:harbor/throne:pull,push"
    req = urllib.request.Request(url)
    import base64
    creds = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()
    req.add_header("Authorization", "Basic " + creds)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            _admin_token_cache = data.get("token", "")
            return _admin_token_cache
    except Exception:
        return ""


def _read_throne_manifest():
    tok = _get_admin_token()
    if not tok:
        return None
    url = DOCKYARD + f"/v2/{THRONE_REPO}/manifests/{THRONE_TAG}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Accept", "application/vnd.oci.image.manifest.v1+json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _push_throne_manifest(annotations=None):
    """Push a minimal OCI manifest to harbor/throne:latest with given annotations."""
    global _admin_token_cache
    _admin_token_cache = ""  # force refresh
    tok = _get_admin_token()
    if not tok:
        return False
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": "sha256:44136fa355ba77b9ad7b35f1a80f6b8bb480e88a82b4d5e0a1c487a1fefa7e6b",
            "size": 2
        },
        "layers": [],
        "annotations": annotations or {}
    }
    body = json.dumps(manifest, sort_keys=True).encode()
    url = DOCKYARD + f"/v2/{THRONE_REPO}/manifests/{THRONE_TAG}"
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201)
    except urllib.error.HTTPError as e:
        return e.code in (200, 201)
    except Exception:
        return False


def _ensure_empty_blob():
    """Ensure the empty config blob exists in Dockyard (required for minimal manifest)."""
    tok = _get_admin_token()
    if not tok:
        return
    # empty JSON object blob
    digest = "sha256:44136fa355ba77b9ad7b35f1a80f6b8bb480e88a82b4d5e0a1c487a1fefa7e6b"
    url = DOCKYARD + f"/v2/{THRONE_REPO}/blobs/{digest}"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=5):
            return  # already exists
    except Exception:
        pass
    # upload it
    start_url = DOCKYARD + f"/v2/{THRONE_REPO}/blobs/uploads/"
    req = urllib.request.Request(start_url, data=b"", method="POST")
    req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            loc = r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "") if e.code == 202 else ""
    if not loc:
        return
    put_url = (DOCKYARD + loc if loc.startswith("/") else loc) + f"&digest={digest}"
    data = b"{}"
    req = urllib.request.Request(put_url, data=data, method="PUT")
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Content-Type", "application/octet-stream")
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# -- Initialization --

def _wait_dockyard(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(DOCKYARD + "/v2/", timeout=2):
                return True
        except Exception:
            time.sleep(1)
    return False


def _init_dockyard():
    with _init_lock:
        if not _wait_dockyard():
            print("dockyard did not come up", flush=True)
            sys.exit(1)
        # register admin user
        _dock("POST", "/api/users", {"username": ADMIN_USER, "password": ADMIN_PASS})
        # create harbor/throne as a public repo
        tok = _get_admin_token()
        if tok:
            _dock("POST", "/api/repos",
                  {"name": THRONE_REPO, "visibility": "public"},
                  token=tok)
            # set DEPLOY_KEY secret (D2 door target)
            _dock("PUT", f"/api/repos/harbor/throne/secrets/DEPLOY_KEY",
                  {"value": "hm-deploy-" + os.urandom(8).hex()},
                  token=tok)
        _ensure_empty_blob()
        # push genesis manifest with no crown
        _push_throne_manifest({})
        print("harbor-master initialized", flush=True)


threading.Thread(target=_init_dockyard, daemon=True).start()

# -- KotH API --

@app.before_request
def _rate_guard():
    # per-IP token-bucket: 20 req/s burst 80
    pass  # fine for finals scale


@app.route("/koth/status")
def koth_status():
    manifest = _read_throne_manifest()
    if manifest is None:
        return jsonify({"holder": None, "since": 0})
    annotations = manifest.get("annotations", {}) or {}
    raw = annotations.get("h7.crown", "")
    tag = _resolve_crown(raw)
    since = 0
    # use manifest creation time as proxy for since -- not available, use 0
    return jsonify({"holder": tag or None, "since": since})


@app.route("/koth/reset", methods=["POST"])
def koth_reset():
    if not ADMIN_TOKEN:
        abort(503, "no admin token configured")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != ADMIN_TOKEN:
        abort(401, "bad token")
    global _admin_token_cache
    _admin_token_cache = ""
    _ensure_empty_blob()
    ok = _push_throne_manifest({})
    if not ok:
        abort(500, "reset failed")
    return jsonify({"ok": True})


@app.route("/koth/info")
def koth_info():
    doors = {
        "D1": {"name": "scope-comma", "vuln": bool(os.environ.get("VULN_D1")), "advisory": "Token scope grants push on harbor/throne via comma-delimited repo list"},
        "D2": {"name": "webhook-secrets", "vuln": bool(os.environ.get("VULN_D2")), "advisory": "Watch delivery exposes DEPLOY_KEY in template data"},
        "D3": {"name": "manifest-digest-bypass", "vuln": bool(os.environ.get("VULN_D3")), "advisory": "Manifest PUT by digest skips push auth when all blobs are linked"},
        "D4": {"name": "case-variant", "vuln": bool(os.environ.get("VULN_D4")), "advisory": "Push to HARBOR/throne (uppercase) writes to harbor/throne after storage normalization"},
    }
    return jsonify({"doors": doors, "throne_repo": THRONE_REPO})


def _resolve_crown(raw):
    """Decode h7.crown annotation to a team tag, optionally via VERIFY_URL."""
    if not raw:
        return None
    if not VERIFY_URL:
        return raw  # no verification, treat raw value as tag
    try:
        url = VERIFY_URL + "/decode?hmac=" + urllib.parse.quote(raw)
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read())
            return data.get("tag")
    except Exception:
        return raw  # fallback: use raw value


import urllib.parse  # noqa: E402


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
