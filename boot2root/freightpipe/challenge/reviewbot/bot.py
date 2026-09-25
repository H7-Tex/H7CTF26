#!/usr/bin/env python3
# Freightpipe "deploy reviewer" NPC.
#
# The depot's automation: every REVIEWBOT_INTERVAL seconds it kicks a fresh
# prod-app deploy build. prod-app's pipeline pulls scripts/build.sh from the
# shared freightpipe-scripts repo at build time, so whatever build.sh currently
# holds is what runs. That shared repo is the only thing a contributor can write
# -> poison build.sh, wait for the bot's next run, read the deploy log.
#
# Pure stdlib on purpose: the deployed pod has no egress, so nothing may be
# pip-installed at runtime. Everything here is urllib/http.cookiejar.
#
# One-time bootstrap on first successful login: activate prod-app in Woodpecker,
# make its build logs publicly readable, and inject the deploy secrets the
# pipeline expects. Idempotent - safe to re-run on restart.

import http.cookiejar as CJ
import json
import os
import re
import sys
import time
import urllib.parse as P
import urllib.request as U

GITEA = os.environ.get("GITEA_URL", "http://gitea:3000")
WP = os.environ.get("WOODPECKER_URL", "http://woodpecker-server:8000")
DEV = os.environ.get("DEV_USER", "dev")
DEV_PW = os.environ.get("DEV_PASSWORD", "FreightDev-2026!")
INTERVAL = int(os.environ.get("REVIEWBOT_INTERVAL", "90"))
REPO = os.environ.get("PROD_REPO", "dev/prod-app")
USER_FLAG = os.environ.get("USER_FLAG", "H7CTF{placeholder_user_flag}")
# stage-2 loot: injected into the prod-app build env (Woodpecker secrets), read via I-PPE
REGISTRY_USER = os.environ.get("REGISTRY_USER", "deployer")
REGISTRY_TOKEN = os.environ.get("REGISTRY_TOKEN", "deploytoken-changeme")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "webhook-secret-changeme")
DEPLOY_URL = os.environ.get("DEPLOY_URL", "http://prod:9000/deploy")

cj = CJ.CookieJar()
op = U.build_opener(U.HTTPCookieProcessor(cj))
HDR = {}


def log(*a):
    print("[reviewbot]", *a, flush=True)


def _open(req):
    try:
        r = op.open(req, timeout=30)
        return r.getcode(), r.geturl(), r.read().decode("utf-8", "replace")
    except U.HTTPError as e:
        return e.code, req.full_url, e.read().decode("utf-8", "replace")


def get(url, headers=None):
    return _open(U.Request(url, headers=headers or {}))


def post(url, form=None, body_json=None, method="POST", headers=None):
    h = dict(headers or {})
    h.update(HDR)
    if body_json is not None:
        data = json.dumps(body_json).encode()
        h["Content-Type"] = "application/json"
    elif form is not None:
        data = P.urlencode(form).encode()
    else:
        data = b""
    return _open(U.Request(url, data=data, headers=h, method=method))


def wait_healthy():
    for _ in range(120):
        try:
            c, _, _ = get(f"{WP}/healthz")
            if 200 <= c < 300:
                log("woodpecker healthy")
                return
        except Exception:
            pass
        time.sleep(2)
    log("timed out waiting for woodpecker")
    sys.exit(1)


def login():
    # gitea password login
    _, _, h = get(f"{GITEA}/user/login")
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', h)
    post(f"{GITEA}/user/login", form={"_csrf": m.group(1), "user_name": DEV, "password": DEV_PW})
    # woodpecker oauth (urllib follows the redirect dance); grant once if asked
    _, _, h = get(f"{WP}/authorize")
    fm = re.search(r"<form[^>]*oauth/grant.*?</form>", h, re.S | re.I)
    if fm:
        form = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', fm.group(0)))
        form["granted"] = "true"
        post(f"{GITEA}/login/oauth/grant", form=form)
    # csrf token for authenticated writes lives in web-config.js
    _, _, wc = get(f"{WP}/web-config.js")
    m = re.search(r'WOODPECKER_CSRF\s*=\s*"([^"]+)"', wc)
    if not m:
        log("could not read WOODPECKER_CSRF; login failed")
        sys.exit(1)
    HDR["X-CSRF-TOKEN"] = m.group(1)
    _, _, who = get(f"{WP}/api/user")
    log("logged in as", json.loads(who).get("login"))


def find_wid():
    _, _, body = get(f"{WP}/api/user/repos")
    for r in json.loads(body):
        if r["full_name"] == REPO:
            return r["id"]
    return None


def activate():
    wid = find_wid()
    if wid:
        return wid
    _, _, body = get(f"{WP}/api/user/repos?all=true")
    rid = [r for r in json.loads(body) if r["full_name"] == REPO][0]["forge_remote_id"]
    c, _, body = post(f"{WP}/api/repos?forge_remote_id={rid}")
    if c >= 300:
        log("activate failed", c, body[:200])
        sys.exit(1)
    wid = json.loads(body)["id"]
    log("activated", REPO, "wid", wid)
    return wid


def make_logs_public(wid):
    # public visibility => build logs readable without prod-app repo access,
    # so the player can read their poisoned deploy output. Still no write/trigger
    # for non-collaborators (that stays the bot's job).
    post(f"{WP}/api/repos/{wid}", body_json={"visibility": "public"}, method="PATCH")


def ensure_secret(wid, name, value):
    c, _, body = get(f"{WP}/api/repos/{wid}/secrets/{name}")
    events = ["push", "manual", "cron", "deployment"]
    if c == 200:
        post(f"{WP}/api/repos/{wid}/secrets/{name}",
             body_json={"name": name, "value": value, "events": events}, method="PATCH")
        log("secret", name, "updated")
    else:
        post(f"{WP}/api/repos/{wid}/secrets",
             body_json={"name": name, "value": value, "events": events})
        log("secret", name, "created")


def inflight(wid):
    # don't stack builds: a slow build (kaniko) must not let the cadence pile up a queue.
    c, _, body = get(f"{WP}/api/repos/{wid}/pipelines?perPage=5")
    try:
        return any(p.get("status") in ("pending", "running") for p in json.loads(body))
    except Exception:
        return False


def trigger(wid):
    if inflight(wid):
        log("skip: a build is already in flight")
        return
    c, _, body = post(f"{WP}/api/repos/{wid}/pipelines", body_json={"branch": "main"})
    if c < 300:
        try:
            log("deploy triggered #", json.loads(body).get("number"))
        except Exception:
            log("deploy triggered")
    else:
        log("trigger failed", c, body[:150])


def main():
    wait_healthy()
    login()
    wid = activate()
    make_logs_public(wid)
    ensure_secret(wid, "user_flag", USER_FLAG)
    ensure_secret(wid, "registry_user", REGISTRY_USER)
    ensure_secret(wid, "registry_token", REGISTRY_TOKEN)
    ensure_secret(wid, "webhook_secret", WEBHOOK_SECRET)
    ensure_secret(wid, "deploy_url", DEPLOY_URL)
    log("bootstrap complete; deploy cadence every", INTERVAL, "s")
    while True:
        trigger(wid)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
