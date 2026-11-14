from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
import secrets
import time
import httpx
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, Response as RawResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

ROOT = Path(__file__).parent
RELEASES = {"v1": "2026.09.24.1", "v2": "2026.09.24.2"}
API_VERSIONS = {"v1": "1.0", "v2": "2.0"}
CONTRACTS = {"v1": "relay.sync-plan/v1", "v2": "relay.sync-plan/v2"}
DEPLOYED_AT = {"v1": "2026-09-20T09:00:00Z", "v2": "2026-09-24T17:30:00Z"}
if os.environ.pop("FLAG", None) is not None:
    logging.getLogger("relay").warning("Relay discarded a flag environment variable; only the exporter may consume it")
CHECKPOINT_FLAG = os.environ.pop("CHECKPOINT_FLAG", None)
EXPORTER_URL = os.environ.get("EXPORTER_URL", "http://exporter:8090").rstrip("/")
EXPORTER_TOKEN = os.environ.get("EXPORTER_TOKEN", "")
APP_ENV = os.environ.get("APP_ENV", "development").lower()

_exporter_url = urlsplit(EXPORTER_URL)
if APP_ENV == "production" and (
    not os.environ.get("EXPORTER_URL") or _exporter_url.scheme not in {"http", "https"} or not _exporter_url.netloc
    or _exporter_url.username or _exporter_url.password
    or len(EXPORTER_TOKEN) < 32
):
    raise RuntimeError("production Relay requires EXPORTER_URL and a high-entropy EXPORTER_TOKEN (32+ characters)")
if APP_ENV == "production" and not CHECKPOINT_FLAG:
    raise RuntimeError("production Relay requires the dynamically injected CHECKPOINT_FLAG")


DIAGNOSTIC_JOB_ID = "JOB-3887"
DIAGNOSTIC_READING = "Clock drift +184 ms · channel 4"

jobs: dict[str, dict[str, Any]] = {
    "JOB-3814": {"id": "JOB-3814", "title": "Cooling inspection", "site": "Plant 14", "address": "North service road", "status": "Assigned", "due": "Today, 11:30", "initials": "P14", "tone": "blue"},
    "JOB-3821": {"id": "JOB-3821", "title": "Generator inspection", "site": "Depot 7", "address": "Bay 3 · Riverside estate", "status": "Awaiting report", "due": "Today, 14:00", "initials": "D7", "tone": "amber"},
    "JOB-3844": {"id": "JOB-3844", "title": "Network cabinet audit", "site": "Building C", "address": "West campus", "status": "Draft", "due": "Tomorrow, 09:00", "initials": "BC", "tone": "green"},
    "JOB-3850": {"id": "JOB-3850", "title": "Pump room service", "site": "Waterworks 2", "address": "Lower access gate", "status": "Assigned", "due": "Tomorrow, 13:15", "initials": "W2", "tone": "violet"},
    DIAGNOSTIC_JOB_ID: {"id": DIAGNOSTIC_JOB_ID, "title": "Telemetry drift report", "site": "North relay station", "address": "Remote cabinet 4", "status": "Draft", "due": "Friday, 16:00", "initials": "N4", "tone": "slate"},
}
_diagnostic_record = {"job_id": DIAGNOSTIC_JOB_ID, "reading": DIAGNOSTIC_READING, "published": False}
_report_preference: dict[str, Any] = {
    "directive": {"contract": "relay.report-package/v2", "scope": "summary"},
    "revision": 0,
    "processed_revision": 0,
}
_dispatch_collection_seconds = max(2, int(os.environ.get("DISPATCH_COLLECTION_SECONDS", "8")))
_dispatch_cooldown_seconds = max(1, int(os.environ.get("DISPATCH_COOLDOWN_SECONDS", "2")))


def _new_dispatch_cycle(now: float) -> dict[str, Any]:
    return {"cycle_id": f"dispatch_{secrets.token_hex(8)}", "state": "collecting",
            "started_at": now, "snapshot_at": now + _dispatch_collection_seconds,
            "snapshot": None, "operation_id": None, "processed_at": None,
            "staged_at": None, "replay_attempts": 0, "next_cycle_at": None}


_dispatch_cycle = _new_dispatch_cycle(time.time())
_last_dispatch_metrics: dict[str, Any] | None = None
activity = [
    {"title": "Report saved", "detail": "Cooling inspection · Plant 14", "when": "8:42 am", "kind": "check"},
    {"title": "Job assigned", "detail": "Generator inspection · Depot 7", "when": "Yesterday", "kind": "pin"},
    {"title": "Draft updated", "detail": "Network cabinet audit · Building C", "when": "Yesterday", "kind": "edit"},
]


class WorkerKey(BaseModel):
    key_id: str
    public_key: dict[str, Any]


class ReplayRequest(BaseModel):
    key_id: str
    envelope: dict[str, Any]
    signature: str | None = None


class OutboxMaterialization(BaseModel):
    envelope: dict[str, Any]


class SyncPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cycle_id: str | None = None


app = FastAPI(title="Relay", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/assets", StaticFiles(directory=ROOT / "static" / "assets"), name="assets")
app.mount("/icons", StaticFiles(directory=ROOT / "static" / "icons"), name="icons")

_state_lock = Lock()
_session_ttl = max(5400, int(os.environ.get("RELAY_SESSION_TTL_SECONDS", "5400")))
_operation_ttl = max(1, int(os.environ.get("SYNC_OPERATION_TTL_SECONDS", "900")))
_sessions: dict[str, dict[str, Any]] = {}
_operations: dict[str, dict[str, Any]] = {}
_exports: dict[str, dict[str, Any]] = {}
_export_by_report: dict[tuple[str, int], str] = {}
_max_sessions = 10000
_max_operations = 5000
_max_exports = 512
_state_ttl = 3600


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def release_manifest(version: str) -> dict[str, Any]:
    assets = {
        path: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for path, relative in {
            "/": Path("static") / version / "index.html",
            f"/assets/relay-{version}.js": Path("static/assets") / f"relay-{version}.js",
            f"/assets/relay-{version}.css": Path("static/assets") / f"relay-{version}.css",
        "/assets/relay-job-detail.css": Path("static/assets/relay-job-detail.css"),
        "/icons/relay.svg": Path("static/icons/relay.svg"),
        "/manifest.webmanifest": Path("static/manifest.webmanifest"),
    }.items()
    }
    if version == "v1":
        assets["/assets/contracts/report-package-v1.json"] = hashlib.sha256(
            (ROOT / "static" / "assets" / "contracts" / "report-package-v1.json").read_bytes()
        ).hexdigest()
    schema_version = int(version[-1])
    build_material = {
        "build": RELEASES[version], "schema_version": schema_version,
        "semantic_contract": CONTRACTS[version], "deployed_at": DEPLOYED_AT[version],
        "assets": assets,
    }
    supplied = os.environ.get("BUILD_SHA" if version == "v2" else "LEGACY_BUILD_SHA", "")
    release_id = supplied[:12].lower() if re.fullmatch(r"[0-9a-fA-F]{12,64}", supplied) else hashlib.sha256(canonical_json(build_material)).hexdigest()[:12]
    return {
        "release_id": release_id,
        "build_channel": "stable",
        "schema_version": schema_version,
        "cache_namespaces": {
            "static": f"relay-static-2026.09.{release_id}",
            "runtime": f"relay-runtime-2026.09.{release_id}",
        },
        "assets": assets,
        "deployed_at": DEPLOYED_AT[version],
        "semantic_contract": CONTRACTS[version],
        **({"previous_release_manifest": "/__release/manifest/v1.json"} if version == "v2" else {}),
    }


RELEASE_MANIFESTS = {version: release_manifest(version) for version in RELEASES}


def structured_event(event: str, **fields: Any) -> None:
    if os.environ.get("RELAY_DEV_LOGS") == "1":
        print(json.dumps({"event": event, **fields}), flush=True)


def _advance_dispatch_locked(now: float | None = None) -> None:
    """Advance the shared dispatch state at observable server-side boundaries.

    Callers hold _state_lock. The snapshot is serialized while the revision and
    directive are protected by the same lock, so no write can produce a torn
    package or change an already snapshotted cycle.
    """
    global _dispatch_cycle, _last_dispatch_metrics
    now = time.time() if now is None else now
    cycle = _dispatch_cycle
    operation = _operations.get(cycle.get("operation_id") or "")
    if (cycle["state"] in {"snapshotted", "staged"} and operation
            and operation["expires"] < time.monotonic()):
        operation["used"] = True
        cycle["state"] = "processed"
        cycle["processed_at"] = now
        cycle["next_cycle_at"] = now + _dispatch_cooldown_seconds
        structured_event("dispatch_cycle_expired", cycle_id=cycle["cycle_id"])
        return
    if cycle["state"] == "collecting" and now >= cycle["snapshot_at"]:
        snapshot = {
            "cycle_id": cycle["cycle_id"],
            "preference_revision": _report_preference["revision"],
            "report_package": json.loads(canonical_json(_report_preference["directive"])),
            "snapshotted_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "snapshotted_at_epoch": now,
        }
        snapshot["digest"] = hashlib.sha256(canonical_json(snapshot)).hexdigest()
        cycle["snapshot"] = snapshot
        if snapshot["preference_revision"] <= _report_preference["processed_revision"]:
            cycle["state"] = "processed"
            cycle["processed_at"] = now
            cycle["next_cycle_at"] = now + _dispatch_cooldown_seconds
            structured_event("dispatch_cycle_skipped", cycle_id=cycle["cycle_id"],
                             revision=snapshot["preference_revision"])
        else:
            cycle["state"] = "snapshotted"
            structured_event("dispatch_preference_snapshotted", cycle_id=cycle["cycle_id"],
                             revision=snapshot["preference_revision"])
    elif cycle["state"] == "processed" and now >= cycle["next_cycle_at"]:
        snapshot = cycle.get("snapshot")
        _last_dispatch_metrics = {
            "cycle_id": cycle["cycle_id"],
            "stage_latency_seconds": round(cycle["staged_at"] - snapshot["snapshotted_at_epoch"], 3)
                if cycle.get("staged_at") and snapshot else None,
            "cycle_duration_seconds": round(cycle["processed_at"] - cycle["started_at"], 3)
                if cycle.get("processed_at") else None,
            "replay_attempts": cycle.get("replay_attempts", 0),
        }
        _dispatch_cycle = _new_dispatch_cycle(now)


def dispatch_public_state(cycle: dict[str, Any]) -> dict[str, Any]:
    snapshot = cycle.get("snapshot")
    return {
        "cycle_id": cycle["cycle_id"], "state": cycle["state"],
        "next_snapshot_at": datetime.fromtimestamp(
            cycle["snapshot_at"] if cycle["state"] != "processed"
            else cycle["next_cycle_at"] + _dispatch_collection_seconds, timezone.utc).isoformat(),
        "preference_revision": _report_preference["revision"],
        "snapshot_revision": snapshot["preference_revision"] if snapshot else None,
        "processed_revision": _report_preference["processed_revision"],
    }


def get_session(request: Request, response: Response, create: bool = False) -> tuple[str | None, dict[str, Any] | None]:
    session_id = request.cookies.get("relay_session")
    session = _sessions.get(session_id or "")
    if session and session["expires"] <= time.monotonic():
        _sessions.pop(session_id or "", None)
        session = None
    if session is None and create:
        session_id = secrets.token_urlsafe(32)
        session = {"expires": time.monotonic() + _session_ttl, "manifest": None, "worker_key": None,
                   "release": "v1", "legacy_profile": "summary", "legacy_profile_revision": 0}
        _sessions[session_id] = session
        _prune_sessions()
        forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        response.set_cookie("relay_session", session_id, max_age=_session_ttl, httponly=True,
                            samesite="lax", secure=request.url.scheme == "https" or forwarded_scheme == "https", path="/")
    return session_id, session


def _prune_sessions() -> None:
    now = time.monotonic()
    for session_id, session in list(_sessions.items()):
        if session["expires"] <= now:
            _sessions.pop(session_id, None)
    while len(_sessions) > _max_sessions:
        _sessions.pop(min(_sessions, key=lambda key: _sessions[key]["expires"]), None)


def session_release(request: Request) -> str:
    session_id = request.cookies.get("relay_session")
    session = _sessions.get(session_id or "")
    return session.get("release", "v1") if session else "v1"


def _prune_exports() -> None:
    now = time.monotonic()
    for export_id, record in list(_exports.items()):
        if record.get("expires", 0) <= now:
            _exports.pop(export_id, None)
            _export_by_report.pop((record["job_id"], record["report_version"]), None)
    while len(_exports) > _max_exports:
        oldest = min(_exports, key=lambda key: _exports[key].get("created", 0))
        record = _exports.pop(oldest)
        _export_by_report.pop((record["job_id"], record["report_version"]), None)


def require_same_origin_fetch(request: Request) -> None:
    origin = request.headers.get("origin", "")
    parsed = urlsplit(origin)
    expected_scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",", 1)[0].strip()
    same_browser_origin = (
        request.headers.get("sec-fetch-site") == "same-origin"
        and request.headers.get("sec-fetch-mode") == "cors"
        and parsed.scheme == expected_scheme
        and parsed.netloc.lower() == request.headers.get("host", "").lower()
    )
    if not same_browser_origin:
        raise HTTPException(403, "Relay sync requires a same-origin browser request")


def key_fingerprint(jwk: dict[str, Any]) -> str:
    public_fields = {name: jwk[name] for name in ("crv", "kty", "x", "y")}
    return base64.urlsafe_b64encode(hashlib.sha256(canonical_json(public_fields)).digest()).decode().rstrip("=")


def public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise ValueError("expected a public P-256 key")
    x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=" * (-len(jwk["y"]) % 4)), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def public_job(job_id: str) -> dict[str, Any] | None:
    job = jobs.get(job_id)
    if job is None:
        return None
    result = dict(job)
    if job_id == DIAGNOSTIC_JOB_ID and _diagnostic_record["published"]:
        result["report"] = {"diagnostic_reading": _diagnostic_record["reading"], "status": "published",
                            "report_package": _diagnostic_record.get("report_package"),
                            "report_version": _diagnostic_record.get("report_version", 1),
                            "preference_revision": _diagnostic_record.get("preference_revision"),
                            "dispatch_cycle_id": _diagnostic_record.get("dispatch_cycle_id")}
        result["export_url"] = f"/api/jobs/{job_id}/exports"
    return result


def require_internal_token(authorization: str | None) -> None:
    if not EXPORTER_TOKEN or not secrets.compare_digest(
        authorization or "", f"Bearer {EXPORTER_TOKEN}"
    ):
        raise HTTPException(404, "not found")


@app.get("/internal/dispatch-metrics", include_in_schema=False)
async def dispatch_metrics(authorization: str | None = Header(default=None)):
    require_internal_token(authorization)
    with _state_lock:
        cycle = _dispatch_cycle
        snapshot = cycle.get("snapshot")
        metrics = {
            "cycle_id": cycle["cycle_id"],
            "stage_latency_seconds": round(cycle["staged_at"] - snapshot["snapshotted_at_epoch"], 3)
                if cycle.get("staged_at") and snapshot else None,
            "cycle_duration_seconds": round(cycle["processed_at"] - cycle["started_at"], 3)
                if cycle.get("processed_at") else None,
            "replay_attempts": cycle.get("replay_attempts", 0),
        }
        return metrics if snapshot or _last_dispatch_metrics is None else _last_dispatch_metrics


def _validate_bounded_json(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > 64 or depth > 4:
        raise HTTPException(422, "report preference is too complex")
    if isinstance(value, dict):
        if len(value) > 16:
            raise HTTPException(422, "report preference has too many fields")
        for key, child in value.items():
            if (not isinstance(key, str) or len(key) > 64
                    or key in {"__proto__", "prototype", "constructor"}):
                raise HTTPException(422, "report preference contains an invalid field")
            _validate_bounded_json(child, depth + 1, count)
    elif isinstance(value, list):
        if len(value) > 16:
            raise HTTPException(422, "report preference list is too large")
        for child in value:
            _validate_bounded_json(child, depth + 1, count)
    elif isinstance(value, str) and len(value) > 512:
        raise HTTPException(422, "report preference text is too long")
    elif isinstance(value, float) and not math.isfinite(value):
        raise HTTPException(422, "report preference contains an unsupported number")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise HTTPException(422, "report preference contains an unsupported value")


async def read_report_preference(request: Request, release_id: str) -> dict[str, Any]:
    try:
        content_length = int(request.headers.get("content-length", "0") or 0)
    except ValueError:
        raise HTTPException(400, "invalid content length")
    if content_length > 4096:
        raise HTTPException(413, "report preference is too large")
    raw = await request.body()
    if len(raw) > 4096:
        raise HTTPException(413, "report preference is too large")
    try:
        value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(422, "report preference is not valid JSON")
    if not isinstance(value, dict):
        raise HTTPException(422, "report preference must be an object")
    _validate_bounded_json(value)
    if release_id == "v1":
        if (set(value) != {"contract", "profile"}
                or value.get("contract") != "relay.report-package/v1"
                or value.get("profile") not in {"summary", "record", "complete"}):
            raise HTTPException(422, "report preference contract is invalid")
    elif (set(value) != {"contract", "scope"}
          or value.get("contract") != "relay.report-package/v2"
          or value.get("scope") not in {"summary", "record"}):
        raise HTTPException(422, "report preference contract is invalid")
    return value


def _validate_report_directive(directive: Any) -> None:
    if not isinstance(directive, dict):
        raise HTTPException(422, "report preference contract is invalid")
    _validate_bounded_json(directive)
    if (set(directive) != {"contract", "scope"}
            or directive.get("contract") != "relay.report-package/v2"
            or directive.get("scope") not in {"summary", "record"}):
        raise HTTPException(422, "report preference contract is invalid")


@app.get("/api/jobs/{job_id}/report-preference")
async def get_report_preference(job_id: str, request: Request, response: Response):
    if job_id != DIAGNOSTIC_JOB_ID:
        raise HTTPException(404, "job not found")
    _, session = get_session(request, response, create=True)
    if session_release(request) == "v1":
        response.headers["ETag"] = f'"report-preference-v1-{session["legacy_profile_revision"]}"'
        response.headers["Cache-Control"] = "no-store"
        return {"report_package": {"contract": "relay.report-package/v1", "profile": session["legacy_profile"]},
                "revision": session["legacy_profile_revision"], "processed_revision": 0,
                "dispatch": dispatch_public_state(_dispatch_cycle)}
    with _state_lock:
        _advance_dispatch_locked()
        response.headers["ETag"] = f'"preference-{_report_preference["revision"]}"'
        response.headers["Cache-Control"] = "no-store"
        return {
            "report_package": json.loads(canonical_json(_report_preference["directive"])),
            "revision": _report_preference["revision"],
            "processed_revision": _report_preference["processed_revision"],
            "dispatch": dispatch_public_state(_dispatch_cycle),
        }


@app.put("/api/jobs/{job_id}/report-preference")
async def put_report_preference(job_id: str, request: Request, response: Response):
    if job_id != DIAGNOSTIC_JOB_ID:
        raise HTTPException(404, "job not found")
    _, session = get_session(request, response, create=True)
    release_id = session_release(request)
    directive = await read_report_preference(request, release_id)
    expected = request.headers.get("if-match")
    if release_id == "v1":
        current = f'"report-preference-v1-{session["legacy_profile_revision"]}"'
        if expected is not None and not secrets.compare_digest(expected, current):
            raise HTTPException(412, "report preference changed; refresh the job and try again")
        session["legacy_profile"] = directive["profile"]
        session["legacy_profile_revision"] += 1
        return {"status": "saved", "revision": session["legacy_profile_revision"],
                "report_package": {"contract": "relay.report-package/v1", "profile": session["legacy_profile"]}}
    with _state_lock:
        _advance_dispatch_locked()
        if expected is not None:
            current = f'"preference-{_report_preference["revision"]}"'
            if not secrets.compare_digest(expected, current):
                raise HTTPException(412, "report preference changed; refresh and try again")
        _report_preference["directive"] = directive
        _report_preference["revision"] += 1
        revision = _report_preference["revision"]
        dispatch = dispatch_public_state(_dispatch_cycle)
    return {"status": "saved", "revision": revision, "dispatch": dispatch}


@app.middleware("http")
async def cache_policy(request: Request, call_next):
    session_id = request.cookies.get("relay_session")
    session = _sessions.get(session_id or "")
    if session and session["expires"] <= time.monotonic():
        _sessions.pop(session_id or "", None)
        session = None
    if session:
        session["expires"] = time.monotonic() + _session_ttl
    response = await call_next(request)
    if session:
        forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
        response.set_cookie("relay_session", session_id, max_age=_session_ttl, httponly=True,
                            samesite="lax", secure=request.url.scheme == "https" or forwarded_scheme == "https", path="/")
    if request.url.path in {"/sw-2026.09.24.1.js", "/sw-2026.09.24.2.js"}:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Service-Worker-Allowed"] = "/"
    elif request.url.path in {"/", "/index.html", "/manifest.webmanifest", "/__release/manifest.json"}:
        response.headers["Cache-Control"] = "no-cache"
    elif request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.get("/")
@app.get("/index.html")
async def index(request: Request, response: Response):
    get_session(request, response, create=True)
    return FileResponse(ROOT / "static" / session_release(request) / "index.html", media_type="text/html")


@app.get("/sw-2026.09.24.1.js")
async def legacy_worker():
    source = (ROOT / "workers" / "sw-legacy.js").read_text(encoding="utf-8")
    return RawResponse(source.replace("__RELEASE_ID__", RELEASE_MANIFESTS["v1"]["release_id"]), media_type="application/javascript", headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Service-Worker-Allowed": "/"})


@app.get("/sw-2026.09.24.2.js")
async def current_worker():
    source = (ROOT / "workers" / "sw-current.js").read_text(encoding="utf-8")
    return RawResponse(source.replace("__RELEASE_ID__", RELEASE_MANIFESTS["v2"]["release_id"]), media_type="application/javascript", headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Service-Worker-Allowed": "/"})


@app.get("/manifest.webmanifest")
async def manifest():
    return FileResponse(ROOT / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/api/meta")
async def meta(response: Response, request: Request):
    get_session(request, response, create=True)
    current = session_release(request)
    manifest = RELEASE_MANIFESTS[current]
    response.headers["X-Relay-Build"] = RELEASES[current]
    response.headers["X-Release-Id"] = manifest["release_id"]
    response.headers["X-Semantic-Contract"] = manifest["semantic_contract"]
    response.headers["Link"] = ('</__release/manifest.json>; rel="describedby", '
                                 '</__release/manifest/v1.json>; rel="predecessor-version", '
                                 '</api/sync/plan>; rel="related"')
    return {"api_version": API_VERSIONS[current], "build": RELEASES[current], "service": "relay-dispatch",
            "release_id": manifest["release_id"], "semantic_contract": manifest["semantic_contract"],
            "manifest": "/__release/manifest.json", "previous_release_manifest": "/__release/manifest/v1.json",
            "sync_plan": "/api/sync/plan"}


@app.get("/__release/manifest.json")
async def get_release_manifest(request: Request, response: Response):
    session_id, session = get_session(request, response, create=True)
    current = session_release(request)
    manifest = RELEASE_MANIFESTS[current]
    session["manifest"] = {"release_id": manifest["release_id"], "semantic_contract": manifest["semantic_contract"], "seen_at": time.monotonic()}
    body = canonical_json(manifest)
    headers = {"ETag": f'"{hashlib.sha256(body).hexdigest()}"', "Cache-Control": "no-cache",
               "X-Release-Id": manifest["release_id"], "X-Semantic-Contract": manifest["semantic_contract"]}
    if response.headers.get("set-cookie"):
        headers["Set-Cookie"] = response.headers["set-cookie"]
    structured_event("release_manifest_served", release_id=manifest["release_id"], session=session_id)
    return RawResponse(body, media_type="application/json", headers=headers)


@app.get("/__release/manifest/v1.json")
async def get_historical_release_manifest():
    manifest = RELEASE_MANIFESTS["v1"]
    body = canonical_json(manifest)
    return RawResponse(body, media_type="application/json", headers={
        "ETag": f'"{hashlib.sha256(body).hexdigest()}"', "Cache-Control": "no-cache",
        "X-Release-Id": manifest["release_id"], "X-Semantic-Contract": manifest["semantic_contract"],
    })


@app.post("/api/runtime/ready")
async def runtime_ready(request: Request):
    require_same_origin_fetch(request)
    _, session = get_session(request, Response(), create=False)
    if not session or session.get("release") != "v1":
        raise HTTPException(404, "not found")
    worker_key = session.get("worker_key")
    if (not worker_key or worker_key.get("enrolled_release") != "v1"
            or session.get("legacy_profile_revision", 0) < 1):
        raise HTTPException(409, "finish saving the report preference before syncing")
    session["release"] = "v2"
    structured_event("client_release_advanced", session=request.cookies.get("relay_session"))
    return {"status": "accepted", "scheduled": True}


@app.get("/api/jobs")
async def get_jobs():
    return {"items": [public_job(job_id) for job_id in jobs], "updated_at": "2026-09-24T08:40:00Z"}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = public_job(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return {"job": job}


@app.post("/api/jobs/{job_id}/exports", status_code=202)
async def create_report_export(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    if job_id == DIAGNOSTIC_JOB_ID and not _diagnostic_record["published"]:
        raise HTTPException(409, "report is not published")
    if job["status"] != "Report published":
        raise HTTPException(409, "report is not ready for packaging")
    report_version = _diagnostic_record.get("report_version", 1) if job_id == DIAGNOSTIC_JOB_ID else 1
    _prune_exports()
    existing_id = _export_by_report.get((job_id, report_version))
    if existing_id and existing_id in _exports:
        return {"export_id": existing_id, "status": "processing",
                "status_url": f"/api/jobs/{job_id}/exports/{existing_id}"}
    payload = {"job_id": job_id, "title": job["title"], "site": job["site"],
               "diagnostic_reading": _diagnostic_record["reading"] if job_id == DIAGNOSTIC_JOB_ID else None,
               "published_at": _diagnostic_record.get("published_at") if job_id == DIAGNOSTIC_JOB_ID else None,
               "report_version": report_version,
               "package_metadata": _diagnostic_record.get("report_package") if job_id == DIAGNOSTIC_JOB_ID else None}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(f"{EXPORTER_URL}/internal/exports",
                headers={"Authorization": f"Bearer {EXPORTER_TOKEN}"}, json=payload)
        response.raise_for_status()
        created = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "report packaging is temporarily unavailable")
    export_id = created["export_id"]
    _exports[export_id] = {"job_id": job_id, "exporter_id": export_id, "report_version": report_version,
                           "created": time.monotonic(), "expires": time.monotonic() + _state_ttl}
    _export_by_report[(job_id, report_version)] = export_id
    _prune_exports()
    structured_event("report_export_created", job_id=job_id, export_id=export_id)
    return {"export_id": export_id, "status": created["status"],
            "status_url": f"/api/jobs/{job_id}/exports/{export_id}"}


@app.get("/api/jobs/{job_id}/exports/{export_id}")
async def report_export_status(job_id: str, export_id: str):
    record = _exports.get(export_id)
    if not record or record["job_id"] != job_id:
        raise HTTPException(404, "export not found")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{EXPORTER_URL}/internal/exports/{record['exporter_id']}",
                headers={"Authorization": f"Bearer {EXPORTER_TOKEN}"})
        if response.status_code == 404:
            raise HTTPException(404, "export not found")
        response.raise_for_status()
        result = response.json()
    except httpx.HTTPError:
        raise HTTPException(503, "report packaging is temporarily unavailable")
    if result["status"] == "complete":
        result["package_url"] = f"/api/jobs/{job_id}/exports/{export_id}/package"
    return result


@app.get("/api/jobs/{job_id}/exports/{export_id}/package")
async def download_report_export(job_id: str, export_id: str):
    record = _exports.get(export_id)
    if not record or record["job_id"] != job_id:
        raise HTTPException(404, "export not found")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{EXPORTER_URL}/internal/exports/{record['exporter_id']}/package",
                headers={"Authorization": f"Bearer {EXPORTER_TOKEN}"})
        if response.status_code in (404, 409):
            raise HTTPException(response.status_code, "package is not available")
        response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(503, "report packaging is temporarily unavailable")
    return RawResponse(response.content, media_type="application/zip",
                       headers={"Content-Disposition": f'attachment; filename="{job_id}-report.zip"'})


@app.get("/api/activity")
async def get_activity():
    return {"items": activity}


@app.get("/api/drafts")
async def get_drafts():
    return {"items": [public_job(job_id) for job_id, job in jobs.items() if job["status"] in {"Draft", "Awaiting report"}]}


@app.post("/api/sync/worker-key", status_code=201)
async def register_worker_key(key: WorkerKey, request: Request, response: Response):
    require_same_origin_fetch(request)
    try:
        public_key_from_jwk(key.public_key)
        expected_id = key_fingerprint(key.public_key)
    except (KeyError, ValueError, TypeError):
        raise HTTPException(400, "worker signing key is invalid")
    if not secrets.compare_digest(key.key_id, expected_id):
        raise HTTPException(400, "worker signing key id does not match")
    _, session = get_session(request, response, create=False)
    if not session:
        raise HTTPException(403, "offline worker registration is unavailable for this session")
    if session.get("release") != "v1":
        registered = session.get("worker_key")
        if not registered or registered.get("enrolled_release") != "v1" or not secrets.compare_digest(registered["key_id"], key.key_id):
            raise HTTPException(403, "worker registration is no longer available for this session")
    existing = session.get("worker_key")
    if existing and existing["key_id"] != key.key_id:
        raise HTTPException(409, "a worker key is already registered for this Relay session")
    session["worker_key"] = {"key_id": key.key_id, "public_key": key.public_key, "enrolled_release": "v1"}
    structured_event("worker_public_key_registered", key_id=key.key_id)
    return {"status": "registered", "key_id": key.key_id}


def build_sync_plan(session_id: str | None, session: dict[str, Any] | None, response: Response,
                    requested_cycle_id: str | None = None):
    current_release = session.get("release", "v1") if session else "v1"
    manifest = RELEASE_MANIFESTS[current_release]
    response.headers["X-Release-Id"] = manifest["release_id"]
    response.headers["X-Semantic-Contract"] = manifest["semantic_contract"]
    with _state_lock:
        _advance_dispatch_locked()

    if current_release == "v1":
        operation_id = secrets.token_urlsafe(24)
        expires_at = int(time.time() + _operation_ttl)
        plan = {"schema_version": 1, "state": "pending-sync", "sync_id": operation_id,
                "operation_id": operation_id, "work_order_id": "JOB-3844", "mode": "preview",
                "persistence": "outbox", "effects": ["draft:prepare"],
                "source_release": manifest["release_id"], "source_contract": CONTRACTS["v1"],
                "expires_at": expires_at}
        operation_kind = "ordinary"
    else:
        with _state_lock:
            cycle = _dispatch_cycle
            if requested_cycle_id and requested_cycle_id != cycle["cycle_id"]:
                raise HTTPException(409, "dispatch state changed; refresh and try again")
            if cycle["state"] == "collecting":
                raise HTTPException(409, "dispatch sync is not ready yet")
            if cycle["state"] not in {"snapshotted", "staged"}:
                raise HTTPException(409, "dispatch sync has already completed")
            existing_id = cycle.setdefault("operation_ids", {}).get(session_id or "")
            if existing_id:
                existing = _operations.get(existing_id)
                if existing:
                    return existing["plan"]
            snapshot = cycle["snapshot"]
            directive = json.loads(canonical_json(snapshot["report_package"]))
            preference_revision = snapshot["preference_revision"]
            operation_id = secrets.token_urlsafe(24)
            expires_at = int(time.time() + _operation_ttl)
            plan = {"schema_version": 2, "sync_state": "observed", "operation_id": operation_id,
                    "work_order_id": DIAGNOSTIC_JOB_ID,
                    "delivery": {"mode": "preview", "persist": False, "apply_after": "2026-09-24T18:00:00Z"},
                    "effects": ["draft:inspect"], "report_package": directive,
                    "preference_revision": preference_revision, "dispatch_cycle_id": cycle["cycle_id"],
                    "snapshot_digest": snapshot["digest"], "expires_at": expires_at}
            _operations[operation_id] = {"session_id": session_id, "release_id": manifest["release_id"],
                "contract": manifest["semantic_contract"], "plan": plan, "kind": "diagnostic-preview",
                "cycle_id": cycle["cycle_id"], "expires": time.monotonic() + _operation_ttl,
                "legacy_profile": session.get("legacy_profile", "summary") if session else "summary",
                "legacy_profile_revision": session.get("legacy_profile_revision", 0) if session else 0,
                "used": False, "legacy_outbox": None}
            cycle["operation_ids"][session_id or ""] = operation_id
            cycle["operation_id"] = operation_id
            _prune_operations()
            return plan
    with _state_lock:
        _operations[operation_id] = {"session_id": session_id, "release_id": manifest["release_id"],
                                      "contract": manifest["semantic_contract"], "plan": plan,
                                      "kind": operation_kind, "expires": time.monotonic() + _operation_ttl, "used": False,
                                      "legacy_outbox": None}
        _prune_operations()
    return plan


def _prune_operations() -> None:
    now = time.monotonic()
    for old_id, record in list(_operations.items()):
        if record["expires"] < now:
            _operations.pop(old_id, None)
    while len(_operations) > _max_operations:
        oldest = min(_operations, key=lambda key: _operations[key]["expires"])
        _operations.pop(oldest, None)


@app.get("/api/sync/plan")
async def sync_plan(request: Request, response: Response):
    session_id, session = get_session(request, response, create=True)
    return build_sync_plan(session_id, session, response)


@app.post("/api/sync/plan")
async def sync_plan_with_report(report: SyncPlanRequest, request: Request, response: Response):
    session_id, session = get_session(request, response, create=True)
    return build_sync_plan(session_id, session, response, report.cycle_id)


def expected_legacy_materialization(operation: dict[str, Any]) -> dict[str, Any]:
    """Recompute the exact envelope emitted by the legacy v1 adapter."""
    plan = operation["plan"]
    delivered_fields = {**plan, **(plan.get("delivery") or {})}
    package_scope = operation.get("legacy_profile") or plan.get("report_package", {}).get("scope") or "summary"
    return {
        **delivered_fields,
        "schema_version": 1,
        "state": delivered_fields.get("state") or "pending-sync",
        "sync_id": delivered_fields.get("sync_id") or delivered_fields.get("operation_id"),
        "operation_id": delivered_fields.get("operation_id"),
        "persistence": delivered_fields.get("persistence") or "outbox",
        "source_release": operation["release_id"],
        "source_contract": operation["contract"],
        "source_delivery": plan.get("delivery"),
        "source_plan": plan,
        "package_preference_revision": operation.get("legacy_profile_revision", 0),
        "report_package": {"contract": "relay.report-package/v1", "profile": package_scope},
    }


def is_legacy_materialization(operation: dict[str, Any], envelope: dict[str, Any]) -> bool:
    plan = operation["plan"]
    if operation["kind"] != "diagnostic-preview":
        return operation["kind"] == "ordinary"
    if (plan.get("schema_version") != 2
            or plan.get("delivery", {}).get("mode") != "preview"
            or plan.get("delivery", {}).get("persist") is not False
            or plan.get("effects") != ["draft:inspect"]
            or operation.get("contract") != CONTRACTS["v2"]
            or operation.get("legacy_profile_revision", 0) < 1):
        return False
    # Equality also rejects unrecognized fields and duplicate client claims.
    return canonical_json(envelope) == canonical_json(expected_legacy_materialization(operation))


@app.post("/api/sync/outbox")
async def materialize_legacy_outbox(materialization: OutboxMaterialization, request: Request, response: Response):
    """Record the v1 adapter's concrete outbox result before it can be replayed."""
    require_same_origin_fetch(request)
    session_id, session = get_session(request, response, create=False)
    if not session or not session_id:
        raise HTTPException(401, "Relay worker session is missing")
    if session.get("release") != "v2" or (session.get("worker_key") or {}).get("enrolled_release") != "v1":
        raise HTTPException(403, "worker registration is no longer available for this session")
    envelope = materialization.envelope
    operation_id = envelope.get("operation_id")
    with _state_lock:
        operation = _operations.get(operation_id or "")
        if not operation or operation["used"]:
            raise HTTPException(409, detail={"code": "operation_consumed", "message": "offline operation is missing or already replayed"})
        if operation["expires"] < time.monotonic():
            raise HTTPException(410, detail={"code": "operation_expired", "message": "offline operation expired"})
        if operation["session_id"] != session_id:
            raise HTTPException(409, "offline operation belongs to another Relay session")
        if operation["kind"] != "diagnostic-preview" or not is_legacy_materialization(operation, envelope):
            raise HTTPException(409, "queued sync data could not be accepted")

        staged = operation.get("legacy_outbox")
        if staged and canonical_json(staged["envelope"]) != canonical_json(envelope):
            raise HTTPException(409, "queued sync data could not be accepted")
        if not staged:
            operation["legacy_outbox"] = {"envelope": envelope, "stored_at": time.monotonic()}
            if operation.get("cycle_id") == _dispatch_cycle.get("cycle_id") and _dispatch_cycle["state"] == "snapshotted":
                _dispatch_cycle["state"] = "staged"
                _dispatch_cycle["staged_at"] = time.time()
            structured_event("legacy_outbox_materialized", operation_id=operation_id)
        result = {"sync_id": operation_id, "status": "queued"}
        if CHECKPOINT_FLAG:
            result["reconciliation_receipt"] = CHECKPOINT_FLAG
        return result


@app.post("/api/sync/replay")
async def replay_sync(replay: ReplayRequest, request: Request, response: Response):
    require_same_origin_fetch(request)
    session_id, session = get_session(request, response, create=False)
    if not session or not session_id:
        raise HTTPException(401, "Relay worker session is missing")
    registered = session.get("worker_key")
    if (session.get("release") != "v2" or not registered or registered.get("enrolled_release") != "v1"
            or not secrets.compare_digest(registered["key_id"], replay.key_id)):
        raise HTTPException(401, "replay signing key is not registered for this Relay session")
    if not replay.signature:
        raise HTTPException(401, "signed offline replay required")

    try:
        raw = base64.urlsafe_b64decode(replay.signature + "=" * (-len(replay.signature) % 4))
        if len(raw) != 64:
            raise ValueError("unexpected ECDSA signature length")
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        key = public_key_from_jwk(registered["public_key"])
        key.verify(encode_dss_signature(r, s), canonical_json({"key_id": replay.key_id, "envelope": replay.envelope}), ec.ECDSA(hashes.SHA256()))
    except (ValueError, KeyError, InvalidSignature):
        raise HTTPException(401, "offline replay signature is invalid")

    envelope = replay.envelope
    operation_id = envelope.get("operation_id")
    with _state_lock:
        operation = _operations.get(operation_id or "")
        if not operation or operation["used"]:
            raise HTTPException(409, detail={"code": "operation_consumed", "message": "offline operation is missing or already replayed"})
        if operation["expires"] < time.monotonic():
            raise HTTPException(410, detail={"code": "operation_expired", "message": "offline operation expired"})
        if operation["session_id"] != session_id:
            raise HTTPException(409, "offline operation belongs to another Relay session")
        if not is_legacy_materialization(operation, envelope):
            raise HTTPException(409, "queued sync data does not match this operation")
        staged = operation.get("legacy_outbox")
        if not staged or canonical_json(staged["envelope"]) != canonical_json(envelope):
            raise HTTPException(409, "queued sync data could not be accepted")
        cycle = _dispatch_cycle
        if cycle.get("cycle_id") != operation.get("cycle_id") or cycle.get("state") != "staged":
            raise HTTPException(409, "dispatch cycle is no longer available")
        cycle["replay_attempts"] += 1
        plan = operation["plan"]
        package = envelope["report_package"]
        operation["used"] = True
        if package.get("profile") == "complete":
            jobs[DIAGNOSTIC_JOB_ID]["status"] = "Report published"
            _diagnostic_record["reading"] = DIAGNOSTIC_READING
            _diagnostic_record["report_package"] = package
            _diagnostic_record["preference_revision"] = plan.get("preference_revision")
            _diagnostic_record["dispatch_cycle_id"] = operation.get("cycle_id")
            _diagnostic_record["published"] = True
            _diagnostic_record["published_at"] = datetime.now(timezone.utc).isoformat()
            _diagnostic_record["report_version"] = int(_diagnostic_record.get("report_version", 0)) + 1
            structured_event("diagnostic_report_published", operation_id=operation_id)
        _report_preference["processed_revision"] = max(
            _report_preference["processed_revision"], int(plan.get("preference_revision") or 0))
        cycle["state"] = "processed"
        cycle["processed_at"] = time.time()
        cycle["next_cycle_at"] = cycle["processed_at"] + _dispatch_cooldown_seconds
        structured_event("dispatch_cycle_processed", cycle_id=cycle["cycle_id"],
                         revision=plan.get("preference_revision"), published=package.get("profile") == "complete")
    structured_event("legacy_sync_replayed", key_id=replay.key_id, operation_id=operation_id)
    result = {"sync_id": operation_id, "status": "accepted"}
    if operation["kind"] == "diagnostic-preview":
        result["report_status"] = "published" if _diagnostic_record["published"] else "not-published"
    return result
