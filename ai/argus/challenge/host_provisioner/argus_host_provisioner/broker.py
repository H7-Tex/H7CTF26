from __future__ import annotations

import base64
import hmac
import hmac
import json
import os
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, Request as FastRequest
from fastapi.responses import JSONResponse
import uvicorn

from argus.kubernetes import DeploymentProfile
from .common import parse_create_request, runtime_label, workload, workload_name


API = "https://kubernetes.default.svc"
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
MAX = 256_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
NAMESPACE = os.getenv("POD_NAMESPACE", "")
INSTANCE_ID = os.getenv("INSTANCE_ID", "")
TOKEN = os.getenv("ARGUS_K8S_BROKER_TOKEN", "")
WORKER_IMAGE = os.getenv("ARGUS_WORKER_IMAGE", "")
ELEVATED_IMAGE = os.getenv("ARGUS_ELEVATED_IMAGE", "")


def _context():
    return ssl.create_default_context(cafile=f"{SA}/ca.crt")


def _kube(method: str, path: str, body: dict | None = None) -> dict:
    request = Request(
        f"{API}{path}",
        data=json.dumps(body, separators=(",", ":")).encode() if body is not None else None,
        method=method,
        headers={
            "Authorization": "Bearer " + open(f"{SA}/token", encoding="utf-8").read().strip(),
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urlopen(request, context=_context(), timeout=10) as response:
            raw = response.read(MAX + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise KeyError("not found") from exc
        raise RuntimeError("Kubernetes broker operation failed") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Kubernetes broker operation failed") from exc
    if len(raw) > MAX:
        raise RuntimeError("Kubernetes response too large")
    return json.loads(raw) if raw else {}


def _owned(deployment_id: str) -> tuple[str, str]:
    if not _ID.fullmatch(deployment_id):
        raise HTTPException(404, "not found")
    return workload_name(INSTANCE_ID, deployment_id), runtime_label(INSTANCE_ID, deployment_id)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def bounded_auth(request: FastRequest, call_next):
    if not hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {TOKEN}"):
        return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    try:
        content_length = int(request.headers.get("content-length", "0") or 0)
    except ValueError:
        return JSONResponse({"error": "invalid request"}, status_code=400)
    if not 0 <= content_length <= 16_384:
        return JSONResponse({"error": "request too large"}, status_code=413)
    return await call_next(request)


@app.post("/v1/workloads")
async def create_workload(request: FastRequest):
    raw = await request.body()
    if len(raw) > 16_384:
        raise HTTPException(413, "request too large")
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(400, "invalid request")
    try:
        deployment_id, profile = parse_create_request(body)
        manifest = workload(INSTANCE_ID, deployment_id, profile, NAMESPACE, WORKER_IMAGE, ELEVATED_IMAGE)
    except (ValueError, TypeError):
        raise HTTPException(400, "invalid request")
    try:
        _kube("POST", f"/apis/apps/v1/namespaces/{quote(NAMESPACE, safe='')}/deployments", manifest)
    except RuntimeError:
        raise HTTPException(502, "workload operation failed")
    return {"created": True}


@app.get("/v1/workloads/{deployment_id}/readiness")
async def readiness(deployment_id: str):
    name, _ = _owned(deployment_id)
    try:
        value = _kube("GET", f"/apis/apps/v1/namespaces/{quote(NAMESPACE, safe='')}/deployments/{quote(name, safe='')}")
    except KeyError:
        raise HTTPException(404, "not found")
    except RuntimeError:
        raise HTTPException(502, "workload operation failed")
    meta, spec, status = value.get("metadata", {}), value.get("spec", {}), value.get("status", {})
    if meta.get("namespace") != NAMESPACE or meta.get("name") != name:
        raise HTTPException(502, "invalid workload evidence")
    ready = spec.get("replicas") == 1 and status.get("observedGeneration") == meta.get("generation") and status.get("availableReplicas", 0) >= 1
    return {"ready": bool(ready)}


@app.get("/v1/workloads/{deployment_id}/evidence")
async def evidence(deployment_id: str):
    name, label = _owned(deployment_id)
    try:
        listing = _kube("GET", f"/api/v1/namespaces/{quote(NAMESPACE, safe='')}/pods?" + urlencode({"labelSelector": f"argus.instance={NAMESPACE},argus.deployment={label}"}))
        pods = listing.get("items")
        if not isinstance(pods, list) or len(pods) != 1:
            raise HTTPException(502, "invalid workload evidence")
        pod = pods[0]
        metadata, spec = pod.get("metadata", {}), pod.get("spec", {})
        if metadata.get("namespace") != NAMESPACE or spec.get("serviceAccountName") not in {"argus-worker", "argus-elevated"}:
            raise HTTPException(502, "invalid workload evidence")
        pod_name = metadata.get("name")
        if not isinstance(pod_name, str) or not pod_name.startswith(name):
            raise HTTPException(502, "invalid workload evidence")
        # The worker prints its result a beat after the container reports "ready"
        # (it does an apiserver read first), so the log can be empty on the first
        # look. Poll it until the JSON line lands rather than 502ing on the race.
        result = None
        for _ in range(8):   # ~10s max, under the app's 15s evidence-call timeout
            raw = urlopen(Request(
                f"{API}/api/v1/namespaces/{quote(NAMESPACE, safe='')}/pods/{quote(pod_name, safe='')}/log?container=workload",
                headers={"Authorization": "Bearer " + open(f"{SA}/token", encoding="utf-8").read().strip()},
            ), context=_context(), timeout=10).read(MAX + 1)
            if len(raw) > MAX:
                raise HTTPException(502, "invalid workload evidence")
            raw = raw.strip()
            if raw:
                try:
                    result = json.loads(raw)
                    break
                except ValueError:
                    pass
            time.sleep(1)
        if not isinstance(result, dict) or set(result) != {"kind", "profile", "resource", "status", "isolation_verified", "verification_result"}:
            raise HTTPException(502, "invalid workload evidence")
        return {"ready": True, "runtime_result": result}
    except HTTPException:
        raise
    except (KeyError, ValueError, OSError, URLError, HTTPError):
        raise HTTPException(502, "workload evidence unavailable")


@app.delete("/v1/workloads/{deployment_id}")
async def delete_workload(deployment_id: str):
    name, _ = _owned(deployment_id)
    try:
        _kube("DELETE", f"/apis/apps/v1/namespaces/{quote(NAMESPACE, safe='')}/deployments/{quote(name, safe='')}")
    except RuntimeError:
        raise HTTPException(502, "workload cleanup failed")
    return {"deleted": True}


def main() -> None:
    if not all((NAMESPACE, INSTANCE_ID, TOKEN, WORKER_IMAGE, ELEVATED_IMAGE)):
        raise RuntimeError("Kubernetes broker settings are incomplete")
    uvicorn.run(app, host="0.0.0.0", port=8085)


if __name__ == "__main__":
    main()
