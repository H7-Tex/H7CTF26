"""The single public ARGUS surface.

Portal is deliberately boring: it exposes fixed player workflows and uses one
fixed, role-owned client for each internal service.  It is not a reverse proxy.
"""

from __future__ import annotations

import json
import math
import os
import re
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .a2a import A2A_JSON_MEDIA_TYPE
from .config import MAX_REQUEST_BODY_BYTES, Settings
from .registry import KNOWN_PACKAGE_ID


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_APPROVAL_FIELDS = frozenset(
    {
        "approval_id",
        "task_id",
        "control_id",
        "target",
        "granted_capability",
        "expires_at",
        "key_id",
        "signature",
    }
)
_A2A_QUERY_FIELDS = frozenset({"A2A-Version", "historyLength"})
_MAX_UPSTREAM_BYTES = MAX_REQUEST_BODY_BYTES
_DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 5.0
_MAX_CONFIGURED_UPSTREAM_TIMEOUT_SECONDS = 3_600.0
# Four bounded 30-second planner calls plus internal HTTP overhead.
_INCIDENT_ANALYSIS_TIMEOUT_SECONDS = 150.0


class PortalUpstreamError(RuntimeError):
    """An internal service failed without exposing its details to the player."""


def _deployment_upstream_timeout() -> float:
    raw = os.getenv(
        "ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS",
        str(_DEFAULT_UPSTREAM_TIMEOUT_SECONDS),
    )
    try:
        timeout = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > _MAX_CONFIGURED_UPSTREAM_TIMEOUT_SECONDS:
        raise ValueError(
            "ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS must be between 0 and 3600 seconds"
        )
    return timeout


def _a2a_error(reason: str, message: str = "Invalid A2A request", status_code: int = 400) -> Response:
    return JSONResponse(
        {
            "error": {
                "code": status_code,
                "status": "FAILED_PRECONDITION" if reason == "VERSION_NOT_SUPPORTED" else "INVALID_ARGUMENT",
                "message": message,
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": reason,
                    "domain": "a2a-protocol.org",
                }],
            }
        },
        status_code=status_code,
        media_type=A2A_JSON_MEDIA_TYPE,
    )


class _FixedServiceClient:
    def __init__(
        self,
        base_url: str,
        edge: str,
        client: httpx.AsyncClient | None = None,
        *,
        timeout: float = _DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    ):
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"), timeout=timeout
        )
        self._owns_client = client is None
        self._edge = edge

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self._edge}"
        try:
            response = await self._client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise PortalUpstreamError("internal service unavailable") from exc
        if len(response.content) > _MAX_UPSTREAM_BYTES:
            raise PortalUpstreamError("internal response exceeded its bound")
        return response


class PortalRegistryClient(_FixedServiceClient):
    async def register(self, body: dict[str, Any]) -> httpx.Response:
        return await self._request("POST", "/api/integrations", json=body)

    async def list_integrations(self) -> httpx.Response:
        return await self._request("GET", "/api/integrations")

    async def catalog(self) -> httpx.Response:
        return await self._request("GET", "/api/catalog")

    async def integration(self, integration_id: str) -> httpx.Response:
        return await self._request("GET", f"/api/integrations/{integration_id}")

    async def approve(self, integration_id: str) -> httpx.Response:
        return await self._request("POST", f"/api/integrations/{integration_id}/approve")

    async def runtime_metadata(self, integration_id: str, body: dict[str, Any]) -> httpx.Response:
        return await self._request(
            "PATCH", f"/api/integrations/{integration_id}/runtime-metadata", json=body
        )

    async def tools(self, integration_id: str) -> httpx.Response:
        return await self._request("GET", f"/api/integrations/{integration_id}/tools")

    async def deliveries(self, integration_id: str) -> httpx.Response:
        return await self._request("GET", f"/api/integrations/{integration_id}/deliveries")


class PortalAgentsClient(_FixedServiceClient):
    async def incident(self, body: dict[str, Any], integration_id: str | None = None) -> httpx.Response:
        path = f"/api/incidents/{integration_id}" if integration_id else "/api/incidents"
        return await self._request(
            "POST", path, json=body, timeout=_INCIDENT_ANALYSIS_TIMEOUT_SECONDS
        )

    async def read_incident(self, incident_id: str) -> httpx.Response:
        return await self._request("GET", f"/api/incidents/{incident_id}")

    async def selection_diagnostics(self, incident_id: str) -> httpx.Response:
        return await self._request("GET", f"/internal/incidents/{incident_id}/selection")

    async def agent_card(self) -> httpx.Response:
        return await self._request("GET", "/.well-known/agent-card.json", headers={"Authorization": ""})

    async def a2a(self, method: str, path: str, *, body: bytes = b"", headers: dict[str, str], params: list[tuple[str, str]]) -> httpx.Response:
        return await self._request(method, path, content=body, headers=headers, params=params)


class PortalDeploymentClient(_FixedServiceClient):
    async def create(self, body: dict[str, Any]) -> httpx.Response:
        return await self._request("POST", "/api/deployments", json=body)

    async def get(self, deployment_id: str) -> httpx.Response:
        return await self._request("GET", f"/api/deployments/{deployment_id}")

    async def delete(self, deployment_id: str) -> httpx.Response:
        return await self._request("DELETE", f"/api/deployments/{deployment_id}")


def _read_response(response: httpx.Response) -> Response:
    if response.status_code in {401, 403}:
        return JSONResponse({"error": "internal service unavailable"}, status_code=502)
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise PortalUpstreamError("internal response was invalid") from exc
    return JSONResponse(payload, status_code=response.status_code)


async def _read_object(request: Request) -> tuple[dict[str, Any] | None, Response | None]:
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        return None, JSONResponse({"error": "request rejected"}, status_code=413)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)
    if not isinstance(value, dict):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)
    return value, None


def _safe_id(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value))


def _a2a_query(request: Request) -> list[tuple[str, str]] | None:
    if any(key not in _A2A_QUERY_FIELDS for key in request.query_params):
        return None
    return list(request.query_params.multi_items())


def _a2a_response(response: httpx.Response) -> Response:
    if len(response.content) > _MAX_UPSTREAM_BYTES:
        raise PortalUpstreamError("A2A response exceeded its bound")
    if response.status_code in {401, 403}:
        return _a2a_error("UPSTREAM_UNAVAILABLE", "A2A service unavailable", 502)
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != A2A_JSON_MEDIA_TYPE:
        raise PortalUpstreamError("A2A response media type was invalid")
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers={"content-type": response.headers["content-type"]},
    )


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGUS Operations Portal</title>
<style>
:root{color-scheme:light;font-family:"Segoe UI Variable","Segoe UI",ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,sans-serif;color:#14212b;background:#eef3f4;--ink:#14212b;--muted:#5d6d76;--navy:#102d3c;--navy-2:#194657;--teal:#0d7b78;--teal-dark:#075b5a;--line:#d5e0e2;--soft:#f6f9f9;--amber:#bf7b19;--red:#b84747}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#eef3f4}::selection{background:#b9e5e0;color:#102d3c}
header{background:var(--navy);color:#fff;border-bottom:1px solid #385866;padding:22px clamp(20px,5vw,72px) 0}.masthead{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;max-width:1440px;margin:0 auto}.brand{display:flex;align-items:center;gap:12px}.mark{display:grid;place-items:center;width:34px;height:34px;border:1px solid #8ad6d1;border-radius:10px;color:#b9f1ec;font-size:14px;font-weight:800;letter-spacing:.06em}.brand h1{margin:0;font-size:1.06rem;letter-spacing:.08em;text-transform:uppercase}.brand p{margin:4px 0 0;color:#b8cdd1;font-size:.86rem}.environment{padding:6px 10px;border:1px solid #4e7480;border-radius:999px;color:#d5eeec;font-size:.73rem;letter-spacing:.08em;text-transform:uppercase}.nav{display:flex;gap:4px;max-width:1440px;margin:24px auto 0;overflow:auto}.nav button{position:relative;border:0;border-radius:9px 9px 0 0;background:transparent;color:#b8cdd1;padding:12px 16px;font:inherit;font-size:.9rem;white-space:nowrap}.nav button:hover{color:#fff;background:#173d4b}.nav button.active{color:#fff;background:#eef3f4}.nav button.active::after{content:"";position:absolute;right:16px;bottom:-4px;left:16px;height:4px;background:#d6a245}
main{width:min(1440px,100%);margin:0 auto;padding:36px clamp(20px,5vw,72px) 72px}.view{animation:surface-in .28s ease-out}.view[hidden]{display:none}@keyframes surface-in{from{opacity:.35;transform:translateY(5px)}to{opacity:1;transform:none}}.page-head{display:flex;justify-content:space-between;align-items:end;gap:24px;margin-bottom:26px}.page-head h2{max-width:14ch;margin:0;color:var(--navy);font-size:clamp(2rem,4vw,3.7rem);line-height:.98;letter-spacing:-.035em}.page-head p{max-width:62ch;margin:0;color:var(--muted);line-height:1.55}.eyebrow{margin:0 0 10px;color:var(--teal-dark);font-size:.74rem;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.summary-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:24px}.summary{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px 20px;box-shadow:0 8px 24px #102d3c0c}.summary strong{display:block;color:var(--navy);font-size:1.03rem}.summary span{display:block;margin-top:7px;color:var(--muted);font-size:.84rem;line-height:1.4}.layout{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(280px,.7fr);gap:18px}.panel{background:#fff;border:1px solid var(--line);border-radius:14px;padding:24px;box-shadow:0 8px 24px #102d3c0c}.panel h3{margin:0;color:var(--navy);font-size:1.15rem;letter-spacing:-.015em}.panel h4{margin:25px 0 9px;color:var(--navy);font-size:.82rem;letter-spacing:.08em;text-transform:uppercase}.panel-intro{margin:8px 0 18px;color:var(--muted);font-size:.91rem;line-height:1.5}.stack{display:grid;gap:14px}.toolbar{display:flex;flex-wrap:wrap;align-items:end;gap:10px}.toolbar .field{flex:1 1 240px}.field{display:grid;gap:7px}.field label,.field>span{color:#32464f;font-size:.82rem;font-weight:700}.field small,.help{color:var(--muted);font-size:.79rem;line-height:1.45}.field small{font-weight:400}.action-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.button{border:1px solid var(--teal);border-radius:8px;background:var(--teal);color:#fff;padding:10px 14px;font:inherit;font-size:.86rem;font-weight:750;cursor:pointer}.button:hover{background:var(--teal-dark);border-color:var(--teal-dark)}.button.secondary{background:#fff;color:var(--teal-dark);border-color:#9fcac8}.button.secondary:hover{background:#eef9f8}.button.subtle{background:#edf3f4;border-color:#d0dfe1;color:#32464f}.button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,.nav button:focus-visible{outline:3px solid #e2ad51;outline-offset:2px}input,select,textarea{width:100%;border:1px solid #bacbd0;border-radius:8px;background:#fff;color:var(--ink);padding:10px 11px;font:inherit;font-size:.9rem}input::placeholder,textarea::placeholder{color:#829197}textarea{min-height:150px;resize:vertical;line-height:1.5}textarea.code,pre,code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}textarea.code{font-size:.82rem}.code-block{min-height:145px;max-height:440px;overflow:auto;margin:0;white-space:pre-wrap;word-break:break-word;border:1px solid #d9e3e5;border-radius:9px;background:#f7fafb;color:#243941;padding:14px;font-size:.78rem;line-height:1.55}.empty{color:#718188}.notice{border:1px solid #dae5e5;border-radius:9px;background:#f7fafb;padding:13px 14px;color:#4d626b;font-size:.83rem;line-height:1.5}.notice strong{color:var(--navy)}.table-wrap{overflow:auto;border:1px solid #d9e3e5;border-radius:10px}.data-table{width:100%;border-collapse:collapse;min-width:580px}.data-table th,.data-table td{padding:12px 14px;border-bottom:1px solid #e7eeee;text-align:left;vertical-align:top;font-size:.83rem}.data-table th{background:#f7fafb;color:#5d6d76;font-size:.7rem;letter-spacing:.1em;text-transform:uppercase}.data-table tr:last-child td{border-bottom:0}.data-table code{font-size:.78rem;color:#245a61}.status{display:inline-flex;align-items:center;gap:7px;color:#25655f;font-size:.78rem;font-weight:750}.status::before{content:"";width:7px;height:7px;border-radius:50%;background:#38a28b}.summary-list{display:grid;gap:11px;margin:0;padding:0;list-style:none}.summary-list li{display:flex;justify-content:space-between;gap:16px;border-bottom:1px solid #e7eeee;padding-bottom:11px;color:#4d626b;font-size:.84rem}.summary-list li:last-child{border-bottom:0;padding-bottom:0}.summary-list strong{color:var(--navy);font-weight:700}.two-col{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.three-col{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.result-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.result-field{border:1px solid #e0e9ea;border-radius:9px;padding:12px;background:#fbfcfc}.result-field span{display:block;color:#718188;font-size:.7rem;letter-spacing:.08em;text-transform:uppercase}.result-field strong{display:block;margin-top:5px;color:var(--navy);font-size:.9rem;overflow-wrap:anywhere}.result-field.wide{grid-column:1/-1}.events{margin:10px 0 0;padding-left:21px;color:#49616a;font-size:.84rem;line-height:1.8}.events code{color:#245a61;font-size:.77rem}.signals{display:flex;flex-wrap:wrap;gap:8px}.signal{display:flex;align-items:center;gap:7px;border:1px solid #d6e2e3;border-radius:8px;padding:9px 10px;color:#49616a;font-size:.82rem}.signal input{width:auto;margin:0;accent-color:var(--teal)}.reference-table{width:100%;border-collapse:collapse}.reference-table th,.reference-table td{padding:10px 0;border-bottom:1px solid #e4ecec;text-align:left;vertical-align:top;font-size:.82rem}.reference-table th{width:43%;color:#354b54;font-weight:700}.reference-table td{color:#60727a}.reference-table code{color:#245a61;font-size:.77rem}.split-result{display:grid;gap:12px}.section-rule{height:1px;margin:22px 0;background:#e5eded}.footer-note{margin-top:24px;color:#77878d;font-size:.76rem;line-height:1.5}.danger{color:var(--red)}
@media(max-width:920px){.layout{grid-template-columns:1fr}.page-head{display:block}.page-head p{margin-top:16px}.summary-strip{grid-template-columns:1fr}.three-col{grid-template-columns:1fr}}
@media(max-width:620px){header{padding-left:18px;padding-right:18px}.masthead{display:block}.environment{display:inline-block;margin-top:15px}main{padding:28px 16px 48px}.nav{margin-top:18px}.nav button{padding:11px 12px;font-size:.82rem}.panel{padding:18px}.two-col,.result-grid{grid-template-columns:1fr}.result-field.wide{grid-column:auto}.page-head h2{font-size:2.5rem}}
</style><style>@media(min-width:921px){.summary-strip{grid-template-columns:repeat(4,minmax(0,1fr))}}</style></head><body>
<header><div class="masthead"><div class="brand"><div class="mark" aria-hidden="true">A</div><div><h1>ARGUS Operations Portal</h1><p>Enterprise integration, incident, and runtime operations</p></div></div></div><nav class="nav" aria-label="Primary navigation"><button class="active" data-view="overview" aria-current="page">Overview</button><button data-view="integrations">Integrations</button><button data-view="incidents">Incidents</button><button data-view="interop">Agent Interop</button><button data-view="runtime">Runtime</button></nav></header>
<main>
<section id="view-overview" class="view" aria-labelledby="overview-title"><div class="page-head"><div><p class="eyebrow">ARGUS / Operations</p><h2 id="overview-title">Operations Overview</h2></div><p>View integrations, incident activity, agent connections, and deployment status.</p></div><div class="summary-strip"><div class="summary"><strong id="overview-integration-count">Not loaded</strong><span>Registered integrations</span></div><div class="summary"><strong id="overview-incident-status">Incident records</strong><span>Incident activity</span></div><div class="summary"><strong>Available</strong><span>Agent interoperability</span></div><div class="summary"><strong>Available</strong><span>Runtime operations</span></div></div><div class="layout"><section class="panel"><h3>Service status</h3><ul class="summary-list"><li><strong>Package registry</strong><span class="status">Available</span></li><li><strong>Incident operations</strong><span class="status">Available</span></li><li><strong>Agent interoperability</strong><span class="status">Available</span></li><li><strong>Deployment runtime</strong><span class="status">Available</span></li></ul></section><section class="panel"><h3>Recent integrations</h3><p class="panel-intro">A compact view of registered integrations in this instance.</p><div id="overview-integrations" class="code-block"><span class="empty">Use Refresh to load the current registry state.</span></div><div class="action-row" style="margin-top:12px"><button id="overview-refresh" class="button secondary">Refresh</button></div></section></div></section>

<section id="view-integrations" class="view" aria-labelledby="integrations-title" hidden><div class="page-head"><div><p class="eyebrow">Registry / Runtime</p><h2 id="integrations-title">Integrations</h2></div><p>Browse package identity, inspect approved integration details, and review the live runtime catalog and delivery inbox.</p></div><div class="layout"><div class="stack"><section class="panel"><h3>Available Packages</h3><p class="panel-intro">Available packages are listed by the organization registry.</p><div id="package-table" class="table-wrap"><table class="data-table"><thead><tr><th>Package</th><th>Publisher type</th><th>Runtime</th></tr></thead><tbody><tr><td><code>vendor-incident-review</code></td><td>community</td><td>mcp</td></tr></tbody></table></div><div class="toolbar" style="margin-top:14px"><div class="field"><label for="package-id">Package ID</label><input id="package-id" value="vendor-incident-review" autocomplete="off"></div><button id="refresh-packages" class="button secondary">Refresh packages</button><button id="register" class="button">Register package</button></div></section><section class="panel"><h3>Integration details</h3><p class="panel-intro">View package details, approval status, and runtime information.</p><div class="toolbar"><div class="field"><label for="integration-id">Integration ID</label><input id="integration-id" autocomplete="off" placeholder="Enter an integration ID"></div><button id="load-integration" class="button secondary">Load details</button><button id="approve" class="button">Approve integration</button></div><div class="two-col" style="margin-top:18px"><div><h4>Package information</h4><div id="integration-detail" class="code-block"><span class="empty">No integration selected.</span></div></div><div><h4>Runtime catalog</h4><div id="catalog-result" class="code-block"><span class="empty">No catalog loaded.</span></div></div></div><div class="action-row" style="margin-top:14px"><button id="catalog" class="button secondary">Load runtime catalog</button><button id="deliveries" class="button secondary">Open delivery inbox</button></div><div class="section-rule"></div><h4>Runtime metadata</h4><p class="help">Update the description published in the runtime catalog.</p><label class="field" for="service-summary"><span>Service summary</span><textarea id="service-summary" placeholder="Describe the operational purpose of this integration"></textarea></label><div class="action-row"><button id="update-summary" class="button">Update runtime metadata</button></div><h4>Delivery inbox</h4><div id="delivery-result" class="code-block"><span class="empty">No deliveries loaded.</span></div></section></div></div></section>

<section id="view-incidents" class="view" aria-labelledby="incidents-title" hidden><div class="page-head"><div><p class="eyebrow">Operations / Casework</p><h2 id="incidents-title">Incident operations</h2></div><p>Create an incident and review the resulting case record.</p></div><div class="layout"><section class="panel"><h3>New incident</h3><div class="two-col"><label class="field"><span>Integration ID</span><input id="incident-integration-id" autocomplete="off" placeholder="Enter an integration ID"></label><label class="field"><span>Incident type</span><select id="incident-type"><option value="deployment-anomaly">Deployment anomaly</option></select></label><label class="field"><span>Severity</span><select id="incident-severity"><option value="low">Low</option><option value="medium">Medium</option><option value="high" selected>High</option><option value="critical">Critical</option></select></label><label class="field"><span>Affected service</span><select id="affected-service"><option value="runtime-controller">Runtime controller</option><option value="deployment-worker">Deployment worker</option></select></label></div><div class="field" style="margin-top:16px"><span>Signals</span><div class="signals"><label class="signal"><input type="checkbox" name="signal" value="policy-drift" checked> Policy drift</label><label class="signal"><input type="checkbox" name="signal" value="vendor-review-required"> Vendor review required</label><label class="signal"><input type="checkbox" name="signal" value="configuration-drift"> Configuration drift</label></div></div><div class="action-row" style="margin-top:18px"><button id="submit-incident" class="button">Submit incident</button><label class="field" style="min-width:220px"><span>Incident ID</span><input id="incident-id" autocomplete="off" placeholder="Returned after submission"></label><button id="read-incident" class="button secondary">Read incident</button></div></section><section class="panel"><h3>Incident record</h3><div id="incident-record" hidden></div><div id="incident-result" class="code-block"><span class="empty">No incident loaded.</span></div></section></div></section>

<section id="view-interop" class="view" aria-labelledby="interop-title" hidden><div class="page-head"><div><p class="eyebrow">Interoperability / A2A</p><h2 id="interop-title">Agent interop</h2></div><p>Send and inspect A2A messages.</p></div><div class="layout"><div class="stack"><section class="panel"><h3>Agent Card</h3><p class="panel-intro">The public Agent Card describes the supported HTTP+JSON interface and skill.</p><div class="action-row"><button id="agent-card" class="button secondary">Load Agent Card</button></div><div id="agent-card-result" class="code-block" style="margin-top:14px"><span class="empty">No Agent Card loaded.</span></div></section><section class="panel"><h3>A2A API reference</h3><p class="panel-intro">A2A request format</p><table class="reference-table"><tbody><tr><th>Interface</th><td><code>POST /message:send</code></td></tr><tr><th>Protocol header</th><td><code>A2A-Version: 1.0</code></td></tr><tr><th>Content type</th><td><code>application/a2a+json</code></td></tr><tr><th>Message role</th><td><code>ROLE_USER</code></td></tr><tr><th>Parts</th><td>Exactly one JSON data Part with media type <code>application/json</code></td></tr><tr><th>Message source</th><td><code>sourceType</code> must be <code>external-partner</code></td></tr><tr><th>Review data</th><td><code>type</code> must be <code>deployment-review</code>; <code>control_id</code> and <code>target</code> are instance-bound strings; <code>recommendation</code> must be <code>approve</code></td></tr><tr><th>Output mode</th><td><code>configuration.acceptedOutputModes</code> includes <code>application/json</code></td></tr><tr><th>Skill</th><td><code>deployment-control-review</code></td></tr></tbody></table></section><section class="panel"><h3>Message tester</h3><p class="panel-intro">Enter a SendMessage request.</p><label class="field" for="a2a-request"><span>SendMessage request</span><textarea id="a2a-request" class="code" spellcheck="false" placeholder="Paste or type a JSON SendMessage request"></textarea></label><div class="action-row" style="margin-top:12px"><button id="send-a2a" class="button">SendMessage</button></div></section></div><aside class="panel"><h3>Task lookup</h3><p class="panel-intro">Retrieve a task by ID.</p><div class="toolbar"><div class="field"><label for="task-id">Task ID</label><input id="task-id" autocomplete="off" placeholder="Enter a task ID"></div><button id="read-task" class="button secondary">Get Task</button></div><div id="task-summary" class="result-grid" hidden></div><h4>Task response</h4><div id="task-result" class="code-block"><span class="empty">No task loaded.</span></div></aside></div></section>

<section id="view-runtime" class="view" aria-labelledby="runtime-title" hidden><div class="page-head"><div><p class="eyebrow">Runtime / Deployments</p><h2 id="runtime-title">Runtime</h2></div><p>Review deployment records and submit a signed deployment approval.</p></div><div class="layout"><section class="panel"><h3>Deployment request</h3><p class="panel-intro">The runtime accepts a signed deployment approval. Deployment settings are determined from the approval.</p><label class="field" for="approval"><span>Signed deployment approval</span><textarea id="approval" class="code" spellcheck="false" placeholder="Paste a signed deployment approval JSON object"></textarea></label><div class="action-row" style="margin-top:12px"><button id="deploy" class="button">Create deployment</button></div><div class="section-rule"></div><div class="toolbar"><div class="field"><label for="deployment-id">Deployment ID</label><input id="deployment-id" autocomplete="off" placeholder="Enter a deployment ID"></div><button id="read-deployment" class="button secondary">Read deployment</button><button id="delete-deployment" class="button subtle">Remove deployment</button></div></section><section class="panel"><h3>Deployment result</h3><div id="deployment-summary" class="result-grid" hidden></div><div id="deployment-result" class="code-block"><span class="empty">No deployment loaded.</span></div></section></div></section>
</main>
<script>
const $=id=>document.getElementById(id);
const show=(id,value)=>$(id).textContent=typeof value==='string'?value:JSON.stringify(value,null,2);
const call=async(path,opts={})=>{const r=await fetch(path,opts);const text=await r.text();let value;try{value=JSON.parse(text)}catch{value=text}if(!r.ok)throw value;return value};
const json=(method='POST')=>({headers:{'content-type':'application/json'},method});
async function run(fn,out){try{return await fn()}catch(e){show(out,e);throw e}}
function encode(value){return encodeURIComponent(value.trim())}
function packageBody(){return {...json(),body:JSON.stringify({package_id:$('package-id').value.trim()})}}
function approvalBody(){return {...json(),body:JSON.stringify(JSON.parse($('approval').value))}}
function renderPackages(value){const packages=Array.isArray(value?.packages)?value.packages:[];const rows=packages.length?packages.map(item=>`<tr><td><code>${escapeHtml(item.package_id||'')}</code></td><td>${escapeHtml(item.publisher_class||'')}</td><td>${escapeHtml(item.runtime||'')}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No packages returned.</td></tr>';$('package-table').innerHTML=`<table class="data-table"><thead><tr><th>Package</th><th>Publisher type</th><th>Runtime</th></tr></thead><tbody>${rows}</tbody></table>`}
function escapeHtml(value){return String(value).replace(/[&<>"']/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]))}
function displayValue(value){return value&&typeof value==='object'?JSON.stringify(value):String(value)}
function renderIncident(value){show('incident-result',value);const record=$('incident-record');const blocks=[];const fields=[['status','Status'],['incident_id','Incident ID']].filter(([key])=>Object.prototype.hasOwnProperty.call(value||{},key));if(fields.length)blocks.push(`<div class="result-grid">${fields.map(([key,label])=>`<div class="result-field"><span>${label}</span><strong>${escapeHtml(displayValue(value[key]))}</strong></div>`).join('')}</div>`);if(Array.isArray(value?.events))blocks.push(`<h4>Timeline</h4><ol class="events">${value.events.map(event=>`<li>${escapeHtml(displayValue(event))}</li>`).join('')}</ol>`);if(Array.isArray(value?.tool_sequence))blocks.push(`<h4>Server-qualified tool sequence</h4><ol class="events">${value.tool_sequence.map(item=>`<li>${escapeHtml(item.server_id||'')}/${escapeHtml(item.tool_name||'')}</li>`).join('')}</ol>`);record.innerHTML=blocks.join('');record.hidden=!blocks.length}
function renderTask(value){show('task-result',value);const task=value?.task||value;const summary=$('task-summary');const fields=[['id','Task ID'],['contextId','Context ID'],['status','Status']].filter(([key])=>Object.prototype.hasOwnProperty.call(task||{},key));summary.innerHTML=fields.map(([key,label])=>`<div class="result-field"><span>${label}</span><strong>${escapeHtml(displayValue(key==='status'?task[key]?.state:task[key]))}</strong></div>`).join('');summary.hidden=!fields.length}
function renderDeployment(value){show('deployment-result',value);const summary=$('deployment-summary');const fields=[['deployment_id','Deployment ID'],['status','Status'],['profile','Profile'],['namespace','Namespace'],['workload','Workload'],['service_account','Service account'],['readiness','Readiness'],['evidence','Evidence'],['events','Events'],['verification_result','Verification result']].filter(([key])=>Object.prototype.hasOwnProperty.call(value||{},key));summary.innerHTML=fields.map(([key,label])=>`<div class="result-field"><span>${label}</span><strong>${escapeHtml(displayValue(value[key]))}</strong></div>`).join('');summary.hidden=!fields.length}
function incidentBody(){return {incident_type:$('incident-type').value,severity:$('incident-severity').value,affected_service:$('affected-service').value,signals:Array.from(document.querySelectorAll('input[name="signal"]:checked')).map(input=>input.value)}}
async function refreshPackages(){const value=await call('/api/packages');renderPackages(value);return value}
async function refreshIntegrations(){const value=await call('/api/integrations');const items=Array.isArray(value?.integrations)?value.integrations:[];show('overview-integration-count',`${items.length} registered`);show('overview-integrations',value);return value}
function integrationPath(suffix=''){return '/api/integrations/'+encode($('integration-id').value)+suffix}
async function sendA2A(){const r=await fetch('/message:send',{method:'POST',headers:{'A2A-Version':'1.0','content-type':'application/a2a+json'},body:$('a2a-request').value});const text=await r.text();let value;try{value=JSON.parse(text)}catch{value=text}if(!r.ok){show('task-result',value);throw value}if(value.task?.id)$('task-id').value=value.task.id;renderTask(value);return value}
async function readTask(){const r=await fetch('/tasks/'+encode($('task-id').value),{headers:{'A2A-Version':'1.0'}});const value=await r.json();if(!r.ok){show('a2a-result',value);throw value}renderTask(value);return value}
function selectView(view){document.querySelectorAll('.view').forEach(section=>section.hidden=section.id!==`view-${view}`);document.querySelectorAll('.nav button').forEach(button=>{const selected=button.dataset.view===view;button.classList.toggle('active',selected);button.setAttribute('aria-current',selected?'page':'false')})}
document.querySelectorAll('.nav button').forEach(button=>button.onclick=()=>selectView(button.dataset.view));
$('overview-refresh').onclick=()=>run(refreshIntegrations,'overview-integrations').catch(()=>{});
$('refresh-packages').onclick=()=>run(refreshPackages,'package-table').catch(()=>{});
$('register').onclick=()=>run(async()=>{const value=await call('/api/integrations',packageBody());if(value.integration_id)$('integration-id').value=value.integration_id;show('integration-detail',value);await refreshIntegrations();return value},'integration-detail').catch(()=>{});
$('load-integration').onclick=()=>run(async()=>{const value=await call(integrationPath());show('integration-detail',value);return value},'integration-detail').catch(()=>{});
$('approve').onclick=()=>run(async()=>{const value=await call(integrationPath('/approve'),{method:'POST'});show('integration-detail',value);return value},'integration-detail').catch(()=>{});
$('catalog').onclick=()=>run(()=>call(integrationPath('/tools')).then(value=>{show('catalog-result',value);return value}),'catalog-result').catch(()=>{});
$('deliveries').onclick=()=>run(()=>call(integrationPath('/deliveries')).then(value=>{show('delivery-result',value);return value}),'delivery-result').catch(()=>{});
$('update-summary').onclick=()=>run(()=>call(integrationPath('/runtime-metadata'),{...json('PATCH'),body:JSON.stringify({service_summary:$('service-summary').value})}).then(value=>{show('integration-detail',value);return value}),'integration-detail').catch(()=>{});
$('submit-incident').onclick=()=>run(async()=>{const value=await call('/api/incidents/'+encode($('incident-integration-id').value),{...json(),body:JSON.stringify(incidentBody())});$('incident-id').value=value.incident_id||'';renderIncident(value);return value},'incident-result').catch(()=>{});
$('read-incident').onclick=()=>run(()=>call('/api/incidents/'+encode($('incident-id').value)).then(value=>{renderIncident(value);return value}),'incident-result').catch(()=>{});
$('agent-card').onclick=()=>run(()=>call('/.well-known/agent-card.json').then(value=>{show('agent-card-result',value);return value}),'agent-card-result').catch(()=>{});
$('send-a2a').onclick=()=>run(sendA2A,'task-result').catch(()=>{});
$('read-task').onclick=()=>run(readTask,'task-result').catch(()=>{});
$('deploy').onclick=()=>run(async()=>{const value=await call('/api/deployments',approvalBody());if(value.deployment_id)$('deployment-id').value=value.deployment_id;renderDeployment(value);return value},'deployment-result').catch(()=>{});
$('read-deployment').onclick=()=>run(()=>call('/api/deployments/'+encode($('deployment-id').value)).then(value=>{renderDeployment(value);return value}),'deployment-result').catch(()=>{});
$('delete-deployment').onclick=()=>run(()=>call('/api/deployments/'+encode($('deployment-id').value),{method:'DELETE'}).then(value=>{renderDeployment(value);return value}),'deployment-result').catch(()=>{});
refreshIntegrations().catch(()=>{});
</script></body></html>"""


def create_app(
    settings: Settings,
    *,
    registry_client: PortalRegistryClient | None = None,
    agents_client: PortalAgentsClient | None = None,
    deployment_client: PortalDeploymentClient | None = None,
) -> FastAPI:
    registry = registry_client or PortalRegistryClient(
        settings.registry_base_url, settings.credential("portal_registry")
    )
    agents = agents_client or PortalAgentsClient(
        settings.agents_base_url, settings.credential("portal_agents")
    )
    deployment = deployment_client or PortalDeploymentClient(
        settings.deployment_base_url,
        settings.credential("portal_deployment"),
        timeout=_deployment_upstream_timeout(),
    )
    owned = (registry_client is None, agents_client is None, deployment_client is None)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            if owned[0]:
                await registry.close()
            if owned[1]:
                await agents.close()
            if owned[2]:
                await deployment.close()

    app = FastAPI(title="ARGUS Operations Portal", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.portal_clients = (registry, agents, deployment)

    async def standard(call: Any) -> Response:
        try:
            return _read_response(await call)
        except PortalUpstreamError:
            return JSONResponse({"error": "upstream unavailable"}, status_code=502)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"role": "portal", "status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _PORTAL_HTML

    @app.get("/api/packages")
    async def packages() -> dict[str, Any]:
        return {"packages": [{"package_id": KNOWN_PACKAGE_ID, "publisher_class": "community", "runtime": "mcp"}]}

    @app.post("/api/integrations")
    async def register(request: Request) -> Response:
        body, error = await _read_object(request)
        if error is not None:
            return error
        if set(body or {}) != {"package_id"} or not isinstance(body["package_id"], str):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await standard(registry.register(body))

    @app.get("/api/integrations")
    async def integrations() -> Response:
        return await standard(registry.list_integrations())

    @app.get("/api/catalog")
    async def catalog() -> Response:
        return await standard(registry.catalog())

    @app.get("/api/integrations/{integration_id}")
    async def integration(integration_id: str) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(registry.integration(integration_id))

    @app.post("/api/integrations/{integration_id}/approve")
    async def approve(integration_id: str) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(registry.approve(integration_id))

    @app.patch("/api/integrations/{integration_id}/runtime-metadata")
    async def runtime_metadata(integration_id: str, request: Request) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        body, error = await _read_object(request)
        if error is not None:
            return error
        if set(body or {}) != {"service_summary"} or not isinstance(body["service_summary"], str):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await standard(registry.runtime_metadata(integration_id, body))

    @app.get("/api/integrations/{integration_id}/tools")
    async def tools(integration_id: str) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(registry.tools(integration_id))

    @app.get("/api/integrations/{integration_id}/deliveries")
    async def deliveries(integration_id: str) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(registry.deliveries(integration_id))

    @app.post("/api/incidents")
    async def incident(request: Request) -> Response:
        body, error = await _read_object(request)
        if error is not None:
            return error
        if "integration_id" not in (body or {}):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await standard(agents.incident(body))

    @app.post("/api/incidents/{integration_id}")
    async def incident_for_integration(integration_id: str, request: Request) -> Response:
        if not _safe_id(integration_id):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        body, error = await _read_object(request)
        if error is not None:
            return error
        if "integration_id" in (body or {}):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await standard(agents.incident(body or {}, integration_id))

    @app.get("/api/incidents/{incident_id}")
    async def read_incident(incident_id: str) -> Response:
        if not _safe_id(incident_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(agents.read_incident(incident_id))

    @app.get("/internal/incident-selection/{incident_id}")
    async def selection_diagnostics(incident_id: str, request: Request) -> Response:
        if settings.environment == "competition" or request.headers.get("X-Argus-Diagnostics") != "1":
            return JSONResponse({"error": "not found"}, status_code=404)
        if not _safe_id(incident_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(agents.selection_diagnostics(incident_id))

    @app.get("/.well-known/agent-card.json")
    async def agent_card(request: Request) -> Response:
        try:
            response = await agents.agent_card()
            if response.status_code >= 400 or response.status_code in {401, 403}:
                raise PortalUpstreamError("agent card unavailable")
            card = response.json()
            interfaces = card.get("supportedInterfaces") if isinstance(card, dict) else None
            if not isinstance(interfaces, list) or len(interfaces) != 1 or not isinstance(interfaces[0], dict):
                raise PortalUpstreamError("agent card unavailable")
            card = dict(card)
            card.pop("securitySchemes", None)
            card.pop("securityRequirements", None)
            card["supportedInterfaces"] = [dict(interfaces[0])]
            interface_url = (
                str(request.url_for("send_message"))
                if settings.environment == "h7"
                else f"{settings.public_base_url}/message:send"
            )
            card["supportedInterfaces"][0]["url"] = interface_url
            return JSONResponse(card)
        except (PortalUpstreamError, ValueError, TypeError, json.JSONDecodeError):
            return JSONResponse({"error": "agent card unavailable"}, status_code=502)

    async def a2a_proxy(request: Request, path: str, method: str) -> Response:
        query = _a2a_query(request)
        if query is None:
            return _a2a_error("INVALID_ARGUMENT")
        raw = await request.body()
        if len(raw) > MAX_REQUEST_BODY_BYTES:
            return _a2a_error("INVALID_ARGUMENT")
        headers = {}
        if "A2A-Version" in request.headers:
            headers["A2A-Version"] = request.headers["A2A-Version"]
        if "content-type" in request.headers:
            headers["Content-Type"] = request.headers["content-type"]
        try:
            return _a2a_response(await agents.a2a(method, path, body=raw, headers=headers, params=query))
        except PortalUpstreamError:
            return JSONResponse({"error": "upstream unavailable"}, status_code=502)

    @app.post("/message:send")
    async def send_message(request: Request) -> Response:
        return await a2a_proxy(request, "/message:send", "POST")

    @app.get("/tasks/{task_id}")
    async def get_task(task_id: str, request: Request) -> Response:
        if not _safe_id(task_id):
            return _a2a_error("TASK_NOT_FOUND", "Task not found", 404)
        return await a2a_proxy(request, f"/tasks/{task_id}", "GET")

    @app.post("/api/deployments")
    async def create_deployment(request: Request) -> Response:
        body, error = await _read_object(request)
        if error is not None:
            return error
        if set(body or {}) != _APPROVAL_FIELDS:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await standard(deployment.create(body))

    @app.get("/api/deployments/{deployment_id}")
    async def get_deployment(deployment_id: str) -> Response:
        if not _safe_id(deployment_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(deployment.get(deployment_id))

    @app.delete("/api/deployments/{deployment_id}")
    async def delete_deployment(deployment_id: str) -> Response:
        if not _safe_id(deployment_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return await standard(deployment.delete(deployment_id))

    return app
