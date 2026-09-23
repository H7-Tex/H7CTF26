import asyncio
import json
import re
from dataclasses import replace
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from argus.a2a import A2A_JSON_MEDIA_TYPE
from argus.config import Settings
from argus.portal import (
    PortalAgentsClient,
    PortalDeploymentClient,
    PortalRegistryClient,
    create_app,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        role="portal",
        instance_id="team-a",
        data_dir=tmp_path,
        database_path=tmp_path / "argus.sqlite3",
        ollama_url="",
        ollama_model="",
        ollama_digest="",
        model_seed=0,
        model_temperature=0.0,
        model_context_tokens=0,
        model_strict_json=False,
        environment="development",
        service_credentials={
            "portal_registry": "portal-registry",
            "portal_agents": "portal-agents",
            "portal_deployment": "portal-deployment",
        },
        registry_base_url="http://registry",
        agents_base_url="http://agents",
        deployment_base_url="http://deployment",
        public_base_url="https://portal.example",
    )


def _upstream_apps():
    registry = FastAPI()
    agents = FastAPI()
    deployment = FastAPI()
    calls: list[tuple[str, str, str]] = []

    @registry.api_route("/{path:path}", methods=["GET", "POST", "PATCH"])
    async def registry_route(path: str, request: Request):
        calls.append(("registry", request.method, request.headers.get("authorization", "")))
        if path == "api/integrations" and request.method == "POST":
            return JSONResponse({"integration_id": "integration-1", "status": "pending"}, status_code=201)
        if path == "api/integrations" and request.method == "GET":
            return JSONResponse({"integrations": []})
        if path == "api/catalog":
            return JSONResponse({"integrations": []})
        return JSONResponse({"ok": True})

    @agents.get("/.well-known/agent-card.json")
    async def card(request: Request):
        calls.append(("agents", request.method, request.headers.get("authorization", "")))
        return JSONResponse({
            "name": "ARGUS Deployment Review Agent",
            "supportedInterfaces": [{"url": "http://agents:8082/message:send", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
            "securitySchemes": {"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
            "securityRequirements": [{"schemes": {"bearerAuth": {"list": []}}}],
        })

    @agents.post("/message:send")
    async def send(request: Request):
        calls.append(("agents", request.method, request.headers.get("authorization", "")))
        assert request.headers["a2a-version"] == "1.0"
        assert request.headers["content-type"] == A2A_JSON_MEDIA_TYPE
        return Response(
            b'{"task":{"id":"task-1"}}',
            media_type=A2A_JSON_MEDIA_TYPE,
        )

    @agents.post("/api/incidents/{integration_id}")
    async def incident(integration_id: str, request: Request):
        body = await request.json()
        return JSONResponse(
            {
                "incident_id": "incident-1",
                "integration_id": integration_id,
                "status": "completed",
                "events": ["Incident accepted", "Analysis complete"],
                "tool_sequence": [{"server_id": "internal-git", "tool_name": "get_incident_runbook"}],
                "incident": body,
            },
            status_code=201,
        )

    @agents.get("/api/incidents/{incident_id}")
    async def read_incident(incident_id: str):
        return JSONResponse(
            {
                "incident_id": incident_id,
                "integration_id": "integration-1",
                "status": "completed",
                "events": ["Incident accepted", "Analysis complete"],
                "tool_sequence": [{"server_id": "internal-git", "tool_name": "get_incident_runbook"}],
            }
        )

    @agents.get("/tasks/{task_id}")
    async def task(task_id: str, request: Request):
        calls.append(("agents", request.method, request.headers.get("authorization", "")))
        return Response(
            json.dumps({"id": task_id}).encode(),
            media_type=A2A_JSON_MEDIA_TYPE,
        )

    @deployment.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
    async def deployment_route(path: str, request: Request):
        calls.append(("deployment", request.method, request.headers.get("authorization", "")))
        if request.method == "POST":
            return JSONResponse({"deployment_id": "deployment-1", "status": "ready"}, status_code=201)
        return JSONResponse({"deployment_id": "deployment-1", "status": "ready"})

    return registry, agents, deployment, calls


class _SlowIncidentClient:
    def __init__(self):
        self.observed_timeout = None

    async def request(self, method: str, path: str, **kwargs):
        self.observed_timeout = kwargs.get("timeout")
        if method == "POST" and path == "/api/incidents/integration-1":
            if self.observed_timeout is None or self.observed_timeout <= 5.0:
                raise httpx.ReadTimeout("simulated five-second upstream timeout")
            await asyncio.sleep(5.1)
            return httpx.Response(
                201,
                json={
                    "incident_id": "incident-slow",
                    "integration_id": "integration-1",
                    "status": "completed",
                    "events": ["Incident accepted", "Analysis complete"],
                    "tool_sequence": [],
                },
                request=httpx.Request(method, "http://agents" + path),
            )
        return httpx.Response(
            404,
            json={"error": "not found"},
            request=httpx.Request(method, "http://agents" + path),
        )


def test_portal_allows_bounded_slow_incident_response(tmp_path):
    slow_client = _SlowIncidentClient()
    portal = create_app(
        _settings(tmp_path),
        agents_client=PortalAgentsClient("http://agents", "portal-agents", client=slow_client),
    )

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=portal), base_url="http://portal"
        ) as player:
            response = await player.post(
                "/api/incidents/integration-1",
                json={
                    "incident_type": "deployment-anomaly",
                    "severity": "high",
                    "affected_service": "runtime-controller",
                    "signals": ["policy-drift"],
                },
            )
        assert response.status_code == 201
        assert response.json()["incident_id"] == "incident-slow"
        assert slow_client.observed_timeout > 5.0

    asyncio.run(scenario())


def test_portal_allows_a_longer_development_deployment_upstream_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS", "180")
    portal = create_app(_settings(tmp_path))
    deployment = portal.state.portal_clients[2]

    try:
        assert deployment._client.timeout.read == 180.0
    finally:
        asyncio.run(deployment.close())


def test_portal_uses_fixed_edges_and_preserves_bounded_a2a(tmp_path):
    registry_app, agents_app, deployment_app, calls = _upstream_apps()

    async def scenario():
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=registry_app), base_url="http://registry") as registry_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=agents_app), base_url="http://agents") as agents_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=deployment_app), base_url="http://deployment") as deployment_http,
        ):
            portal = create_app(
                _settings(tmp_path),
                registry_client=PortalRegistryClient("http://registry", "portal-registry", client=registry_http),
                agents_client=PortalAgentsClient("http://agents", "portal-agents", client=agents_http),
                deployment_client=PortalDeploymentClient("http://deployment", "portal-deployment", client=deployment_http),
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portal), base_url="http://portal") as player:
                assert (await player.get("/healthz")).json()["role"] == "portal"
                card = await player.get("/.well-known/agent-card.json")
                assert card.status_code == 200
                assert card.json()["supportedInterfaces"][0]["url"] == "https://portal.example/message:send"
                assert "securitySchemes" not in card.json()
                assert "securityRequirements" not in card.json()
                registered = await player.post("/api/integrations", json={"package_id": "vendor-incident-review"})
                assert registered.status_code == 201
                assert (await player.get("/api/catalog")).status_code == 200
                rejected = await player.post(
                    "/api/integrations",
                    json={"package_id": "vendor-incident-review", "url": "http://attacker"},
                )
                assert rejected.status_code == 400
                a2a = await player.post(
                    "/message:send?A2A-Version=1.0",
                    headers={"A2A-Version": "1.0", "Content-Type": A2A_JSON_MEDIA_TYPE},
                    content=b'{"message":{}}',
                )
                assert a2a.status_code == 200
                assert a2a.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                task = await player.get("/tasks/task-1", headers={"A2A-Version": "1.0"})
                assert task.status_code == 200
                deployment = await player.post(
                    "/api/deployments",
                    json={
                        "approval_id": "a", "task_id": "t", "control_id": "c", "target": "x",
                        "granted_capability": "protected-runtime", "expires_at": "x",
                        "key_id": "k", "signature": "s",
                    },
                )
                assert deployment.status_code == 201
                assert (await player.post("/api/deployments", json={"profile": "elevated"})).status_code == 400
            assert all(secret in {"Bearer portal-registry", "Bearer portal-agents", "Bearer portal-deployment"} for _, _, secret in calls)
            assert ("agents", "GET", "Bearer portal-agents") in calls
            assert all("secret" not in item[2] for item in calls)

    asyncio.run(scenario())


def test_h7_agent_card_uses_host_and_only_trusted_forwarding_headers(tmp_path):
    registry_app, agents_app, deployment_app, _ = _upstream_apps()
    settings = replace(_settings(tmp_path), environment="h7", public_base_url="")

    async def scenario():
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=registry_app), base_url="http://registry") as registry_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=agents_app), base_url="http://agents") as agents_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=deployment_app), base_url="http://deployment") as deployment_http,
        ):
            portal = create_app(
                settings,
                registry_client=PortalRegistryClient("http://registry", "portal-registry", client=registry_http),
                agents_client=PortalAgentsClient("http://agents", "portal-agents", client=agents_http),
                deployment_client=PortalDeploymentClient("http://deployment", "portal-deployment", client=deployment_http),
            )
            trusted = ProxyHeadersMiddleware(portal, trusted_hosts="10.0.0.0/8")
            headers = {"host": "portal.h7.invalid", "x-forwarded-host": "attacker.invalid", "x-forwarded-proto": "https"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=trusted, client=("203.0.113.10", 5000)),
                base_url="http://portal.h7.invalid",
            ) as direct:
                response = await direct.get("/.well-known/agent-card.json", headers=headers)
                assert response.json()["supportedInterfaces"][0]["url"] == "http://portal.h7.invalid/message:send"
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=trusted, client=("10.1.2.3", 5000)),
                base_url="http://internal.invalid",
            ) as ingress:
                response = await ingress.get("/.well-known/agent-card.json", headers=headers)
                assert response.json()["supportedInterfaces"][0]["url"] == "https://portal.h7.invalid/message:send"

    asyncio.run(scenario())


def test_portal_register_button_posts_a_package_object(tmp_path):
    registry_app, agents_app, deployment_app, _calls = _upstream_apps()

    async def scenario():
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=registry_app), base_url="http://registry") as registry_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=agents_app), base_url="http://agents") as agents_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=deployment_app), base_url="http://deployment") as deployment_http,
        ):
            portal = create_app(
                _settings(tmp_path),
                registry_client=PortalRegistryClient("http://registry", "portal-registry", client=registry_http),
                agents_client=PortalAgentsClient("http://agents", "portal-agents", client=agents_http),
                deployment_client=PortalDeploymentClient("http://deployment", "portal-deployment", client=deployment_http),
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portal), base_url="http://portal") as player:
                html = (await player.get("/")).text
                assert "function packageBody()" in html
                assert "package_id:$('package-id').value.trim()" in html
                assert "<code>vendor-incident-review</code>" in html
                assert "body('package-id')" not in html

    asyncio.run(scenario())


def test_portal_initial_page_is_not_a_prepared_exploit_wizard(tmp_path):
    registry_app, agents_app, deployment_app, _calls = _upstream_apps()

    async def scenario():
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=registry_app), base_url="http://registry") as registry_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=agents_app), base_url="http://agents") as agents_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=deployment_app), base_url="http://deployment") as deployment_http,
        ):
            portal = create_app(
                _settings(tmp_path),
                registry_client=PortalRegistryClient("http://registry", "portal-registry", client=registry_http),
                agents_client=PortalAgentsClient("http://agents", "portal-agents", client=agents_http),
                deployment_client=PortalDeploymentClient("http://deployment", "portal-deployment", client=deployment_http),
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portal), base_url="http://portal") as player:
                html = (await player.get("/")).text
                compact = re.sub(r"\s+", "", html)
                assert all(label in html for label in ("Overview", "Integrations", "Incidents", "Agent Interop", "Runtime"))
                assert "Operations Overview" in html
                assert "View integrations, incident activity, agent connections, and deployment status." in html
                assert "Incident records" in html
                assert "Operational data is loaded on demand." not in html
                assert "Available Packages" in html
                assert "Registration is an explicit operation." not in html
                assert "View package details, approval status, and runtime information." in html
                assert "Create an incident and review the resulting case record." in html
                assert "The incident record includes the available activity and tool history." not in html
                assert "inspect the returned task" not in html
                assert "A2A request format" in html
                assert "Values are supplied by the integrating client." not in html
                assert "Protocol errors are returned unchanged" not in html
                assert "submit a signed deployment approval" in html
                assert "Deployment settings are determined from the approval." in html
                assert '<textarea id="a2a-request" class="code" spellcheck="false" placeholder="Paste or type a JSON SendMessage request"></textarea>' in html
                assert '<textarea id="approval" class="code" spellcheck="false" placeholder="Paste a signed deployment approval JSON object"></textarea>' in html
                initial_document = html.split("<script>", 1)[0]
                assert "external-partner" in initial_document
                assert "recommendation" in initial_document
                assert "approve" in initial_document
                assert "messageId" not in initial_document
                assert all(label not in initial_document for label in (
                    "Source Message / History", "Source Metadata", "Recommendation Data",
                    "Normalized Request", "Signed Approval Artifact", "Protected Objective",
                ))
                assert "Registry notes" not in initial_document
                assert "Package information, approval state, and runtime observations are intentionally shown as separate records." not in initial_document
                assert "HTTP+JSON / A2A 1.0" not in initial_document
                assert "No incident loaded." in initial_document
                assert "Method Not Allowed" not in initial_document
                assert "deployment-summary" in initial_document
                assert "<span>Profile</span>" not in initial_document
                assert "<span>Namespace</span>" not in initial_document
                assert "<span>Protected Objective</span>" not in initial_document
                assert "Deployment result" in initial_document
                header = html[html.index("<header>"):html.index("</header>")]
                assert "environment" not in header
                assert 'type="number"' not in header
                assert "<select" not in header
                assert '"type":"deployment-review"' not in compact
                assert '"recommendation":"approve"' not in compact
                assert '"control_id":""' not in compact
                assert '"target":"team-runtime"' not in compact
                assert '"sourceType":"external-partner"' not in compact
                assert "vendor-message-1" not in html
                assert all(label not in html.lower() for label in ("semantic downgrade", "authority laundering", "privilege escalation"))

                send_block = html.split("async function sendA2A(){", 1)[1].split("async function readTask", 1)[0]
                deploy_block = html.split("$('deploy').onclick=", 1)[1].split("$('read-deployment').onclick=", 1)[0]
                assert "/api/deployments" not in send_block
                assert "approval" not in send_block.lower()
                assert "delivery" not in send_block.lower()
                assert "/message:send" not in deploy_block
                assert "a2a" not in deploy_block.lower()
                assert "delivery" not in deploy_block.lower()
                assert "task" not in deploy_block.lower()
                assert "show('task-result',value)" in html
                assert "function renderDeployment(value)" in html

                assert "deployment-control-review" in html
                assert "ROLE_USER" in html
                assert "A2A-Version: 1.0" in html
                assert "application/a2a+json" in html
                assert all(field in html for field in ("sourceType", "type", "control_id", "target", "recommendation"))

    asyncio.run(scenario())


def test_portal_only_usability_path_keeps_actions_explicit(tmp_path):
    registry_app, agents_app, deployment_app, calls = _upstream_apps()

    async def scenario():
        async with (
            httpx.AsyncClient(transport=httpx.ASGITransport(app=registry_app), base_url="http://registry") as registry_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=agents_app), base_url="http://agents") as agents_http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=deployment_app), base_url="http://deployment") as deployment_http,
        ):
            portal = create_app(
                _settings(tmp_path),
                registry_client=PortalRegistryClient("http://registry", "portal-registry", client=registry_http),
                agents_client=PortalAgentsClient("http://agents", "portal-agents", client=agents_http),
                deployment_client=PortalDeploymentClient("http://deployment", "portal-deployment", client=deployment_http),
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portal), base_url="http://portal") as player:
                assert (await player.get("/api/packages")).json()["packages"][0]["package_id"] == "vendor-incident-review"
                registration = await player.post("/api/integrations", json={"package_id": "vendor-incident-review"})
                assert registration.status_code == 201
                integration_id = "integration-1"
                assert (await player.get(f"/api/integrations/{integration_id}")).status_code == 200
                assert (await player.get(f"/api/integrations/{integration_id}/tools")).status_code == 200
                incident = await player.post(
                    f"/api/incidents/{integration_id}",
                    json={
                        "incident_type": "deployment-anomaly",
                        "severity": "high",
                        "affected_service": "runtime-controller",
                        "signals": ["policy-drift"],
                    },
                )
                assert incident.status_code == 201
                assert incident.json()["tool_sequence"][0] == {
                    "server_id": "internal-git", "tool_name": "get_incident_runbook"
                }
                assert (await player.get(f"/api/integrations/{integration_id}/deliveries")).status_code == 200
                card = await player.get("/.well-known/agent-card.json")
                assert card.status_code == 200
                source = {
                    "message": {
                        "messageId": "vendor-message-test",
                        "role": "ROLE_USER",
                        "parts": [{
                            "data": {
                                "type": "deployment-review",
                                "control_id": "control-team-a",
                                "target": "team-runtime",
                                "recommendation": "approve",
                            },
                            "mediaType": "application/json",
                        }],
                        "metadata": {"sourceType": "external-partner"},
                    },
                    "configuration": {"acceptedOutputModes": ["application/json"]},
                }
                task = await player.post(
                    "/message:send",
                    headers={"A2A-Version": "1.0", "Content-Type": A2A_JSON_MEDIA_TYPE},
                    content=json.dumps(source).encode(),
                )
                assert task.status_code == 200
                assert (await player.get("/tasks/task-1", headers={"A2A-Version": "1.0"})).status_code == 200
                approval = {
                    "approval_id": "approval-1", "task_id": "task-1", "control_id": "control-team-a",
                    "target": "team-runtime", "granted_capability": "protected-runtime",
                    "expires_at": "2099-01-01T00:00:00Z", "key_id": "key-1", "signature": "signature-1",
                }
                deployment = await player.post("/api/deployments", json=approval)
                assert deployment.status_code == 201
                edges = [edge for edge, _, _ in calls]
                assert edges[-1] == "deployment"
                assert edges.count("registry") >= 3
                assert edges.count("agents") >= 2
                assert set(edges) <= {"registry", "agents", "deployment"}

    asyncio.run(scenario())
