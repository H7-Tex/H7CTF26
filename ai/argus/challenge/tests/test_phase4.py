import asyncio
import hashlib
import hmac
import json
from dataclasses import replace

import httpx
import pytest

from argus.a2a import A2AValidationError, A2A_JSON_MEDIA_TYPE, validate_send_message_request
from argus.agents import create_app as create_agents_app
from argus.agents import seed_control_material
from argus.config import MCP_PROTOCOL_VERSION, Settings
from argus.domain import GrantedCapability, canonical_approval_claims
from argus.mcp import create_app as create_mcp_app
from argus.mcp_client import HttpCoordinatorClient, HttpSecurityClient
from argus.mcp_protocol import SECURITY_TOOL_NAME
from argus.store import canonical_json, open_database


def _settings(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "mcp")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "phase4-signing-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_REGISTRY_MCP", "registry-mcp-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_COORDINATOR", "agents-coordinator-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_COORDINATOR_SECURITY", "coordinator-security-secret")
    mcp_settings = Settings.load()

    monkeypatch.delenv("ARGUS_CREDENTIAL_REGISTRY_MCP")
    monkeypatch.delenv("ARGUS_CREDENTIAL_COORDINATOR_SECURITY")
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry-secret")
    return Settings.load(), mcp_settings


def _send_message(control_id="control-team-a", target="team-runtime", configuration=None):
    request = {
        "message": {
            "messageId": "vendor-message-1",
            "role": "ROLE_USER",
            "parts": [{
                "data": {
                    "type": "deployment-review",
                    "control_id": control_id,
                    "target": target,
                    "recommendation": "approve",
                },
                "mediaType": "application/json",
            }],
            "metadata": {"sourceType": "external-partner"},
        },
    }
    if configuration is not None:
        request["configuration"] = configuration
    return request


def _a2a_headers(version="1.0", **extra):
    headers = {
        "Authorization": "Bearer portal-agents-secret",
        "Content-Type": A2A_JSON_MEDIA_TYPE,
        **extra,
    }
    if version is not None:
        headers["A2A-Version"] = version
    return headers


def _security_request(arguments, name=SECURITY_TOOL_NAME):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": name,
            "arguments": arguments,
        },
    }


class _RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, app):
        self._delegate = httpx.ASGITransport(app=app)
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return await self._delegate.handle_async_request(request)


def test_a2a_contract_rejects_pseudo_envelopes_and_privilege_fields():
    valid = _send_message()
    invalid_part = {**valid, "message": {**valid["message"], "parts": [{
        "kind": "data", "data": valid["message"]["parts"][0]["data"], "mediaType": "application/json"
    }]}}
    for invalid in (
        {**valid, "protocolVersion": "1.0"},
        {**valid, "agentCard": {}},
        {**valid, "taskId": "player-task"},
        invalid_part,
        {**valid, "message": {**valid["message"], "messageId": ""}},
        {**valid, "message": {**valid["message"], "role": "user"}},
        {**valid, "message": {**valid["message"], "parts": [{"url": "https://bad.example"}]}},
        {**valid, "granted_capability": "protected-runtime"},
    ):
        with pytest.raises(A2AValidationError):
            validate_send_message_request(invalid)


def test_a2a_contract_accepts_optional_bounded_configuration():
    assert validate_send_message_request(_send_message())["history_length"] is None
    assert validate_send_message_request(_send_message(configuration={"acceptedOutputModes": ["application/json"]}))
    assert validate_send_message_request(_send_message(configuration={"historyLength": 0}))["history_length"] == 0
    assert validate_send_message_request(_send_message(configuration={
        "acceptedOutputModes": ["text/plain", "application/json"], "historyLength": 0,
    }))["history_length"] == 0
    for configuration in (
        {"acceptedOutputModes": ["text/plain"]},
        {"historyLength": -1},
        {"historyLength": 33},
    ):
        with pytest.raises(A2AValidationError):
            validate_send_message_request(_send_message(configuration=configuration))
    for field in ("profile", "namespace", "service_account", "manifest"):
        invalid = _send_message()
        invalid["message"]["parts"][0]["data"][field] = "player-value"
        with pytest.raises(A2AValidationError):
            validate_send_message_request(invalid)


def test_phase4_a2a_v1_to_mcp_security_preserves_source_and_loses_provenance(
    clean_argus_env, monkeypatch
):
    agents_settings, mcp_settings = _settings(clean_argus_env, monkeypatch)
    seed_control_material(agents_settings, control_id="control-team-a", target="team-runtime")
    mcp_app = create_mcp_app(mcp_settings)

    async def scenario():
        recording = _RecordingTransport(mcp_app)
        async with httpx.AsyncClient(transport=recording, base_url="http://mcp") as mcp_http:
            mcp_app.state.mcp_service.security_client = HttpSecurityClient(
                "http://mcp", "coordinator-security-secret", client=mcp_http
            )
            agents_app = create_agents_app(
                agents_settings,
                coordinator_client=HttpCoordinatorClient(
                    "http://mcp", "agents-coordinator-secret", client=mcp_http
                ),
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=agents_app), base_url="http://agents"
            ) as agents_http:
                card = await agents_http.get("/.well-known/agent-card.json")
                assert card.status_code == 200
                assert card.headers["content-type"].startswith("application/json")
                assert card.json()["supportedInterfaces"][0]["protocolBinding"] == "HTTP+JSON"
                assert card.json()["supportedInterfaces"][0]["protocolVersion"] == "1.0"
                assert card.json()["securitySchemes"]["bearerAuth"]["httpAuthSecurityScheme"]["scheme"] == "Bearer"

                created = await agents_http.post(
                    "/message:send", headers=_a2a_headers(), content=canonical_json(_send_message())
                )
                assert created.status_code == 200
                assert created.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                task = created.json()["task"]
                assert task["id"] != "vendor-message-1"
                assert task["contextId"] != task["id"]
                assert task["status"]["state"] == "TASK_STATE_COMPLETED"
                source_message = task["history"][0]
                source_artifact = task["metadata"]["artifact"]
                assert source_message["metadata"]["sourceType"] == "external-partner"
                assert source_artifact["type"] == "deployment-review"
                security_arguments = task["metadata"]["normalization"]
                assert security_arguments == {
                    "task_id": task["id"], "control_id": "control-team-a",
                    "target": "team-runtime", "decision": "approve",
                }
                assert "sourceType" not in security_arguments
                assert "type" not in security_arguments

                approval = task["artifacts"][0]["parts"][0]["data"]
                assert approval["granted_capability"] == GrantedCapability.PROTECTED_RUNTIME.value
                assert approval["task_id"] == task["id"]
                claims = canonical_approval_claims(
                    instance_id=mcp_settings.instance_id, approval_id=approval["approval_id"],
                    task_id=approval["task_id"], control_id=approval["control_id"], target=approval["target"],
                    granted_capability=GrantedCapability.PROTECTED_RUNTIME,
                    expires_at=approval["expires_at"], key_id=approval["key_id"],
                )
                assert approval["signature"] == hmac.new(
                    b"phase4-signing-secret", claims.encode(), hashlib.sha256
                ).hexdigest()
                fetched = await agents_http.get(f"/tasks/{task['id']}", headers=_a2a_headers())
                assert fetched.status_code == 200
                assert fetched.json() == task
                historyless = await agents_http.get(
                    f"/tasks/{task['id']}?historyLength=0", headers=_a2a_headers()
                )
                assert historyless.status_code == 200
                assert "history" not in historyless.json()
                one_history = await agents_http.get(
                    f"/tasks/{task['id']}?historyLength=1", headers=_a2a_headers()
                )
                assert len(one_history.json()["history"]) <= 1
                assert (await agents_http.get(
                    f"/tasks/{task['id']}?historyLength=-1", headers=_a2a_headers()
                )).json()["error"]["details"][0]["reason"] == "INVALID_ARGUMENT"

                configured = await agents_http.post(
                    "/message:send", headers=_a2a_headers(), content=canonical_json(_send_message(configuration={
                        "acceptedOutputModes": ["text/plain", "application/json"], "historyLength": 0,
                    }))
                )
                assert configured.status_code == 200
                assert "history" not in configured.json()["task"]
                query_version = await agents_http.post(
                    "/message:send?A2A-Version=1.0", headers=_a2a_headers(version=None),
                    content=canonical_json(_send_message(configuration={"acceptedOutputModes": ["application/json"]})),
                )
                assert query_version.status_code == 200

                with open_database(mcp_settings.database_path, mcp_settings.instance_id) as connection:
                    approval_count = connection.execute("SELECT COUNT(*) FROM security_approvals").fetchone()[0]
                bad_coordinator_app = create_agents_app(
                    agents_settings,
                    coordinator_client=HttpCoordinatorClient("http://mcp", "wrong-coordinator-secret", client=mcp_http),
                )
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=bad_coordinator_app), base_url="http://agents") as bad_coordinator:
                    rejected = await bad_coordinator.post(
                        "/message:send", headers=_a2a_headers(), content=canonical_json(_send_message())
                    )
                assert rejected.status_code == 200
                assert rejected.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"
                with open_database(mcp_settings.database_path, mcp_settings.instance_id) as connection:
                    assert connection.execute("SELECT COUNT(*) FROM security_approvals").fetchone()[0] == approval_count

                for headers in (
                    {"Authorization": "Bearer portal-agents-secret"},
                    _a2a_headers(version="0.9"),
                ):
                    rejected = await agents_http.post(
                        "/message:send", headers=headers, content=canonical_json(_send_message())
                    )
                    assert rejected.status_code == 400
                    assert rejected.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                    assert rejected.json()["error"]["details"][0]["reason"] == "VERSION_NOT_SUPPORTED"
                conflict = await agents_http.post(
                    "/message:send?A2A-Version=0.9", headers=_a2a_headers(), content=canonical_json(_send_message())
                )
                assert conflict.status_code == 400
                assert conflict.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                assert conflict.json()["error"]["details"][0]["reason"] == "VERSION_NOT_SUPPORTED"
                wrong_content_type = await agents_http.post(
                    "/message:send", headers=_a2a_headers(**{"Content-Type": "application/json"}),
                    content=canonical_json(_send_message()),
                )
                assert wrong_content_type.status_code == 400
                assert wrong_content_type.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                assert wrong_content_type.json()["error"]["details"][0]["reason"] == "CONTENT_TYPE_NOT_SUPPORTED"
                for invalid in (
                    {**_send_message(), "protocolVersion": "1.0"},
                    {**_send_message(), "agentCard": {}},
                    {**_send_message(), "taskId": "player-task"},
                    {**_send_message(), "message": {**_send_message()["message"], "role": "user"}},
                    {**_send_message(), "message": {**_send_message()["message"], "parts": [{"data": {}, "kind": "data", "mediaType": "application/json"}]}},
                    {**_send_message(), "message": {**_send_message()["message"], "messageId": ""}},
                    _send_message("control-team-b"),
                    _send_message("control-team-a", "other-runtime"),
                ):
                    rejected = await agents_http.post(
                        "/message:send", headers=_a2a_headers(), content=canonical_json(invalid)
                    )
                    assert rejected.status_code in {200, 400}
                    if rejected.status_code == 200:
                        assert rejected.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"
                oversized = _send_message("x" * 65)
                rejected = await agents_http.post(
                    "/message:send", headers=_a2a_headers(), content=canonical_json(oversized)
                )
                assert rejected.status_code == 400

                other_app = create_agents_app(
                    replace(agents_settings, instance_id="team-b"), coordinator_client=HttpCoordinatorClient(
                        "http://mcp", "agents-coordinator-secret", client=mcp_http
                    )
                )
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=other_app), base_url="http://agents") as other_http:
                    cross_instance = await other_http.get(f"/tasks/{task['id']}", headers=_a2a_headers())
                assert cross_instance.status_code == 404
                assert cross_instance.headers["content-type"].startswith(A2A_JSON_MEDIA_TYPE)
                assert cross_instance.json()["error"]["details"][0]["reason"] == "TASK_NOT_FOUND"

            security_request = next(request for request in recording.requests if request.url.path == "/mcp/security")
            security_wire = json.loads(security_request.content)
            assert security_request.headers["authorization"] == "Bearer coordinator-security-secret"
            assert security_wire["params"]["name"] == SECURITY_TOOL_NAME
            assert set(security_wire["params"]["arguments"]) == {
                "task_id", "control_id", "target", "decision"
            }
            assert "sourceType" not in security_wire["params"]["arguments"]
            assert "type" not in security_wire["params"]["arguments"]

            coordinator_headers = {
                "Authorization": "Bearer agents-coordinator-secret", "X-Argus-Instance": mcp_settings.instance_id,
            }
            normalized = task["metadata"]["normalization"]
            wrong_coordinator = await mcp_http.post(
                f"/internal/coordinator/tasks/{task['id']}",
                headers={**coordinator_headers, "Authorization": "Bearer wrong-coordinator-secret"}, json={},
            )
            assert wrong_coordinator.status_code == 401
            agents_to_security = await mcp_http.post(
                "/mcp/security", headers=coordinator_headers, json=_security_request(normalized)
            )
            assert agents_to_security.status_code == 401
            security_headers = {
                "Authorization": "Bearer coordinator-security-secret", "X-Argus-Instance": mcp_settings.instance_id,
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, "Mcp-Method": "tools/call", "Mcp-Name": SECURITY_TOOL_NAME,
            }
            assert (await mcp_http.post(
                "/mcp/security", headers=security_headers, json=_security_request(normalized, name="arbitrary")
            )).status_code == 400
            assert (await mcp_http.post(
                "/mcp/security", headers=security_headers,
                json=_security_request({**normalized, "granted_capability": "protected-runtime"})
            )).status_code == 400
            assert (await mcp_http.post(
                "/mcp/security", headers={**security_headers, "Authorization": "Bearer wrong-security-secret"},
                json=_security_request(normalized)
            )).status_code == 401

            with open_database(mcp_settings.database_path, mcp_settings.instance_id) as connection:
                stored = connection.execute(
                    "SELECT artifact_json, normalized_tool FROM a2a_tasks WHERE id = ?", (task["id"],)
                ).fetchone()
                persisted = json.loads(stored[0])
                assert persisted["message"]["metadata"]["sourceType"] == "external-partner"
                assert persisted["message"]["parts"][0]["data"]["type"] == "deployment-review"
                assert "type" not in json.loads(stored[1])["request"]

    asyncio.run(scenario())
