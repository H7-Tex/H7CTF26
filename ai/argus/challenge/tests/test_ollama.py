import asyncio
import json

import httpx
import pytest

from argus.agents import create_app
from argus.config import Settings
from argus.ollama_client import OllamaPlanner, PlannerError


_DIGEST = "a" * 64


def _settings(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_COORDINATOR", "agents-coordinator-secret")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", _DIGEST)
    monkeypatch.setenv("OLLAMA_SEED", "7")
    monkeypatch.setenv("OLLAMA_TEMPERATURE", "0")
    monkeypatch.setenv("ARGUS_MODEL_STRICT_JSON", "true")
    monkeypatch.setenv("ARGUS_A2A_INTERFACE_URL", "https://agents.example")
    return Settings.load()


def _planner(settings, response):
    async def handler(_request):
        return response

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://ollama",
    )
    return OllamaPlanner(settings, client=client)


def test_ollama_model_attestation_accepts_expected_model_and_digest(clean_argus_env, monkeypatch):
    settings = _settings(clean_argus_env, monkeypatch)
    planner = _planner(
        settings,
        httpx.Response(200, json={"models": [{"name": settings.ollama_model, "digest": _DIGEST}]}),
    )
    assert asyncio.run(planner.verify_model()) == _DIGEST


@pytest.mark.parametrize(
    "model_entry",
    [
        {"name": "qwen2.5-coder:7b", "digest": "b" * 64},
        {"name": "llama3:8b", "digest": _DIGEST},
    ],
)
def test_ollama_model_attestation_rejects_wrong_digest_or_model(
    clean_argus_env, monkeypatch, model_entry
):
    settings = _settings(clean_argus_env, monkeypatch)
    planner = _planner(settings, httpx.Response(200, json={"models": [model_entry]}))
    with pytest.raises(PlannerError):
        asyncio.run(planner.verify_model())


def test_ollama_model_attestation_rejects_unavailable_server(clean_argus_env, monkeypatch):
    settings = _settings(clean_argus_env, monkeypatch)

    async def handler(_request):
        raise httpx.ConnectError("offline")

    planner = OllamaPlanner(
        settings,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="http://ollama",
        ),
    )
    with pytest.raises(PlannerError):
        asyncio.run(planner.verify_model())


def test_ollama_selector_sends_capabilities_without_history_or_arguments(clean_argus_env, monkeypatch):
    settings = _settings(clean_argus_env, monkeypatch)
    captured = {}

    async def handler(request):
        captured["request"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "action": "select",
                            "server_id": "internal-git",
                            "tool_name": "get_incident_runbook",
                        }
                    )
                }
            },
        )

    planner = OllamaPlanner(
        settings,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="http://ollama",
        ),
    )
    result = asyncio.run(
        planner.select(
            incident={
                "incident_type": "deployment-anomaly",
                "affected_service": "runtime-controller",
                "signals": ["vendor-review-required"],
            },
            requested_outcome={
                "incident_domain": "deployment-anomaly",
                "evidence_domains": ["service_ownership"],
                "operational_recommendation": None,
            },
            tools=[
                {
                    "server_id": "internal-git",
                    "tool_name": "get_incident_runbook",
                    "description": "Retrieve incident runbook references.",
                    "inputSchema": {"type": "object"},
                }
            ],
        )
    )

    assert result == {
        "action": "select",
        "server_id": "internal-git",
        "tool_name": "get_incident_runbook",
    }
    user_payload = json.loads(captured["request"]["messages"][1]["content"])
    assert set(user_payload) == {"incident", "requested_outcome", "available_tools"}
    assert user_payload["requested_outcome"] == {
        "incident_domain": "deployment-anomaly",
        "evidence_domains": ["service_ownership"],
        "operational_recommendation": None,
    }
    assert "analysis_request" not in user_payload["incident"]
    assert "signals" not in user_payload["incident"]
    assert user_payload["available_tools"] == {
        "live_catalog": [],
        "internal_context": [
            {
                "description": "Retrieve incident runbook references.",
                "identity": {
                    "server_id": "internal-git",
                    "tool_name": "get_incident_runbook",
                },
            },
        ],
    }
    assert "arguments" not in captured["request"]["messages"][1]["content"]
    assert "inputSchema" not in captured["request"]["messages"][1]["content"]


def test_competition_agents_fail_startup_when_model_cannot_be_verified(clean_argus_env, monkeypatch):
    settings = _settings(clean_argus_env, monkeypatch)
    planner = _planner(settings, httpx.Response(200, json={"models": []}))
    app = create_app(settings, planner=planner)

    async def scenario():
        with pytest.raises(PlannerError):
            async with app.router.lifespan_context(app):
                pass

    asyncio.run(scenario())
