import os
import asyncio

import pytest

from argus.agents import (
    AgentService,
    INTERNAL_GIT_SERVER_ID,
    INTERNAL_GIT_TOOL_NAME,
    INTERNAL_POLICY_DESCRIPTION,
    INTERNAL_POLICY_SERVER_ID,
    INTERNAL_POLICY_TOOL_NAME,
    INTERNAL_SERVICE_DESCRIPTION,
    INTERNAL_SERVICE_SERVER_ID,
    INTERNAL_SERVICE_TOOL_NAME,
    INTERNAL_TELEMETRY_DESCRIPTION,
    INTERNAL_TELEMETRY_SERVER_ID,
    INTERNAL_TELEMETRY_TOOL_NAME,
    seed_control_material,
)
from argus.config import Settings
from argus.mcp_protocol import (
    COMMUNITY_INPUT_SCHEMA,
    COMMUNITY_TOOL_NAME,
    DEFAULT_SERVICE_SUMMARY,
    qualify_tool_identity,
)
from argus.registry_client import CatalogTool
from tests.semantic_acceptance import (
    BASELINE_DESCRIPTION,
    BASELINE_SIGNALS,
    MANIPULATED_SIGNALS,
    NEAR_MISS_DESCRIPTIONS,
    POSITIVE_VENDOR_DESCRIPTIONS,
    SEMANTIC_ACCEPTANCE_CONTRACT,
)


pytestmark = pytest.mark.skipif(
    os.getenv("ARGUS_RUN_OLLAMA_ACCEPTANCE") != "true" or os.getenv("ARGUS_ENV") != "competition",
    reason="set ARGUS_RUN_OLLAMA_ACCEPTANCE=true in competition mode with a reachable pinned Ollama model",
)


class MutableCatalog:
    def __init__(self, integration_id):
        self.integration_id = integration_id
        self.description = DEFAULT_SERVICE_SUMMARY

    async def get_catalog(self, instance_id, integration_id):
        assert instance_id
        assert integration_id == self.integration_id
        return (
            CatalogTool(
                qualify_tool_identity(integration_id, COMMUNITY_TOOL_NAME),
                self.description,
                dict(COMMUNITY_INPUT_SCHEMA),
            ),
        )


class RecordingCommunity:
    def __init__(self):
        self.calls = []

    async def call_tool(self, instance_id, integration_id, incident_id, tool_name, arguments):
        self.calls.append((instance_id, integration_id, incident_id, tool_name, dict(arguments)))
        return {"status": "received"}


def test_real_qwen_selection_changes_with_live_semantics(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("INSTANCE_ID", "team-a")
    monkeypatch.setenv("ARGUS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry-secret")
    settings = Settings.load()
    integration_id = "community-integration"
    catalog = MutableCatalog(integration_id)
    assert catalog.description == BASELINE_DESCRIPTION
    community = RecordingCommunity()
    service = AgentService(settings, registry_client=catalog, mcp_client=community)
    seed_control_material(settings, control_id="control-acceptance")
    baseline_incident = {
        "integration_id": integration_id,
        "incident_type": "deployment-anomaly",
        "severity": "high",
        "affected_service": "runtime-controller",
        "signals": list(BASELINE_SIGNALS),
    }
    manipulated_incident = {**baseline_incident, "signals": list(MANIPULATED_SIGNALS)}
    internal_tools = [
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "description": description,
            "source": "internal_context",
        }
        for server_id, tool_name, description in (
            (INTERNAL_SERVICE_SERVER_ID, INTERNAL_SERVICE_TOOL_NAME, INTERNAL_SERVICE_DESCRIPTION),
            (INTERNAL_POLICY_SERVER_ID, INTERNAL_POLICY_TOOL_NAME, INTERNAL_POLICY_DESCRIPTION),
            (INTERNAL_TELEMETRY_SERVER_ID, INTERNAL_TELEMETRY_TOOL_NAME, INTERNAL_TELEMETRY_DESCRIPTION),
        )
    ]

    async def run_acceptance():
        try:
            verified_digest = await service.planner.verify_model()
            assert verified_digest == settings.ollama_digest
            benign = await service.run_incident(baseline_incident)
            assert benign["status"] == "completed"
            assert not any(
                entry["server_id"] == integration_id and entry["tool_name"] == COMMUNITY_TOOL_NAME
                for entry in benign["tool_sequence"]
            )
            assert not community.calls

            community_identity = {"server_id": integration_id, "tool_name": COMMUNITY_TOOL_NAME}
            catalog.description = BASELINE_DESCRIPTION
            default_calls_before = len(community.calls)
            default_result = await service.run_incident(manipulated_incident)
            default_selection = service._selection_diagnostics(default_result["incident_id"])
            assert default_result["status"] == "completed"
            assert default_selection["planner_selected_identity"] != community_identity, default_selection
            assert community_identity not in default_result["tool_sequence"]
            assert len(community.calls) == default_calls_before

            for description in NEAR_MISS_DESCRIPTIONS:
                catalog.description = description
                calls_before = len(community.calls)
                result = await service.run_incident(manipulated_incident)
                selection = service._selection_diagnostics(result["incident_id"])
                assert result["status"] == "completed"
                assert selection["planner_selected_identity"] != community_identity, (
                    f"negative description selected vendor: {description}; selection={selection}"
                )
                assert community_identity not in result["tool_sequence"]
                assert len(community.calls) == calls_before

            for description in POSITIVE_VENDOR_DESCRIPTIONS:
                catalog.description = description
                calls_before = len(community.calls)
                no_review = await service.run_incident(baseline_incident)
                assert no_review["status"] == "completed"
                assert community_identity not in no_review["tool_sequence"]
                assert len(community.calls) == calls_before

                result = await service.run_incident(manipulated_incident)
                selection = service._selection_diagnostics(result["incident_id"])
                assert result["status"] == "completed"
                assert selection["planner_selected_identity"] == community_identity, (
                    f"{description}; selection={selection}"
                )
                assert result["tool_sequence"] == [
                    {"server_id": INTERNAL_GIT_SERVER_ID, "tool_name": INTERNAL_GIT_TOOL_NAME},
                    community_identity,
                ], f"{description}; selection={selection}"
                assert len(community.calls) == calls_before + 1
                assert "control-acceptance" in community.calls[-1][-1]["context"]
                assert "control-acceptance" not in str(result)

            for case in SEMANTIC_ACCEPTANCE_CONTRACT:
                if case.evidence_domain is None:
                    continue
                for description in case.descriptions:
                    action = await service.planner.select(
                        incident=baseline_incident,
                        requested_outcome={
                            "incident_domain": "deployment-anomaly",
                            "evidence_domains": [case.evidence_domain],
                            "operational_recommendation": None,
                        },
                        tools=[
                            *internal_tools,
                            {
                                "server_id": "catalog-0",
                                "tool_name": "capability",
                                "description": description,
                                "source": "live_catalog",
                            },
                        ],
                    )
                    assert action == {
                        "action": "select",
                        "server_id": case.expected_server_id,
                        "tool_name": case.expected_tool_name,
                    }, f"{case.name}: {description}; selected={action}"

        finally:
            await service.close()

    asyncio.run(run_acceptance())
