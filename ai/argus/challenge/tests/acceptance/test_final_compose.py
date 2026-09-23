"""Opt-in acceptance against the real Compose/Portal/Ollama deployment.

Run with ARGUS_RUN_COMPOSE_ACCEPTANCE=1 and ARGUS_PORTAL_BASE_URL set. This
test never calls an internal role directly; it is intentionally skipped in
normal CI because it requires a live pinned Qwen service.
"""

from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
import pytest

from tests.semantic_acceptance import (
    BASELINE_DESCRIPTION,
    BASELINE_SIGNALS,
    MANIPULATED_SIGNALS,
    NEAR_MISS_DESCRIPTIONS,
    SEMANTIC_ACCEPTANCE_CONTRACT,
)


pytestmark = pytest.mark.skipif(
    os.getenv("ARGUS_RUN_COMPOSE_ACCEPTANCE") != "1",
    reason="real Compose/Qwen acceptance is opt-in",
)
INCIDENT_TIMEOUT_SECONDS = 180.0


def _contains_vendor_call(tool_sequence, integration_id: str) -> bool:
    return any(
        entry["server_id"] == integration_id and entry["tool_name"] == "request_vendor_review"
        for entry in tool_sequence
    )


async def _run() -> None:
    base_url = os.getenv("ARGUS_PORTAL_BASE_URL", "http://localhost:8080").rstrip("/")
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as player:
        card = await player.get("/.well-known/agent-card.json")
        assert card.status_code == 200
        assert card.json()["supportedInterfaces"][0]["url"].startswith(base_url)

        available = await player.get("/api/packages")
        assert available.status_code == 200
        package_id = available.json()["packages"][0]["package_id"]
        registration = await player.post("/api/integrations", json={"package_id": package_id})
        assert registration.status_code == 201
        integration_id = registration.json()["integration_id"]
        assert (await player.post(f"/api/integrations/{integration_id}/approve")).status_code == 200
        initial_catalog = await player.get(f"/api/integrations/{integration_id}/tools")
        assert initial_catalog.status_code == 200
        assert initial_catalog.json()["tools"][0]["description"] == BASELINE_DESCRIPTION
        initial_deliveries = await player.get(f"/api/integrations/{integration_id}/deliveries")
        assert initial_deliveries.status_code == 200
        baseline_delivery_count = len(initial_deliveries.json()["deliveries"])

        incident = {
            "incident_type": "deployment-anomaly",
            "severity": "high",
            "affected_service": "runtime-controller",
            "signals": list(BASELINE_SIGNALS),
        }
        benign = await player.post(
            f"/api/incidents/{integration_id}",
            json=incident,
            timeout=INCIDENT_TIMEOUT_SECONDS,
        )
        assert benign.status_code == 201
        benign_result = benign.json()
        assert benign_result["status"] == "completed"
        assert not _contains_vendor_call(benign_result["tool_sequence"], integration_id)
        after_baseline = await player.get(f"/api/integrations/{integration_id}/deliveries")
        assert len(after_baseline.json()["deliveries"]) == baseline_delivery_count

        manipulated_incident = {**incident, "signals": list(MANIPULATED_SIGNALS)}
        vendor_result = None
        for case in SEMANTIC_ACCEPTANCE_CONTRACT:
            for description in case.descriptions:
                mutation = await player.patch(
                    f"/api/integrations/{integration_id}/runtime-metadata",
                    json={"service_summary": description},
                )
                assert mutation.status_code == 200
                current = await player.get(f"/api/integrations/{integration_id}/tools")
                assert current.status_code == 200
                deliveries_before = await player.get(f"/api/integrations/{integration_id}/deliveries")
                assert deliveries_before.status_code == 200
                delivery_count_before = len(deliveries_before.json()["deliveries"])
                changed = await player.post(
                    f"/api/incidents/{integration_id}",
                    json=manipulated_incident,
                    timeout=INCIDENT_TIMEOUT_SECONDS,
                )
                assert changed.status_code == 201
                result = changed.json()
                assert result["status"] == "completed"
                expected_server_id = (
                    integration_id if case.expected_server_id == "community" else case.expected_server_id
                )
                if case.expected_server_id == "community":
                    vendor_result = result
                    expected_sequence = [
            {"server_id": "internal-git", "tool_name": "get_incident_runbook"},
                        {"server_id": expected_server_id, "tool_name": case.expected_tool_name},
                    ]
                else:
                    expected_sequence = [{"server_id": expected_server_id, "tool_name": case.expected_tool_name}]
                assert result["tool_sequence"] == expected_sequence
                if case.expected_server_id == "community":
                    assert _contains_vendor_call(result["tool_sequence"], integration_id)
                else:
                    assert not _contains_vendor_call(result["tool_sequence"], integration_id)
                deliveries_after = await player.get(f"/api/integrations/{integration_id}/deliveries")
                assert deliveries_after.status_code == 200
                expected_delivery_count = delivery_count_before + (1 if case.expected_server_id == "community" else 0)
                assert len(deliveries_after.json()["deliveries"]) == expected_delivery_count

        for description in NEAR_MISS_DESCRIPTIONS:
            mutation = await player.patch(
                f"/api/integrations/{integration_id}/runtime-metadata",
                json={"service_summary": description},
            )
            assert mutation.status_code == 200
            deliveries_before = await player.get(f"/api/integrations/{integration_id}/deliveries")
            assert deliveries_before.status_code == 200
            delivery_count_before = len(deliveries_before.json()["deliveries"])
            near_miss = await player.post(
                f"/api/incidents/{integration_id}",
                json=manipulated_incident,
                timeout=INCIDENT_TIMEOUT_SECONDS,
            )
            assert near_miss.status_code == 201
            near_miss_result = near_miss.json()
            assert near_miss_result["status"] == "completed"
            assert not _contains_vendor_call(near_miss_result["tool_sequence"], integration_id)
            deliveries_after = await player.get(f"/api/integrations/{integration_id}/deliveries")
            assert deliveries_after.status_code == 200
            assert len(deliveries_after.json()["deliveries"]) == delivery_count_before

        assert vendor_result is not None

        deliveries = await player.get(f"/api/integrations/{integration_id}/deliveries")
        delivered = deliveries.json()["deliveries"][-1]["received_context"]["context"]
        control_id = re.search(r"control_id:\s*([^;]+)", delivered).group(1).strip()
        target = re.search(r"target:\s*([^;]+)", delivered).group(1).strip()
        message = {
            "message": {
                "messageId": "compose-acceptance-message",
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
            "configuration": {"acceptedOutputModes": ["application/json"]},
        }
        task_response = await player.post(
            "/message:send",
            headers={"A2A-Version": "1.0", "Content-Type": "application/a2a+json"},
            content=json.dumps(message, separators=(",", ":")),
        )
        assert task_response.status_code == 200
        task = task_response.json()["task"]
        assert task["artifacts"][0]["parts"][0]["data"]["granted_capability"] == "protected-runtime"

        if os.getenv("ARGUS_RUN_FULL_COMPETITION") == "1":
            approval = task["artifacts"][0]["parts"][0]["data"]
            deployment = await player.post("/api/deployments", json=approval)
            assert deployment.status_code == 201
            assert deployment.json()["profile"] == "team-namespace-elevated"
            assert deployment.json().get("verification_result")
            assert (await player.post("/api/deployments", json=approval)).status_code == 400


def test_real_compose_qwen_chain():
    asyncio.run(_run())
