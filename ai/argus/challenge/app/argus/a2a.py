"""Strict, bounded A2A 1.0 HTTP+JSON values shared by Agents and Coordinator."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .config import MAX_ARTIFACT_BYTES, MAX_TASK_HISTORY
from .store import canonical_json


A2A_SOURCE_TYPE = "external-partner"
A2A_SKILL_ID = "deployment-control-review"
A2A_ARTIFACT_TYPE = "deployment-review"
A2A_RECOMMENDATION = "approve"
NORMALIZED_SECURITY_TOOL = "security.request_approval"
A2A_JSON_MEDIA_TYPE = "application/a2a+json"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SEND_MESSAGE_FIELDS = frozenset({"message", "configuration"})
_CONFIGURATION_FIELDS = frozenset({"acceptedOutputModes", "historyLength"})
_MESSAGE_FIELDS = frozenset({"messageId", "role", "parts", "metadata"})
_METADATA_FIELDS = frozenset({"sourceType"})
_PART_FIELDS = frozenset({"data", "mediaType"})
_ARTIFACT_FIELDS = frozenset({"type", "control_id", "target", "recommendation"})
_NORMALIZED_FIELDS = frozenset({"task_id", "control_id", "target", "decision"})
_TASK_STATES = {
    "submitted": "TASK_STATE_SUBMITTED",
    "working": "TASK_STATE_WORKING",
    "normalized": "TASK_STATE_WORKING",
    "completed": "TASK_STATE_COMPLETED",
    "failed": "TASK_STATE_FAILED",
    "rejected": "TASK_STATE_REJECTED",
}


class A2AValidationError(ValueError):
    """A bounded A2A contract or state value was rejected."""


def validate_task_id(value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise A2AValidationError("task id is invalid")
    return value


def validate_recommendation_artifact(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _ARTIFACT_FIELDS:
        raise A2AValidationError("recommendation artifact is invalid")
    artifact = dict(value)
    if (
        artifact["type"] != A2A_ARTIFACT_TYPE
        or artifact["recommendation"] != A2A_RECOMMENDATION
        or not isinstance(artifact["control_id"], str)
        or not _IDENTIFIER.fullmatch(artifact["control_id"])
        or not isinstance(artifact["target"], str)
        or not _IDENTIFIER.fullmatch(artifact["target"])
    ):
        raise A2AValidationError("recommendation artifact is invalid")
    if len(canonical_json(artifact).encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise A2AValidationError("recommendation artifact is too large")
    return {key: artifact[key] for key in _ARTIFACT_FIELDS}


def validate_send_message_request(value: Any) -> dict[str, Any]:
    """Validate the sole player-facing A2A SendMessageRequest contract."""

    if not isinstance(value, Mapping) or "message" not in value or not set(value) <= _SEND_MESSAGE_FIELDS:
        raise A2AValidationError("A2A SendMessage request is invalid")
    configuration = value.get("configuration", {})
    if not isinstance(configuration, Mapping) or not set(configuration) <= _CONFIGURATION_FIELDS:
        raise A2AValidationError("A2A SendMessage configuration is invalid")
    configuration = dict(configuration)
    output_modes = configuration.get("acceptedOutputModes")
    if output_modes is not None:
        if (
            not isinstance(output_modes, list)
            or not 1 <= len(output_modes) <= 8
            or any(not isinstance(mode, str) or not 1 <= len(mode) <= 128 or "/" not in mode for mode in output_modes)
            or "application/json" not in output_modes
        ):
            raise A2AValidationError("A2A SendMessage configuration is invalid")
    history_length = configuration.get("historyLength")
    if history_length is not None and (isinstance(history_length, bool) or not isinstance(history_length, int) or not 0 <= history_length <= MAX_TASK_HISTORY):
        raise A2AValidationError("A2A SendMessage configuration is invalid")
    message = value["message"]
    if not isinstance(message, Mapping) or set(message) != _MESSAGE_FIELDS:
        raise A2AValidationError("A2A message is invalid")
    if message["role"] != "ROLE_USER" or not isinstance(message["parts"], list) or len(message["parts"]) != 1:
        raise A2AValidationError("A2A message is invalid")
    message_id = validate_task_id(message["messageId"])
    metadata = message["metadata"]
    if (
        not isinstance(metadata, Mapping)
        or set(metadata) != _METADATA_FIELDS
        or metadata["sourceType"] != A2A_SOURCE_TYPE
    ):
        raise A2AValidationError("A2A message metadata is invalid")
    part = message["parts"][0]
    if (
        not isinstance(part, Mapping)
        or set(part) != _PART_FIELDS
        or part["mediaType"] != "application/json"
    ):
        raise A2AValidationError("A2A part is invalid")
    artifact = validate_recommendation_artifact(part["data"])
    normalized = {
        "message": {
            "messageId": message_id,
            "role": "ROLE_USER",
            "parts": [{"data": artifact, "mediaType": "application/json"}],
            "metadata": {"sourceType": A2A_SOURCE_TYPE},
        },
        "configuration": configuration,
        "configuration_present": "configuration" in value,
        "history_length": history_length,
        "source_type": A2A_SOURCE_TYPE,
        "skill_id": A2A_SKILL_ID,
        "artifact_type": A2A_ARTIFACT_TYPE,
        "artifact": artifact,
    }
    if len(canonical_json(normalized).encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise A2AValidationError("A2A SendMessage request is too large")
    return normalized


def a2a_wire(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the persisted, valid SendMessageRequest source representation."""

    wire = {
        "message": {
            "messageId": value["message"]["messageId"],
            "role": "ROLE_USER",
            "parts": [{"data": dict(value["artifact"]), "mediaType": "application/json"}],
            "metadata": dict(value["message"]["metadata"]),
        },
    }
    if value["configuration_present"]:
        wire["configuration"] = dict(value["configuration"])
    return wire


def normalize_recommendation(task_id: str, artifact: Mapping[str, Any]) -> dict[str, str]:
    validate_task_id(task_id)
    validated = validate_recommendation_artifact(artifact)
    return {
        "task_id": task_id,
        "control_id": validated["control_id"],
        "target": validated["target"],
        "decision": validated["recommendation"],
    }


def validate_normalized_request(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _NORMALIZED_FIELDS:
        raise A2AValidationError("normalized security request is invalid")
    normalized = dict(value)
    if normalized.get("decision") != A2A_RECOMMENDATION:
        raise A2AValidationError("normalized security request is invalid")
    validate_task_id(normalized.get("task_id"))
    for field in ("control_id", "target"):
        if not isinstance(normalized[field], str) or not _IDENTIFIER.fullmatch(normalized[field]):
            raise A2AValidationError("normalized security request is invalid")
    if len(canonical_json(normalized).encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise A2AValidationError("normalized security request is too large")
    return {key: normalized[key] for key in _NORMALIZED_FIELDS}


def task_projection(
    row: Mapping[str, Any], approval: Mapping[str, Any] | None = None, history_length: int | None = None
) -> dict[str, Any]:
    """Convert persisted internal state to the bounded A2A v1 Task response."""

    try:
        source = validate_send_message_request(json.loads(row["artifact_json"]))
    except (KeyError, TypeError, json.JSONDecodeError, A2AValidationError) as exc:
        raise A2AValidationError("stored A2A task is invalid") from exc
    if (
        row["origin_subject"] != source["source_type"]
        or row["owner_class"] != A2A_SOURCE_TYPE
        or row["skill_id"] != source["skill_id"]
        or row["artifact_kind"] != A2A_ARTIFACT_TYPE
        or not row["context_id"]
    ):
        raise A2AValidationError("stored A2A task is inconsistent")
    task: dict[str, Any] = {
        "id": row["id"],
        "contextId": row["context_id"],
        "status": {"state": _TASK_STATES.get(row["status"], "TASK_STATE_FAILED")},
        "metadata": {"artifact": dict(source["artifact"]), "skill": A2A_SKILL_ID},
    }
    if history_length != 0:
        task["history"] = [dict(source["message"])][-history_length:] if history_length else [dict(source["message"])]
    normalized_tool = row["normalized_tool"]
    if normalized_tool:
        try:
            normalized_state = json.loads(normalized_tool)
        except (TypeError, json.JSONDecodeError) as exc:
            raise A2AValidationError("stored normalized task state is invalid") from exc
        if isinstance(normalized_state, Mapping) and isinstance(normalized_state.get("request"), Mapping):
            task["metadata"]["normalization"] = dict(normalized_state["request"])
    if approval is not None:
        task["artifacts"] = [{
            "artifactId": f"approval-{approval['id']}",
            "name": "security-approval",
            "parts": [{"data": {
                "approval_id": approval["id"], "task_id": approval["task_id"],
                "control_id": approval["control_id"], "target": approval["target"],
                "granted_capability": approval["granted_capability"], "expires_at": approval["expires_at"],
                "key_id": approval["key_id"], "signature": approval["signature"],
            }, "mediaType": "application/json"}],
        }]
    return task
