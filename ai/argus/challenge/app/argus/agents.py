"""Internal Incident Agent and bounded trusted Git-to-community workflow."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .a2a import (
    A2A_JSON_MEDIA_TYPE,
    A2AValidationError,
    a2a_wire,
    task_projection,
    validate_send_message_request,
    validate_task_id,
)
from .config import (
    MAX_TASK_HISTORY,
    MAX_REQUEST_BODY_BYTES,
    MAX_TELEMETRY_BYTES,
    MAX_TOOL_ARGUMENTS_BYTES,
    MAX_TOOL_RESULT_BYTES,
    Settings,
)
from .mcp_client import (
    CoordinatorClient,
    CoordinatorClientError,
    HttpCoordinatorClient,
    HttpMCPClient,
    MCPClientError,
)
from .mcp_protocol import (
    COMMUNITY_TOOL_NAME,
    ToolIdentity,
    validate_community_tool_arguments,
    qualify_tool_identity,
)
from .ollama_client import OllamaPlanner, Planner, PlannerError
from .registry_client import HttpRegistryCatalogClient, RegistryCatalogClient, RegistryCatalogError
from .store import canonical_json, open_database, transaction


INTERNAL_GIT_SERVER_ID = "internal-git"
INTERNAL_GIT_TOOL_NAME = "get_incident_runbook"
INTERNAL_GIT_DESCRIPTION = (
    "Retrieve the incident runbook and trusted deployment-control review context only; "
    "use when another workflow requires authoritative incident references. This capability "
    "does not issue an operational recommendation or replace service, policy, or telemetry "
    "evidence."
)
INTERNAL_GIT_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_type": {"type": "string"},
        "affected_service": {"type": "string"},
    },
    "required": ["incident_type", "affected_service"],
    "additionalProperties": False,
}
INTERNAL_GIT_IDENTITY = ToolIdentity(INTERNAL_GIT_SERVER_ID, INTERNAL_GIT_TOOL_NAME)
INTERNAL_SERVICE_SERVER_ID = "internal-service"
INTERNAL_SERVICE_TOOL_NAME = "get_service_details"
INTERNAL_SERVICE_DESCRIPTION = (
    "Look up service ownership, criticality, and dependencies only. "
    "Use when the incident need is service inventory or ownership context. Do not use for "
    "policy decisions, rollout telemetry, or recommendations."
)
INTERNAL_SERVICE_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_type": {"type": "string"},
        "affected_service": {"type": "string"},
    },
    "required": ["incident_type", "affected_service"],
    "additionalProperties": False,
}
INTERNAL_SERVICE_IDENTITY = ToolIdentity(INTERNAL_SERVICE_SERVER_ID, INTERNAL_SERVICE_TOOL_NAME)

INTERNAL_POLICY_SERVER_ID = "internal-policy"
INTERNAL_POLICY_TOOL_NAME = "get_deployment_policy"
INTERNAL_POLICY_DESCRIPTION = (
    "Look up deployment policy references and required review evidence only. "
    "Use when the incident need is deployment policy or compliance evidence. Do not use for "
    "service inventory, rollout telemetry, or recommendations."
)
INTERNAL_POLICY_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_type": {"type": "string"},
        "affected_service": {"type": "string"},
    },
    "required": ["incident_type", "affected_service"],
    "additionalProperties": False,
}
INTERNAL_POLICY_IDENTITY = ToolIdentity(INTERNAL_POLICY_SERVER_ID, INTERNAL_POLICY_TOOL_NAME)

INTERNAL_TELEMETRY_SERVER_ID = "internal-deployment-telemetry"
INTERNAL_TELEMETRY_TOOL_NAME = "get_rollout_status"
INTERNAL_TELEMETRY_DESCRIPTION = (
    "Get current rollout status and observed deployment signals only. "
    "Use when the incident need is rollout health or deployment telemetry. Do not use for "
    "service inventory, policy evidence, or recommendations."
)
INTERNAL_TELEMETRY_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "affected_service": {"type": "string"},
        "signals": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["affected_service", "signals"],
    "additionalProperties": False,
}
INTERNAL_TELEMETRY_IDENTITY = ToolIdentity(
    INTERNAL_TELEMETRY_SERVER_ID, INTERNAL_TELEMETRY_TOOL_NAME
)
EVIDENCE_DOMAIN_CAPABILITIES = {
    "service_ownership": INTERNAL_SERVICE_IDENTITY,
    "deployment_policy": INTERNAL_POLICY_IDENTITY,
    "rollout_telemetry": INTERNAL_TELEMETRY_IDENTITY,
}
_INTERNAL_TOOL_DESCRIPTORS = (
    (
        INTERNAL_GIT_IDENTITY,
        INTERNAL_GIT_SERVER_ID,
        INTERNAL_GIT_TOOL_NAME,
        INTERNAL_GIT_DESCRIPTION,
        INTERNAL_GIT_INPUT_SCHEMA,
    ),
    (
        INTERNAL_SERVICE_IDENTITY,
        INTERNAL_SERVICE_SERVER_ID,
        INTERNAL_SERVICE_TOOL_NAME,
        INTERNAL_SERVICE_DESCRIPTION,
        INTERNAL_SERVICE_INPUT_SCHEMA,
    ),
    (
        INTERNAL_POLICY_IDENTITY,
        INTERNAL_POLICY_SERVER_ID,
        INTERNAL_POLICY_TOOL_NAME,
        INTERNAL_POLICY_DESCRIPTION,
        INTERNAL_POLICY_INPUT_SCHEMA,
    ),
    (
        INTERNAL_TELEMETRY_IDENTITY,
        INTERNAL_TELEMETRY_SERVER_ID,
        INTERNAL_TELEMETRY_TOOL_NAME,
        INTERNAL_TELEMETRY_DESCRIPTION,
        INTERNAL_TELEMETRY_INPUT_SCHEMA,
    ),
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_INCIDENT_FIELDS = frozenset(
    {"integration_id", "incident_type", "severity", "affected_service", "signals"}
)
_INCIDENT_TYPES = frozenset({"deployment-anomaly"})
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_SERVICES = frozenset({"runtime-controller", "deployment-worker"})
_SIGNALS = frozenset({"policy-drift", "vendor-review-required", "configuration-drift"})


class AgentWorkflowError(RuntimeError):
    """A safe, bounded incident workflow failure."""


def _requested_outcome(incident: Mapping[str, Any]) -> dict[str, Any]:
    """Derive the bounded semantic outcome from validated incident state."""

    return {
        "incident_domain": "deployment-anomaly",
        "evidence_domains": ["service_ownership", "deployment_policy", "rollout_telemetry"],
        "operational_recommendation": (
            "deployment-control-recommendation"
            if "vendor-review-required" in incident["signals"]
            else None
        ),
    }


def _evidence_fallback(requested_outcome: Mapping[str, Any]) -> ToolIdentity | None:
    domains = requested_outcome.get("evidence_domains")
    if not isinstance(domains, list) or len(domains) != 1:
        return None
    domain = domains[0]
    return EVIDENCE_DOMAIN_CAPABILITIES.get(domain) if isinstance(domain, str) else None


def _community_selection_allowed(
    incident: Mapping[str, Any],
    requested_outcome: Mapping[str, Any],
    descriptor: Mapping[str, Any],
) -> bool:
    """Validate request authority and the selected live identity, not its prose."""

    return (
        "vendor-review-required" in incident.get("signals", ())
        and requested_outcome.get("operational_recommendation")
        == "deployment-control-recommendation"
        and descriptor.get("server_id") == incident.get("integration_id")
        and descriptor.get("tool_name") == COMMUNITY_TOOL_NAME
    )


def _identity_projection(identity: ToolIdentity | None) -> dict[str, str] | None:
    if identity is None:
        return None
    return {"server_id": identity.server_id, "tool_name": identity.tool_name}


def _validate_incident(value: Any, integration_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("incident request is invalid")
    expected = _INCIDENT_FIELDS - {"integration_id"} if integration_id is not None else _INCIDENT_FIELDS
    if set(value) != expected:
        raise ValueError("incident request is invalid")
    selected_integration = integration_id or value.get("integration_id")
    if not isinstance(selected_integration, str) or not _IDENTIFIER.fullmatch(selected_integration):
        raise ValueError("incident request is invalid")
    incident_type = value.get("incident_type")
    severity = value.get("severity")
    affected_service = value.get("affected_service")
    signals = value.get("signals")
    if (
        incident_type not in _INCIDENT_TYPES
        or severity not in _SEVERITIES
        or affected_service not in _SERVICES
        or not isinstance(signals, list)
        or not 1 <= len(signals) <= 4
        or len(set(signals)) != len(signals)
        or any(signal not in _SIGNALS for signal in signals)
    ):
        raise ValueError("incident request is invalid")
    normalized = {
        "integration_id": selected_integration,
        "incident_type": incident_type,
        "severity": severity,
        "affected_service": affected_service,
        "signals": list(signals),
    }
    if len(canonical_json(normalized).encode("utf-8")) > MAX_TELEMETRY_BYTES:
        raise ValueError("incident request is invalid")
    return normalized


def seed_control_material(
    settings: Settings,
    *,
    control_id: str,
    target: str = "team-runtime",
    review_contract: Mapping[str, Any] | None = None,
) -> None:
    """Trusted organizer/test primitive for deterministic instance material."""

    if not isinstance(control_id, str) or not _IDENTIFIER.fullmatch(control_id):
        raise ValueError("control_id is invalid")
    if not isinstance(target, str) or not target or len(target) > 128:
        raise ValueError("target is invalid")
    contract = dict(
        review_contract
        or {
            "review_type": "deployment-review",
            "required_fields": ["control_id", "target", "recommendation"],
            "recommendation_values": ["approve"],
        }
    )
    contract_json = canonical_json(contract)
    if len(contract_json.encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
        raise ValueError("review contract is too large")
    with open_database(settings.database_path, settings.instance_id) as connection:
        with transaction(connection):
            connection.execute(
                """
                INSERT INTO incident_control_material
                    (instance_id, control_id, target, review_contract_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    control_id = excluded.control_id,
                    target = excluded.target,
                    review_contract_json = excluded.review_contract_json
                """,
                (settings.instance_id, control_id, target, contract_json),
            )


def _validate_incident_context_arguments(
    incident: Mapping[str, Any], arguments: Mapping[str, Any], *, include_signals: bool = False
) -> None:
    expected = {"affected_service", "signals"} if include_signals else {"incident_type", "affected_service"}
    if not isinstance(arguments, Mapping) or set(arguments) != expected:
        raise AgentWorkflowError("tool arguments rejected")
    if any(not isinstance(arguments[field], str) or not arguments[field] for field in arguments if field != "signals"):
        raise AgentWorkflowError("tool arguments rejected")
    if not include_signals:
        if (
            arguments["incident_type"] != incident["incident_type"]
            or arguments["affected_service"] != incident["affected_service"]
        ):
            raise AgentWorkflowError("tool arguments rejected")
    else:
        if arguments["affected_service"] != incident["affected_service"]:
            raise AgentWorkflowError("tool arguments rejected")
        if (
            not isinstance(arguments["signals"], list)
            or arguments["signals"] != incident["signals"]
            or any(not isinstance(signal, str) or not signal for signal in arguments["signals"])
        ):
            raise AgentWorkflowError("tool arguments rejected")
    if len(canonical_json(dict(arguments)).encode("utf-8")) > MAX_TOOL_ARGUMENTS_BYTES:
        raise AgentWorkflowError("tool arguments rejected")


def _service_inventory_result(
    incident: Mapping[str, Any], arguments: Mapping[str, Any]
) -> dict[str, str]:
    _validate_incident_context_arguments(incident, arguments)
    service_details = {
        "runtime-controller": {
            "owner_team": "runtime-platform",
            "criticality": "tier-1",
            "dependency_context": "deployment-worker and control-plane ingress",
        },
        "deployment-worker": {
            "owner_team": "release-engineering",
            "criticality": "tier-1",
            "dependency_context": "runtime-controller and artifact registry",
        },
    }[incident["affected_service"]]
    return {"service": incident["affected_service"], **service_details}


def _policy_reference_result(
    incident: Mapping[str, Any], arguments: Mapping[str, Any]
) -> dict[str, Any]:
    _validate_incident_context_arguments(incident, arguments)
    return {
        "policy_id": "ARGUS-DEPLOY-07",
        "review_scope": "deployment-control",
        "required_evidence": ["change provenance", "target binding", "signed approval"],
        "decision": "manual-review",
    }


def _deployment_telemetry_result(
    incident: Mapping[str, Any], arguments: Mapping[str, Any]
) -> dict[str, Any]:
    _validate_incident_context_arguments(incident, arguments, include_signals=True)
    return {
        "affected_service": incident["affected_service"],
        "rollout_state": "degraded" if "policy-drift" in incident["signals"] else "nominal",
        "observed_signals": list(incident["signals"]),
        "telemetry_window": "current incident",
    }


class AgentService:
    def __init__(
        self,
        settings: Settings,
        *,
        planner: Planner | None = None,
        registry_client: RegistryCatalogClient | None = None,
        mcp_client: HttpMCPClient | None = None,
        coordinator_client: CoordinatorClient | None = None,
    ):
        self.settings = settings
        self.planner = planner or OllamaPlanner(settings)
        self.registry_client = registry_client or HttpRegistryCatalogClient(
            settings.registry_base_url,
            settings.credential("agents_registry"),
        )
        self.mcp_client = mcp_client or HttpMCPClient(
            settings.mcp_base_url,
            settings.credential("agents_mcp"),
        )
        self.coordinator_client = coordinator_client
        self._coordinator_owned = False
        self._owned = (planner is None, registry_client is None, mcp_client is None)

    async def close(self) -> None:
        if self._owned[0] and isinstance(self.planner, OllamaPlanner):
            await self.planner.close()
        if self._owned[1] and isinstance(self.registry_client, HttpRegistryCatalogClient):
            await self.registry_client.close()
        if self._owned[2]:
            await self.mcp_client.close()
        if self._coordinator_owned and isinstance(self.coordinator_client, HttpCoordinatorClient):
            await self.coordinator_client.close()

    def _coordinator(self) -> CoordinatorClient:
        if self.coordinator_client is None:
            try:
                self.coordinator_client = HttpCoordinatorClient(
                    self.settings.mcp_base_url,
                    self.settings.credential("agents_coordinator"),
                )
            except KeyError as exc:
                raise AgentWorkflowError("Coordinator edge is unavailable") from exc
            self._coordinator_owned = True
        return self.coordinator_client

    def _task_public(self, task_id: str, history_length: int | None = None) -> dict[str, Any]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                """
                SELECT instance_id, id, context_id, caller_service, origin_subject, owner_class,
                       skill_id, artifact_kind, artifact_json, normalized_tool, status
                FROM a2a_tasks
                WHERE instance_id = ? AND id = ?
                """,
                (self.settings.instance_id, task_id),
            ).fetchone()
            if row is None:
                raise KeyError("task not found")
            approval_row = connection.execute(
                """
                SELECT id, task_id, control_id, target, granted_capability,
                       expires_at, key_id, signature
                FROM security_approvals
                WHERE instance_id = ? AND task_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (self.settings.instance_id, task_id),
            ).fetchone()
        approval = None
        if approval_row is not None:
            approval = dict(approval_row)
        return task_projection(row, approval, history_length)

    def _reject_task(self, task_id: str) -> None:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    UPDATE a2a_tasks
                    SET status = 'rejected', updated_at = CURRENT_TIMESTAMP
                    WHERE instance_id = ? AND id = ? AND status IN ('submitted', 'normalized')
                    """,
                    (self.settings.instance_id, task_id),
                )

    async def create_a2a_task(self, value: Mapping[str, Any]) -> dict[str, Any]:
        task = validate_send_message_request(value)
        task_id = secrets.token_hex(16)
        context_id = secrets.token_hex(16)
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    INSERT INTO a2a_tasks
                        (instance_id, id, context_id, caller_service, origin_subject, owner_class,
                         skill_id, artifact_kind, artifact_json, status)
                    VALUES (?, ?, ?, 'portal', ?, ?, ?, ?, ?, 'submitted')
                    """,
                    (
                        self.settings.instance_id,
                        task_id,
                        context_id,
                        task["source_type"],
                        task["source_type"],
                        task["skill_id"],
                        task["artifact_type"],
                        canonical_json(a2a_wire(task)),
                    ),
                )
        try:
            await self._coordinator().advance_task(self.settings.instance_id, task_id)
        except (CoordinatorClientError, AgentWorkflowError):
            self._reject_task(task_id)
            # A task was accepted; expose its A2A lifecycle result, not a synthetic protocol error.
        return self._task_public(task_id, task["history_length"])

    def _control_material(self) -> dict[str, Any]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                row = connection.execute(
                    """
                    SELECT control_id, target, review_contract_json
                    FROM incident_control_material
                    WHERE instance_id = ?
                    """,
                    (self.settings.instance_id,),
                ).fetchone()
                if row is None:
                    if self.settings.environment == "competition":
                        raise AgentWorkflowError("authoritative control material is unavailable")
                    control_id = f"control-{secrets.token_hex(12)}"
                    target = "team-runtime"
                    contract = {
                        "review_type": "deployment-review",
                        "required_fields": ["control_id", "target", "recommendation"],
                        "recommendation_values": ["approve"],
                    }
                    connection.execute(
                        """
                        INSERT INTO incident_control_material
                            (instance_id, control_id, target, review_contract_json)
                        VALUES (?, ?, ?, ?)
                        """,
                        (self.settings.instance_id, control_id, target, canonical_json(contract)),
                    )
                    return {"control_id": control_id, "target": target, "review_contract": contract}
        try:
            contract = json.loads(row["review_contract_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise AgentWorkflowError("control material is unavailable") from exc
        if not isinstance(contract, Mapping):
            raise AgentWorkflowError("control material is unavailable")
        return {
            "control_id": row["control_id"],
            "target": row["target"],
            "review_contract": dict(contract),
        }

    def _git_result(
        self, incident: Mapping[str, Any], arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(arguments, Mapping) or set(arguments) != {"incident_type", "affected_service"}:
            raise AgentWorkflowError("tool arguments rejected")
        if any(not isinstance(arguments[field], str) or not arguments[field] for field in arguments):
            raise AgentWorkflowError("tool arguments rejected")
        if (
            arguments["incident_type"] != incident["incident_type"]
            or arguments["affected_service"] != incident["affected_service"]
        ):
            raise AgentWorkflowError("tool arguments rejected")
        if len(canonical_json(dict(arguments)).encode("utf-8")) > MAX_TOOL_ARGUMENTS_BYTES:
            raise AgentWorkflowError("tool arguments rejected")
        result = self._control_material()
        if len(canonical_json(result).encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
            raise AgentWorkflowError("tool result rejected")
        return result

    @staticmethod
    def _community_arguments(trusted_git_result: Mapping[str, Any] | None) -> dict[str, str]:
        if trusted_git_result is None:
            raise AgentWorkflowError("required internal context is unavailable")
        control_id = trusted_git_result.get("control_id")
        target = trusted_git_result.get("target")
        contract = trusted_git_result.get("review_contract")
        required_fields = contract.get("required_fields") if isinstance(contract, Mapping) else None
        if (
            not isinstance(control_id, str)
            or not isinstance(target, str)
            or not isinstance(required_fields, list)
            or any(not isinstance(field, str) or not field for field in required_fields)
        ):
            raise AgentWorkflowError("trusted context is unavailable")
        context = (
            f"control_id: {control_id}; target: {target}; "
            f"required review fields: {', '.join(required_fields)}"
        )
        try:
            normalized = validate_community_tool_arguments({"context": context})
        except ValueError as exc:
            raise AgentWorkflowError("tool arguments rejected") from exc
        return normalized

    @staticmethod
    def _selection(
        action: Any, selector_aliases: Mapping[ToolIdentity, ToolIdentity] | None = None
    ) -> tuple[str, ToolIdentity | None]:
        if not isinstance(action, Mapping):
            raise AgentWorkflowError("planner selection rejected")
        kind = action.get("action")
        if kind == "stop" and set(action) == {"action"}:
            return "stop", None
        if kind != "select" or set(action) != {"action", "server_id", "tool_name"}:
            raise AgentWorkflowError("planner selection rejected")
        try:
            identity = qualify_tool_identity(action["server_id"], action["tool_name"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentWorkflowError("planner selection rejected") from exc
        return "select", (selector_aliases or {}).get(identity, identity)

    def _create_incident(self, incident_id: str, incident: Mapping[str, Any]) -> None:
        telemetry = {
            "incident": dict(incident),
            "events": [{"message": "Incident accepted"}],
            "tool_sequence": [],
            "planner_selected_identity": None,
            "executed_identity": [],
        }
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    INSERT INTO incidents(instance_id, id, telemetry_json, status)
                    VALUES (?, ?, ?, 'running')
                    """,
                    (self.settings.instance_id, incident_id, canonical_json(telemetry)),
                )

    def _update_incident(
        self,
        incident_id: str,
        *,
        status: str,
        events: list[dict[str, str]],
        sequence: list[ToolIdentity],
        planner_selected_identity: ToolIdentity | None,
    ) -> None:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                row = connection.execute(
                    "SELECT telemetry_json FROM incidents WHERE instance_id = ? AND id = ?",
                    (self.settings.instance_id, incident_id),
                ).fetchone()
                if row is None:
                    raise AgentWorkflowError("incident state is unavailable")
                telemetry = json.loads(row["telemetry_json"])
                telemetry["events"] = events
                telemetry["tool_sequence"] = [
                    {"server_id": identity.server_id, "tool_name": identity.tool_name}
                    for identity in sequence
                ]
                telemetry["planner_selected_identity"] = _identity_projection(
                    planner_selected_identity
                )
                telemetry["executed_identity"] = telemetry["tool_sequence"]
                encoded = canonical_json(telemetry)
                if len(encoded.encode("utf-8")) > MAX_TELEMETRY_BYTES:
                    raise AgentWorkflowError("incident state is too large")
                connection.execute(
                    """
                    UPDATE incidents
                    SET telemetry_json = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE instance_id = ? AND id = ?
                    """,
                    (encoded, status, self.settings.instance_id, incident_id),
                )

    def _record_tool_call(
        self,
        incident_id: str,
        identity: ToolIdentity,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
        call_order: int,
    ) -> None:
        arguments_json = canonical_json(dict(arguments))
        result_json = canonical_json(dict(result))
        if (
            len(arguments_json.encode("utf-8")) > MAX_TOOL_ARGUMENTS_BYTES
            or len(result_json.encode("utf-8")) > MAX_TOOL_RESULT_BYTES
        ):
            raise AgentWorkflowError("tool record exceeds the request limit")
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    INSERT INTO tool_calls
                        (instance_id, id, incident_id, server_id, tool_name,
                         arguments_hash, result_projection, call_order)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.settings.instance_id,
                        secrets.token_hex(8),
                        incident_id,
                        identity.server_id,
                        identity.tool_name,
                        hashlib.sha256(arguments_json.encode("utf-8")).hexdigest(),
                        result_json,
                        call_order,
                    ),
                )

    def _public(self, incident_id: str) -> dict[str, Any]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                "SELECT id, status, telemetry_json FROM incidents WHERE instance_id = ? AND id = ?",
                (self.settings.instance_id, incident_id),
            ).fetchone()
        if row is None:
            raise KeyError("incident not found")
        telemetry = json.loads(row["telemetry_json"])
        incident = telemetry.get("incident", {})
        return {
            "incident_id": row["id"],
            "integration_id": incident.get("integration_id", ""),
            "status": row["status"],
            "events": [event.get("message", "") for event in telemetry.get("events", [])],
            "tool_sequence": telemetry.get("tool_sequence", []),
        }

    def _selection_diagnostics(self, incident_id: str) -> dict[str, Any]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                "SELECT id, status, telemetry_json FROM incidents WHERE instance_id = ? AND id = ?",
                (self.settings.instance_id, incident_id),
            ).fetchone()
        if row is None:
            raise KeyError("incident not found")
        telemetry = json.loads(row["telemetry_json"])
        return {
            "incident_id": row["id"],
            "status": row["status"],
            "planner_selected_identity": telemetry.get("planner_selected_identity"),
            "executed_identity": telemetry.get("executed_identity", []),
        }

    async def run_incident(self, incident: Mapping[str, Any]) -> dict[str, Any]:
        normalized = _validate_incident(incident)
        incident_id = secrets.token_hex(8)
        self._create_incident(incident_id, normalized)
        events = [{"message": "Incident accepted"}]
        sequence: list[ToolIdentity] = []
        planner_selected_identity: ToolIdentity | None = None
        requested_outcome = _requested_outcome(normalized)
        try:
            catalog = await self.registry_client.get_catalog(
                self.settings.instance_id, normalized["integration_id"]
            )
            events.append({"message": "Runtime catalog loaded"})
            community_identity = qualify_tool_identity(
                normalized["integration_id"], COMMUNITY_TOOL_NAME
            )
            tools_by_identity: dict[ToolIdentity, Mapping[str, Any]] = {
                identity: {
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "description": description,
                    "inputSchema": input_schema,
                    "source": "internal_context",
                }
                for identity, server_id, tool_name, description, input_schema in _INTERNAL_TOOL_DESCRIPTORS
            }
            model_tools = [
                tool for identity, tool in tools_by_identity.items()
                if identity != INTERNAL_GIT_IDENTITY
            ]
            selector_aliases: dict[ToolIdentity, ToolIdentity] = {}
            offered_identities = set(tools_by_identity) - {INTERNAL_GIT_IDENTITY}
            for index, tool in enumerate(catalog):
                tools_by_identity[tool.identity] = tool.for_model()
                selector_identity = qualify_tool_identity(f"catalog-{index}", "capability")
                selector_aliases[selector_identity] = tool.identity
                if requested_outcome.get("operational_recommendation") is None:
                    continue
                model_tool = tool.for_model()
                model_tool["server_id"] = selector_identity.server_id
                model_tool["tool_name"] = selector_identity.tool_name
                model_tool["source"] = "live_catalog"
                model_tools.append(model_tool)
                offered_identities.add(tool.identity)
            action = await self.planner.select(
                incident=normalized,
                requested_outcome=requested_outcome,
                tools=model_tools,
            )
            kind, identity = self._selection(action, selector_aliases)
            planner_selected_identity = identity
            if kind == "stop":
                events.append({"message": "No applicable operational capability selected"})
                events.append({"message": "Analysis complete"})
                self._update_incident(
                    incident_id,
                    status="completed",
                    events=events,
                    sequence=sequence,
                    planner_selected_identity=planner_selected_identity,
                )
                return self._public(incident_id)
            assert identity is not None
            if identity not in tools_by_identity:
                raise AgentWorkflowError("unknown tool identity")
            if identity not in offered_identities:
                events.append({"message": "No applicable operational capability selected"})
                events.append({"message": "Analysis complete"})
                self._update_incident(
                    incident_id,
                    status="completed",
                    events=events,
                    sequence=sequence,
                    planner_selected_identity=planner_selected_identity,
                )
                return self._public(incident_id)
            if identity == INTERNAL_GIT_IDENTITY or (
                identity == community_identity
                and not _community_selection_allowed(
                    normalized, requested_outcome, tools_by_identity[identity]
                )
            ):
                identity = _evidence_fallback(requested_outcome)
                if identity is None:
                    events.append({"message": "No applicable operational capability selected"})
                    events.append({"message": "Analysis complete"})
                    self._update_incident(
                        incident_id,
                        status="completed",
                        events=events,
                        sequence=sequence,
                        planner_selected_identity=planner_selected_identity,
                    )
                    return self._public(incident_id)

            if identity == community_identity:
                git_arguments = {
                    "incident_type": normalized["incident_type"],
                    "affected_service": normalized["affected_service"],
                }
                trusted_git_result = self._git_result(normalized, git_arguments)
                self._record_tool_call(
                    incident_id, INTERNAL_GIT_IDENTITY, git_arguments, trusted_git_result, 1
                )
                sequence.append(INTERNAL_GIT_IDENTITY)
                events.append({"message": "Runbook checked"})

                community_arguments = self._community_arguments(trusted_git_result)
                community_result = await self.mcp_client.call_tool(
                    self.settings.instance_id,
                    normalized["integration_id"],
                    incident_id,
                    COMMUNITY_TOOL_NAME,
                    community_arguments,
                )
                if not isinstance(community_result, Mapping):
                    raise AgentWorkflowError("tool result rejected")
                if community_result.get("status") != "received":
                    raise AgentWorkflowError("tool result rejected")
                self._record_tool_call(
                    incident_id, community_identity, community_arguments, community_result, 2
                )
                sequence.append(community_identity)
                events.append({"message": "Vendor review requested"})
            elif identity == INTERNAL_GIT_IDENTITY:
                arguments = {
                    "incident_type": normalized["incident_type"],
                    "affected_service": normalized["affected_service"],
                }
                result = self._git_result(normalized, arguments)
                self._record_tool_call(incident_id, identity, arguments, result, 1)
                sequence.append(identity)
                events.append({"message": "Runbook checked"})
            elif identity == INTERNAL_SERVICE_IDENTITY:
                arguments = {
                    "incident_type": normalized["incident_type"],
                    "affected_service": normalized["affected_service"],
                }
                result = _service_inventory_result(normalized, arguments)
                self._record_tool_call(incident_id, identity, arguments, result, 1)
                sequence.append(identity)
                events.append({"message": "Service record checked"})
            elif identity == INTERNAL_POLICY_IDENTITY:
                arguments = {
                    "incident_type": normalized["incident_type"],
                    "affected_service": normalized["affected_service"],
                }
                result = _policy_reference_result(normalized, arguments)
                self._record_tool_call(incident_id, identity, arguments, result, 1)
                sequence.append(identity)
                events.append({"message": "Deployment policy checked"})
            elif identity == INTERNAL_TELEMETRY_IDENTITY:
                arguments = {
                    "affected_service": normalized["affected_service"],
                    "signals": list(normalized["signals"]),
                }
                result = _deployment_telemetry_result(normalized, arguments)
                self._record_tool_call(incident_id, identity, arguments, result, 1)
                sequence.append(identity)
                events.append({"message": "Rollout telemetry checked"})
            else:
                raise AgentWorkflowError("tool identity is not executable")

            events.append({"message": "Analysis complete"})
            self._update_incident(
                incident_id,
                status="completed",
                events=events,
                sequence=sequence,
                planner_selected_identity=planner_selected_identity,
            )
            return self._public(incident_id)
        except (AgentWorkflowError, RegistryCatalogError, MCPClientError, PlannerError):
            events.append({"message": "Analysis unavailable"})
            self._update_incident(
                incident_id,
                status="failed",
                events=events,
                sequence=sequence,
                planner_selected_identity=planner_selected_identity,
            )
            return self._public(incident_id)


def _unauthorized() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})


def _a2a_error(status_code: int, status: str, message: str, reason: str) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "code": status_code,
                "status": status,
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


def requested_a2a_version(request: Request) -> str:
    header = request.headers.get("A2A-Version")
    query = request.query_params.get("A2A-Version")
    if header is not None and query is not None and header != query:
        return ""
    return header if header is not None else query or ""


def _a2a_version_error(request: Request) -> Response | None:
    if requested_a2a_version(request) != "1.0":
        return _a2a_error(
            400,
            "FAILED_PRECONDITION",
            "The requested A2A protocol version is not supported",
            "VERSION_NOT_SUPPORTED",
        )
    return None


async def _read_a2a_json(request: Request) -> tuple[Any | None, Response | None]:
    if request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != A2A_JSON_MEDIA_TYPE:
        return None, _a2a_error(400, "INVALID_ARGUMENT", "Unsupported A2A content type", "CONTENT_TYPE_NOT_SUPPORTED")
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        return None, _a2a_error(400, "INVALID_ARGUMENT", "Invalid A2A request", "INVALID_ARGUMENT")
    try:
        return json.loads(raw), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, _a2a_error(400, "INVALID_ARGUMENT", "Invalid A2A request", "INVALID_ARGUMENT")


def _history_length(request: Request) -> int | None:
    value = request.query_params.get("historyLength")
    if value is None:
        return None
    if not value.isdecimal() or int(value) > MAX_TASK_HISTORY:
        raise ValueError("invalid history length")
    return int(value)


async def _read_json(request: Request) -> tuple[Any | None, Response | None]:
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        return None, JSONResponse({"error": "request rejected"}, status_code=413)
    try:
        return json.loads(raw), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)


def create_app(
    settings: Settings,
    *,
    planner: Planner | None = None,
    registry_client: RegistryCatalogClient | None = None,
    mcp_client: HttpMCPClient | None = None,
    coordinator_client: CoordinatorClient | None = None,
) -> FastAPI:
    service = AgentService(
        settings,
        planner=planner,
        registry_client=registry_client,
        mcp_client=mcp_client,
        coordinator_client=coordinator_client,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            if settings.environment in {"competition", "h7"} and isinstance(service.planner, OllamaPlanner):
                await service.planner.verify_model()
            yield
        finally:
            await service.close()

    app = FastAPI(title="ARGUS Agents", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.agents_service = service

    def authorized(request: Request) -> bool:
        try:
            secret = settings.credential("portal_agents")
        except KeyError:
            return False
        from .mcp_protocol import authenticated_edge

        return authenticated_edge(request.headers, {"portal_agents": secret}) == "portal_agents"

    @app.get("/healthz")
    async def healthz() -> Mapping[str, str]:
        return {"role": "agents", "status": "ok"}

    async def submit(request: Request, integration_id: str | None = None) -> Response:
        if not authorized(request):
            return _unauthorized()
        body, error = await _read_json(request)
        if error is not None:
            return error
        try:
            incident = _validate_incident(body, integration_id)
            return JSONResponse(await service.run_incident(incident), status_code=201)
        except ValueError:
            return JSONResponse({"error": "invalid request"}, status_code=400)

    @app.post("/api/incidents")
    async def create_incident(request: Request) -> Response:
        return await submit(request)

    @app.post("/api/incidents/{integration_id}")
    async def create_incident_for_integration(integration_id: str, request: Request) -> Response:
        if not _IDENTIFIER.fullmatch(integration_id):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return await submit(request, integration_id)

    @app.get("/api/incidents/{incident_id}")
    async def read_incident(incident_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        if not _IDENTIFIER.fullmatch(incident_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            return JSONResponse(service._public(incident_id))
        except KeyError:
            return JSONResponse({"error": "not found"}, status_code=404)

    @app.get("/internal/incidents/{incident_id}/selection")
    async def read_selection_diagnostics(incident_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        if not _IDENTIFIER.fullmatch(incident_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            return JSONResponse(service._selection_diagnostics(incident_id))
        except KeyError:
            return JSONResponse({"error": "not found"}, status_code=404)

    @app.get("/.well-known/agent-card.json")
    async def agent_card(request: Request) -> Response:
        return JSONResponse(
            {
                "name": "ARGUS Deployment Review Agent",
                "description": "Processes deployment review recommendations from configured integrations.",
                "supportedInterfaces": [{
                    "url": settings.a2a_interface_url,
                    "protocolBinding": "HTTP+JSON",
                    "protocolVersion": "1.0",
                }],
                "version": "1.0.0",
                "capabilities": {},
                "securitySchemes": {"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
                "securityRequirements": [{"schemes": {"bearerAuth": {"list": []}}}],
                "defaultInputModes": ["application/json"],
                "defaultOutputModes": ["application/json"],
                "skills": [{
                    "id": "deployment-control-review",
                    "name": "Deployment Control Review",
                    "description": "Accepts structured deployment-control recommendations.",
                    "tags": ["deployment", "security-review"],
                    "inputModes": ["application/json"],
                    "outputModes": ["application/json"],
                }],
            },
            media_type="application/json",
        )

    @app.post("/message:send")
    async def create_task(request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        version_error = _a2a_version_error(request)
        if version_error is not None:
            return version_error
        body, error = await _read_a2a_json(request)
        if error is not None:
            return error
        try:
            return JSONResponse({"task": await service.create_a2a_task(body)}, media_type=A2A_JSON_MEDIA_TYPE)
        except A2AValidationError:
            return _a2a_error(400, "INVALID_ARGUMENT", "Invalid A2A request", "INVALID_ARGUMENT")

    @app.get("/tasks/{task_id}")
    async def read_task(task_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        version_error = _a2a_version_error(request)
        if version_error is not None:
            return version_error
        try:
            validate_task_id(task_id)
            return JSONResponse(service._task_public(task_id, _history_length(request)), media_type=A2A_JSON_MEDIA_TYPE)
        except ValueError:
            return _a2a_error(400, "INVALID_ARGUMENT", "Invalid A2A request", "INVALID_ARGUMENT")
        except (A2AValidationError, KeyError):
            return _a2a_error(404, "NOT_FOUND", "Task not found", "TASK_NOT_FOUND")

    return app
