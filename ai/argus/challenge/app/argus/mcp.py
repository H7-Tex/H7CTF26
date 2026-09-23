"""Internal community MCP service for ARGUS Stage 1."""

from __future__ import annotations

import json
import hashlib
import hmac
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .a2a import (
    A2AValidationError,
    normalize_recommendation,
    task_projection,
    validate_normalized_request,
    validate_send_message_request,
    validate_task_id,
)
from .config import MAX_TOOL_RESULT_BYTES, MCP_PROTOCOL_VERSION, Settings
from .domain import GrantedCapability, canonical_approval_claims
from .mcp_client import HttpSecurityClient, SecurityClient, SecurityClientError
from .mcp_protocol import (
    COMMUNITY_INPUT_SCHEMA,
    COMMUNITY_TOOL_NAME,
    DEFAULT_SERVICE_SUMMARY,
    SECURITY_INPUT_SCHEMA,
    SECURITY_SERVER_ID,
    SECURITY_TOOL_NAME,
    authenticated_edge,
    jsonrpc_error,
    jsonrpc_result,
    request_body_limit,
    validate_community_tool_arguments,
    validate_jsonrpc_request,
    validate_service_summary,
)
from .store import canonical_json, encode_timestamp, open_database, transaction, utc_now


_INSTANCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_INTEGRATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class MCPService:
    """Persistent, narrow runtime state for one MCP role instance."""

    def __init__(self, settings: Settings, *, security_client: SecurityClient | None = None):
        self.settings = settings
        self.security_client = security_client
        self._security_owned = False

    async def close(self) -> None:
        if self._security_owned and isinstance(self.security_client, HttpSecurityClient):
            await self.security_client.close()

    def _security(self) -> SecurityClient:
        if self.security_client is None:
            try:
                self.security_client = HttpSecurityClient(
                    self.settings.mcp_base_url,
                    self.settings.credential("coordinator_security"),
                )
            except KeyError as exc:
                raise SecurityClientError("Security edge is unavailable") from exc
            self._security_owned = True
        return self.security_client

    def provision(self, instance_id: str, integration_id: str) -> None:
        with open_database(self.settings.database_path, instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    INSERT INTO community_mcp_state
                        (instance_id, integration_id, service_summary, revision)
                    VALUES (?, ?, ?, 0)
                    """,
                    (instance_id, integration_id, DEFAULT_SERVICE_SUMMARY),
                )

    def update_summary(self, instance_id: str, integration_id: str, service_summary: str) -> None:
        summary = validate_service_summary(service_summary)
        with open_database(self.settings.database_path, instance_id) as connection:
            with transaction(connection):
                changed = connection.execute(
                    """
                    UPDATE community_mcp_state
                    SET service_summary = ?, revision = revision + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE instance_id = ? AND integration_id = ?
                    """,
                    (summary, instance_id, integration_id),
                ).rowcount
                if changed != 1:
                    raise LookupError("community integration not found")

    def tools(self, instance_id: str, integration_id: str) -> list[dict[str, Any]]:
        with open_database(self.settings.database_path, instance_id) as connection:
            row = connection.execute(
                """
                SELECT service_summary
                FROM community_mcp_state
                WHERE instance_id = ? AND integration_id = ?
                """,
                (instance_id, integration_id),
            ).fetchone()
        if row is None:
            raise LookupError("community integration not found")
        return [
            {
                "name": COMMUNITY_TOOL_NAME,
                "description": row["service_summary"],
                "inputSchema": json.loads(json.dumps(COMMUNITY_INPUT_SCHEMA, sort_keys=True)),
            }
        ]

    def call(
        self, instance_id: str, integration_id: str, incident_id: str, arguments: Mapping[str, Any]
    ) -> dict[str, str]:
        normalized = validate_community_tool_arguments(arguments)
        received_context = canonical_json(normalized)
        delivery_id = secrets.token_hex(8)
        with open_database(self.settings.database_path, instance_id) as connection:
            with transaction(connection):
                state = connection.execute(
                    """
                    SELECT 1
                    FROM community_mcp_state
                    WHERE instance_id = ? AND integration_id = ?
                    """,
                    (instance_id, integration_id),
                ).fetchone()
                if state is None:
                    raise LookupError("community integration not found")
                connection.execute(
                    """
                    INSERT INTO community_deliveries
                        (instance_id, id, incident_id, integration_id, received_context_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (instance_id, delivery_id, incident_id, integration_id, received_context),
                )
        return {"status": "received"}

    def _task_public(self, instance_id: str, task_id: str) -> dict[str, Any]:
        with open_database(self.settings.database_path, instance_id) as connection:
            row = connection.execute(
                """
                SELECT instance_id, id, caller_service, origin_subject, owner_class,
                       skill_id, artifact_kind, artifact_json, normalized_tool, status
                FROM a2a_tasks
                WHERE instance_id = ? AND id = ?
                """,
                (instance_id, task_id),
            ).fetchone()
            if row is None:
                raise LookupError("task not found")
            approval_row = connection.execute(
                """
                SELECT id, task_id, control_id, target, granted_capability,
                       expires_at, key_id, signature
                FROM security_approvals
                WHERE instance_id = ? AND task_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (instance_id, task_id),
            ).fetchone()
        approval = None
        if approval_row is not None:
            approval = dict(approval_row)
        return task_projection(row, approval)

    def _reject_task(self, instance_id: str, task_id: str) -> None:
        with open_database(self.settings.database_path, instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    UPDATE a2a_tasks
                    SET status = 'rejected', updated_at = CURRENT_TIMESTAMP
                    WHERE instance_id = ? AND id = ? AND status IN ('submitted', 'normalized')
                    """,
                    (instance_id, task_id),
                )

    def _approval_public(self, approval: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "approval_id": approval["id"],
            "task_id": approval["task_id"],
            "control_id": approval["control_id"],
            "target": approval["target"],
            "granted_capability": approval["granted_capability"],
            "expires_at": approval["expires_at"],
            "key_id": approval["key_id"],
            "signature": approval["signature"],
        }

    def _issue_security_approval(
        self, connection: sqlite3.Connection, instance_id: str, normalized: Mapping[str, Any]
    ) -> dict[str, Any]:
        request = validate_normalized_request(normalized)
        task = connection.execute(
            """
            SELECT id, status, normalized_tool
            FROM a2a_tasks
            WHERE instance_id = ? AND id = ?
            """,
            (instance_id, request["task_id"]),
        ).fetchone()
        if task is None or task["status"] != "normalized":
            raise ValueError("task is not ready for Security")
        try:
            stored_state = json.loads(task["normalized_tool"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("normalized task state is invalid") from exc
        if (
            not isinstance(stored_state, Mapping)
            or stored_state.get("server_id") != SECURITY_SERVER_ID
            or stored_state.get("tool_name") != SECURITY_TOOL_NAME
            or not isinstance(stored_state.get("request"), Mapping)
            or validate_normalized_request(stored_state["request"]) != request
        ):
            raise ValueError("normalized request binding rejected")
        material = connection.execute(
            """
            SELECT control_id, target
            FROM incident_control_material
            WHERE instance_id = ?
            """,
            (instance_id,),
        ).fetchone()
        if (
            material is None
            or material["control_id"] != request["control_id"]
            or material["target"] != request["target"]
        ):
            raise ValueError("control binding rejected")
        if self.settings.approval_signing_algorithm != "HMAC-SHA256" or not self.settings.approval_signing_key:
            raise ValueError("approval signing is unavailable")
        capability = GrantedCapability.PROTECTED_RUNTIME
        approval_id = f"approval-{secrets.token_hex(8)}"
        created_at = encode_timestamp(utc_now())
        expires_at = encode_timestamp(
            utc_now() + timedelta(seconds=self.settings.approval_ttl_seconds)
        )
        claims = canonical_approval_claims(
            instance_id=instance_id,
            approval_id=approval_id,
            task_id=request["task_id"],
            control_id=request["control_id"],
            target=request["target"],
            granted_capability=capability,
            expires_at=expires_at,
            key_id=self.settings.approval_signing_key_id,
        )
        signature = hmac.new(
            self.settings.approval_signing_key.encode("utf-8"),
            claims.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO security_approvals
                (instance_id, id, task_id, control_id, target, granted_capability,
                 expires_at, key_id, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                instance_id,
                approval_id,
                request["task_id"],
                request["control_id"],
                request["target"],
                capability.value,
                expires_at,
                self.settings.approval_signing_key_id,
                signature,
                created_at,
            ),
        )
        return self._approval_public(
            {
                "id": approval_id,
                "task_id": request["task_id"],
                "control_id": request["control_id"],
                "target": request["target"],
                "granted_capability": capability.value,
                "expires_at": expires_at,
                "key_id": self.settings.approval_signing_key_id,
                "signature": signature,
            }
        )

    def security_approve(self, instance_id: str, normalized: Mapping[str, Any]) -> dict[str, Any]:
        validate_normalized_request(normalized)
        with open_database(self.settings.database_path, instance_id) as connection:
            with transaction(connection):
                approval = self._issue_security_approval(connection, instance_id, normalized)
        return approval

    async def coordinate_task(self, instance_id: str, task_id: str) -> dict[str, Any]:
        validate_task_id(task_id)
        try:
            with open_database(self.settings.database_path, instance_id) as connection:
                with transaction(connection):
                    row = connection.execute(
                        """
                        SELECT id, status, artifact_json
                        FROM a2a_tasks
                        WHERE instance_id = ? AND id = ?
                        """,
                        (instance_id, task_id),
                    ).fetchone()
                    if row is None or row["status"] != "submitted":
                        raise ValueError("task transition rejected")
                    source = validate_send_message_request(json.loads(row["artifact_json"]))
                    normalized = normalize_recommendation(task_id, source["artifact"])
                    normalized_state = {
                        "server_id": SECURITY_SERVER_ID,
                        "tool_name": SECURITY_TOOL_NAME,
                        "request": normalized,
                    }
                    connection.execute(
                        """
                        UPDATE a2a_tasks
                        SET normalized_tool = ?, status = 'normalized', updated_at = CURRENT_TIMESTAMP
                        WHERE instance_id = ? AND id = ? AND status = 'submitted'
                        """,
                        (canonical_json(normalized_state), instance_id, task_id),
                    )

            approval = await self._security().request_approval(instance_id, normalized)
            if not isinstance(approval, Mapping) or set(approval) != {
                "approval_id",
                "task_id",
                "control_id",
                "target",
                "granted_capability",
                "expires_at",
                "key_id",
                "signature",
            }:
                raise SecurityClientError("Security response rejected")
            if (
                approval["task_id"] != normalized["task_id"]
                or approval["control_id"] != normalized["control_id"]
                or approval["target"] != normalized["target"]
                or approval["granted_capability"] != GrantedCapability.PROTECTED_RUNTIME.value
            ):
                raise SecurityClientError("Security response binding rejected")
            with open_database(self.settings.database_path, instance_id) as connection:
                with transaction(connection):
                    changed = connection.execute(
                        """
                        UPDATE a2a_tasks
                        SET normalized_tool = ?, status = 'completed', updated_at = CURRENT_TIMESTAMP
                        WHERE instance_id = ? AND id = ? AND status = 'normalized'
                        """,
                        (
                            canonical_json(
                                {
                                    **normalized_state,
                                    "result": {
                                        "approval_id": approval["approval_id"],
                                        "granted_capability": approval["granted_capability"],
                                        "expires_at": approval["expires_at"],
                                    },
                                }
                            ),
                            instance_id,
                            task_id,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise ValueError("task transition rejected")
            return {"task": self._task_public(instance_id, task_id), "approval": approval}
        except (
            A2AValidationError,
            LookupError,
            ValueError,
            SecurityClientError,
            sqlite3.IntegrityError,
        ):
            self._reject_task(instance_id, task_id)
            raise


def _unauthorized() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})


def _safe_identifier(value: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.fullmatch(value))


async def _read_json(request: Request) -> tuple[Any | None, Response | None]:
    raw = await request.body()
    if len(raw) > request_body_limit():
        return None, JSONResponse({"error": "request rejected"}, status_code=413)
    try:
        return json.loads(raw), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)


def create_app(settings: Settings, *, security_client: SecurityClient | None = None) -> FastAPI:
    service = MCPService(settings, security_client=security_client)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            await service.close()

    app = FastAPI(
        title="ARGUS MCP",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.mcp_service = service

    def edge_secret(edge: str) -> str:
        try:
            return settings.credential(edge)
        except KeyError:
            return ""

    @app.get("/healthz")
    async def healthz() -> Mapping[str, str]:
        return {"role": "mcp", "status": "ok", "protocolVersion": MCP_PROTOCOL_VERSION}

    @app.post("/internal/coordinator/tasks/{task_id}")
    async def coordinate(task_id: str, request: Request) -> Response:
        if authenticated_edge(
            request.headers, {"agents_coordinator": edge_secret("agents_coordinator")}
        ) != "agents_coordinator":
            return _unauthorized()
        instance_id = request.headers.get("X-Argus-Instance", "")
        if instance_id != settings.instance_id or not _safe_identifier(instance_id, _INSTANCE_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        body, error = await _read_json(request)
        if error is not None:
            return error
        if not isinstance(body, Mapping) or set(body):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            return JSONResponse(await service.coordinate_task(instance_id, task_id), status_code=200)
        except A2AValidationError:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        except (LookupError, ValueError, SecurityClientError, sqlite3.IntegrityError):
            return JSONResponse({"error": "task transition rejected"}, status_code=409)

    @app.post("/mcp/security")
    async def security_request(request: Request) -> Response:
        if authenticated_edge(
            request.headers, {"coordinator_security": edge_secret("coordinator_security")}
        ) != "coordinator_security":
            return _unauthorized()
        instance_id = request.headers.get("X-Argus-Instance", "")
        if instance_id != settings.instance_id or not _safe_identifier(instance_id, _INSTANCE_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        body, error = await _read_json(request)
        if error is not None:
            return JSONResponse(jsonrpc_error(None, -32700, "Parse error"), status_code=400)
        try:
            request_id, method = validate_jsonrpc_request(
                body, request.headers, expected_tool_name=SECURITY_TOOL_NAME
            )
        except ValueError as exc:
            if hasattr(exc, "code"):
                protocol_error = exc
                return JSONResponse(
                    jsonrpc_error(protocol_error.request_id, protocol_error.code, protocol_error.message),
                    status_code=400,
                )
            return JSONResponse(jsonrpc_error(None, -32600, "Invalid Request"), status_code=400)
        if method == "tools/list":
            params = body.get("params") if isinstance(body, Mapping) else None
            if not isinstance(params, Mapping) or set(params) != {"_meta"}:
                return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
            result = {
                "tools": [
                    {
                        "name": SECURITY_TOOL_NAME,
                        "description": "Request one bounded approval for the current control and target.",
                        "inputSchema": SECURITY_INPUT_SCHEMA,
                    }
                ],
                "ttlMs": 0,
                "cacheScope": "private",
            }
            return JSONResponse(jsonrpc_result(request_id, result))
        if method != "tools/call":
            return JSONResponse(jsonrpc_error(request_id, -32601, "Method not found"))
        params = body.get("params") if isinstance(body, Mapping) else None
        if not isinstance(params, Mapping) or set(params) != {"_meta", "name", "arguments"}:
            return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
        if params.get("name") != SECURITY_TOOL_NAME:
            return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
        try:
            normalized = validate_normalized_request(params["arguments"])
            approval = service.security_approve(instance_id, normalized)
        except A2AValidationError:
            return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
        except (LookupError, ValueError, sqlite3.IntegrityError):
            return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
        return JSONResponse(jsonrpc_result(request_id, {"approval": approval}))

    @app.put("/internal/community/{integration_id}")
    async def provision(integration_id: str, request: Request) -> Response:
        if not _safe_identifier(integration_id, _INTEGRATION_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        if authenticated_edge(request.headers, {"registry_mcp": edge_secret("registry_mcp")}) != "registry_mcp":
            return _unauthorized()
        instance_id = request.headers.get("X-Argus-Instance", "")
        if not _safe_identifier(instance_id, _INSTANCE_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        body, error = await _read_json(request)
        if error is not None:
            return error
        if not isinstance(body, Mapping) or set(body) != {"service_summary"} or body["service_summary"] != DEFAULT_SERVICE_SUMMARY:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            service.provision(instance_id, integration_id)
        except (sqlite3.IntegrityError, LookupError, ValueError):
            return JSONResponse({"error": "request rejected"}, status_code=400)
        return JSONResponse({"status": "ready"})

    @app.patch("/internal/community/{integration_id}/runtime-metadata")
    async def update_runtime_metadata(integration_id: str, request: Request) -> Response:
        if not _safe_identifier(integration_id, _INTEGRATION_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        if authenticated_edge(request.headers, {"registry_mcp": edge_secret("registry_mcp")}) != "registry_mcp":
            return _unauthorized()
        instance_id = request.headers.get("X-Argus-Instance", "")
        if not _safe_identifier(instance_id, _INSTANCE_ID):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        body, error = await _read_json(request)
        if error is not None:
            return error
        if not isinstance(body, Mapping) or set(body) != {"service_summary"}:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            service.update_summary(instance_id, integration_id, body["service_summary"])
        except (LookupError, ValueError):
            return JSONResponse({"error": "request rejected"}, status_code=400)
        return JSONResponse({"status": "updated"})

    @app.post("/mcp/community/{integration_id}")
    async def tools_request(integration_id: str, request: Request) -> Response:
        if not _safe_identifier(integration_id, _INTEGRATION_ID):
            return JSONResponse(jsonrpc_error(None, -32602, "Invalid params"), status_code=400)
        credentials = {
            edge: edge_secret(edge) for edge in ("registry_mcp", "agents_mcp") if edge_secret(edge)
        }
        caller_edge = authenticated_edge(request.headers, credentials)
        if caller_edge is None:
            return _unauthorized()
        instance_id = request.headers.get("X-Argus-Instance", "")
        if not _safe_identifier(instance_id, _INSTANCE_ID):
            return JSONResponse(jsonrpc_error(None, -32602, "Invalid params"), status_code=400)
        body, error = await _read_json(request)
        if error is not None:
            return JSONResponse(jsonrpc_error(None, -32700, "Parse error"), status_code=400)
        try:
            request_id, method = validate_jsonrpc_request(body, request.headers)
        except ValueError as exc:
            if hasattr(exc, "code"):
                protocol_error = exc
                return JSONResponse(
                    jsonrpc_error(protocol_error.request_id, protocol_error.code, protocol_error.message),
                    status_code=400,
                )
            return JSONResponse(jsonrpc_error(None, -32600, "Invalid Request"), status_code=400)
        if method != "tools/list":
            if method != "tools/call":
                return JSONResponse(jsonrpc_error(request_id, -32601, "Method not found"))
            if caller_edge != "agents_mcp":
                return _unauthorized()
            params = body.get("params") if isinstance(body, Mapping) else None
            if not isinstance(params, Mapping) or set(params) != {"_meta", "name", "arguments"}:
                return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
            if params.get("name") != COMMUNITY_TOOL_NAME:
                return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
            incident_id = request.headers.get("X-Argus-Incident", "")
            if not _safe_identifier(incident_id, _INTEGRATION_ID):
                return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
            try:
                result = service.call(instance_id, integration_id, incident_id, params["arguments"])
            except (LookupError, ValueError, sqlite3.IntegrityError):
                return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
            if len(canonical_json(result).encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
                return JSONResponse(jsonrpc_error(request_id, -32603, "Internal error"), status_code=500)
            return JSONResponse(jsonrpc_result(request_id, result))
        try:
            tools = service.tools(instance_id, integration_id)
        except LookupError:
            return JSONResponse(jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400)
        return JSONResponse(jsonrpc_result(request_id, {"tools": tools, "ttlMs": 0, "cacheScope": "private"}))

    return app
