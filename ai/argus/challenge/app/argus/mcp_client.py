"""HTTP client for the fixed internal Registry-to-MCP edge."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from .config import MAX_ARTIFACT_BYTES, MAX_TOOL_RESULT_BYTES, MCP_PROTOCOL_VERSION
from .mcp_protocol import (
    COMMUNITY_INPUT_SCHEMA,
    COMMUNITY_TOOL_NAME,
    DEFAULT_SERVICE_SUMMARY,
    SECURITY_TOOL_NAME,
    ValidatedToolsList,
    validate_tools_list_response,
)
from .store import canonical_json


class MCPClientError(RuntimeError):
    """A safe, transport-level MCP failure."""


class CoordinatorClientError(RuntimeError):
    """A safe, transport-level Coordinator failure."""


class SecurityClientError(RuntimeError):
    """A safe, transport-level Coordinator-to-Security failure."""


class MCPClient(Protocol):
    async def provision(self, instance_id: str, integration_id: str) -> None:
        ...

    async def update_runtime_metadata(
        self, instance_id: str, integration_id: str, service_summary: str
    ) -> None:
        ...

    async def list_tools(self, instance_id: str, integration_id: str) -> ValidatedToolsList:
        ...

    async def call_tool(
        self,
        instance_id: str,
        integration_id: str,
        incident_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        ...


class CoordinatorClient(Protocol):
    async def advance_task(self, instance_id: str, task_id: str) -> Mapping[str, Any]:
        ...


class SecurityClient(Protocol):
    async def request_approval(
        self, instance_id: str, normalized: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        ...


class HttpMCPClient:
    """Use only the configured internal MCP base URL and edge credential."""

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        client: httpx.AsyncClient | None = None,
    ):
        self._client = client or httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=5.0)
        self._owns_client = client is None
        self._credential = credential

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _headers(self, instance_id: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._credential}",
            "X-Argus-Instance": instance_id,
        }

    async def _admin_request(
        self, method: str, path: str, instance_id: str, payload: Mapping[str, Any]
    ) -> None:
        try:
            response = await self._client.request(
                method, path, headers=self._headers(instance_id), json=dict(payload)
            )
        except httpx.HTTPError as exc:
            raise MCPClientError("MCP service unavailable") from exc
        if response.status_code >= 400:
            raise MCPClientError("MCP request rejected")

    async def provision(self, instance_id: str, integration_id: str) -> None:
        await self._admin_request(
            "PUT",
            f"/internal/community/{integration_id}",
            instance_id,
            {"service_summary": DEFAULT_SERVICE_SUMMARY},
        )

    async def update_runtime_metadata(
        self, instance_id: str, integration_id: str, service_summary: str
    ) -> None:
        await self._admin_request(
            "PATCH",
            f"/internal/community/{integration_id}/runtime-metadata",
            instance_id,
            {"service_summary": service_summary},
        )

    async def list_tools(self, instance_id: str, integration_id: str) -> ValidatedToolsList:
        request_id = 1
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "argus-registry",
                        "version": "0.1.0",
                    },
                }
            },
        }
        headers = self._headers(instance_id)
        headers.update(
            {
                "Content-Type": "application/json",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
            }
        )
        try:
            response = await self._client.post(
                f"/mcp/community/{integration_id}", headers=headers, json=body
            )
            payload = response.json()
            if response.status_code >= 400:
                raise MCPClientError("MCP request rejected")
            return validate_tools_list_response(
                payload,
                request_id=request_id,
                expected_name=COMMUNITY_TOOL_NAME,
                expected_schema=COMMUNITY_INPUT_SCHEMA,
            )
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if isinstance(exc, MCPClientError):
                raise
            raise MCPClientError("MCP response rejected") from exc

    async def call_tool(
        self,
        instance_id: str,
        integration_id: str,
        incident_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        request_id = 1
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "argus-agents",
                        "version": "0.1.0",
                    },
                },
                "name": tool_name,
                "arguments": dict(arguments),
            },
        }
        headers = self._headers(instance_id)
        headers.update(
            {
                "Content-Type": "application/json",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool_name,
                "X-Argus-Incident": incident_id,
            }
        )
        try:
            response = await self._client.post(
                f"/mcp/community/{integration_id}", headers=headers, json=body
            )
            if len(response.content) > MAX_TOOL_RESULT_BYTES:
                raise MCPClientError("MCP response rejected")
            payload = response.json()
            if response.status_code >= 400:
                raise MCPClientError("MCP request rejected")
            if (
                not isinstance(payload, Mapping)
                or payload.get("jsonrpc") != "2.0"
                or payload.get("id") != request_id
                or not isinstance(payload.get("result"), Mapping)
            ):
                raise MCPClientError("MCP response rejected")
            result = dict(payload["result"])
            if len(canonical_json(result).encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
                raise MCPClientError("MCP response rejected")
            return result
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise MCPClientError("MCP response rejected") from exc


class HttpCoordinatorClient:
    """Use only the configured Agents-to-Coordinator edge."""

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        client: httpx.AsyncClient | None = None,
    ):
        self._client = client or httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=5.0)
        self._owns_client = client is None
        self._credential = credential

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def advance_task(self, instance_id: str, task_id: str) -> Mapping[str, Any]:
        try:
            response = await self._client.post(
                f"/internal/coordinator/tasks/{task_id}",
                headers={
                    "Authorization": f"Bearer {self._credential}",
                    "X-Argus-Instance": instance_id,
                },
                json={},
            )
            if response.status_code >= 400 or len(response.content) > MAX_ARTIFACT_BYTES:
                raise CoordinatorClientError("Coordinator request rejected")
            payload = response.json()
            if not isinstance(payload, Mapping):
                raise CoordinatorClientError("Coordinator response rejected")
            return dict(payload)
        except CoordinatorClientError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise CoordinatorClientError("Coordinator response rejected") from exc


class HttpSecurityClient:
    """Invoke only the fixed MCP Security tool over the Coordinator edge."""

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        client: httpx.AsyncClient | None = None,
    ):
        self._client = client or httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=5.0)
        self._owns_client = client is None
        self._credential = credential

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def request_approval(
        self, instance_id: str, normalized: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        request_id = 1
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "argus-coordinator",
                        "version": "0.1.0",
                    },
                },
                "name": SECURITY_TOOL_NAME,
                "arguments": dict(normalized),
            },
        }
        headers = {
            "Authorization": f"Bearer {self._credential}",
            "X-Argus-Instance": instance_id,
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": SECURITY_TOOL_NAME,
        }
        try:
            response = await self._client.post("/mcp/security", headers=headers, json=body)
            if response.status_code >= 400 or len(response.content) > MAX_TOOL_RESULT_BYTES:
                raise SecurityClientError("Security request rejected")
            payload = response.json()
            result = payload.get("result") if isinstance(payload, Mapping) else None
            if (
                not isinstance(payload, Mapping)
                or payload.get("jsonrpc") != "2.0"
                or payload.get("id") != request_id
                or not isinstance(result, Mapping)
                or set(result) != {"approval"}
                or not isinstance(result["approval"], Mapping)
            ):
                raise SecurityClientError("Security response rejected")
            approval = dict(result["approval"])
            if len(canonical_json(approval).encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
                raise SecurityClientError("Security response rejected")
            return approval
        except SecurityClientError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise SecurityClientError("Security response rejected") from exc
