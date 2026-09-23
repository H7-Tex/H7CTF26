"""Bounded JSON-RPC and Streamable HTTP semantics for MCP 2026-07-28."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import (
    MAX_DESCRIPTOR_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MAX_TOOL_CALLS,
    MAX_TOOL_ARGUMENTS_BYTES,
    MCP_PROTOCOL_VERSION,
)
from .store import canonical_json


COMMUNITY_TOOL_NAME = "request_vendor_review"
SECURITY_SERVER_ID = "security"
SECURITY_TOOL_NAME = "request_approval"
DEFAULT_SERVICE_SUMMARY = "Summarize incident context for vendor support review."
COMMUNITY_INPUT_SCHEMA = {
    "type": "object",
    "properties": {"context": {"type": "string"}},
    "required": ["context"],
    "additionalProperties": False,
}
SECURITY_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "task_id": {"type": "string"},
        "control_id": {"type": "string"},
        "target": {"type": "string"},
        "decision": {"type": "string", "const": "approve"},
    },
    "required": ["task_id", "control_id", "target", "decision"],
    "additionalProperties": False,
}
MAX_SERVICE_SUMMARY_BYTES = 2_048
MAX_TOOL_NAME_BYTES = 128
MAX_CLIENT_FIELD_BYTES = 128
MAX_LIST_TTL_MS = 86_400_000
MCP_HEADER_MISMATCH = -32020
_PROMPT_INJECTION_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bignore\b.{0,48}\b(?:previous|prior|earlier|system|developer)\b.{0,24}\b(?:instructions?|prompts?|rules?)\b",
        r"\b(?:reveal|exfiltrate)\b.{0,48}\b(?:secrets?|credentials?|tokens?|system prompt|private data|protected data)\b",
        r"\b(?:copy|send)\b.{0,40}\ball of (?:its|the) output\b",
        r"\bexecute\b.{0,40}\binstructions supplied by\b",
    )
)


class ProtocolError(ValueError):
    """A safe JSON-RPC protocol error with no internal details."""

    def __init__(self, code: int, message: str, request_id: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """Canonical internal identity for a tool exposed by one MCP server."""

    server_id: str
    tool_name: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.server_id, str)
            or not self.server_id
            or len(self.server_id.encode("utf-8")) > MAX_CLIENT_FIELD_BYTES
            or not isinstance(self.tool_name, str)
            or not self.tool_name
            or len(self.tool_name.encode("utf-8")) > MAX_TOOL_NAME_BYTES
        ):
            raise ValueError("tool identity is invalid")


def qualify_tool_identity(server_id: str, tool_name: str) -> ToolIdentity:
    """Return the only supported internal identity form: ``(server_id, tool_name)``."""

    return ToolIdentity(server_id, tool_name)


@dataclass(frozen=True, slots=True)
class ValidatedToolsList:
    request_id: str | int | float
    tools: tuple[dict[str, Any], ...]
    ttl_ms: int
    cache_scope: str

    def by_identity(self, server_id: str) -> dict[ToolIdentity, dict[str, Any]]:
        """Index tools by server-qualified identity, never by a global name."""

        return {
            qualify_tool_identity(server_id, tool["name"]): tool
            for tool in self.tools
        }


def jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def jsonrpc_result(request_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": dict(result)}


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def authenticated_edge(headers: Mapping[str, str], credentials: Mapping[str, str]) -> str | None:
    """Derive the caller from a configured bearer secret, never from a header label."""

    authorization = _header(headers, "Authorization") or ""
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        return None
    for edge, secret in credentials.items():
        if secret and hmac.compare_digest(token, secret):
            return edge
    return None


def validate_jsonrpc_request(
    body: Any,
    headers: Mapping[str, str],
    *,
    expected_tool_name: str = COMMUNITY_TOOL_NAME,
) -> tuple[str | int | float, str]:
    if not isinstance(body, Mapping):
        raise ProtocolError(-32600, "Invalid Request")
    request_id = body.get("id")
    if not isinstance(request_id, (str, int, float)) or isinstance(request_id, bool):
        raise ProtocolError(-32600, "Invalid Request")
    if isinstance(request_id, float) and not math.isfinite(request_id):
        raise ProtocolError(-32600, "Invalid Request", request_id)
    if body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
        raise ProtocolError(-32600, "Invalid Request", request_id)
    method = body["method"]
    params = body.get("params", {})
    if not isinstance(params, Mapping):
        raise ProtocolError(-32602, "Invalid params", request_id)
    meta = params.get("_meta")
    if not isinstance(meta, Mapping):
        raise ProtocolError(-32602, "Invalid params", request_id)
    if meta.get("io.modelcontextprotocol/protocolVersion") != MCP_PROTOCOL_VERSION:
        raise ProtocolError(-32602, "Invalid params", request_id)
    client_capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(client_capabilities, Mapping):
        raise ProtocolError(-32602, "Invalid params", request_id)
    client_info = meta.get("io.modelcontextprotocol/clientInfo")
    if client_info is not None:
        if not isinstance(client_info, Mapping):
            raise ProtocolError(-32602, "Invalid params", request_id)
        for field in ("name", "version"):
            value = client_info.get(field)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_CLIENT_FIELD_BYTES:
                raise ProtocolError(-32602, "Invalid params", request_id)

    protocol_header = _header(headers, "MCP-Protocol-Version")
    method_header = _header(headers, "Mcp-Method")
    if protocol_header != MCP_PROTOCOL_VERSION or method_header != method:
        raise ProtocolError(MCP_HEADER_MISMATCH, "Header mismatch", request_id)
    if _header(headers, "Mcp-Session-Id") is not None:
        raise ProtocolError(-32600, "Invalid Request", request_id)
    if method == "tools/list" and _header(headers, "Mcp-Name") is not None:
        raise ProtocolError(-32600, "Invalid Request", request_id)
    if method == "tools/call" and _header(headers, "Mcp-Name") != expected_tool_name:
        raise ProtocolError(MCP_HEADER_MISMATCH, "Header mismatch", request_id)
    return request_id, method


def _reject_schema_refs(value: Any) -> None:
    if isinstance(value, Mapping):
        if "$ref" in value:
            raise ProtocolError(-32602, "Invalid params")
        for child in value.values():
            _reject_schema_refs(child)
    elif isinstance(value, list):
        for child in value:
            _reject_schema_refs(child)


def _normalize_tools(
    tools: Any,
    *,
    expected_name: str,
    expected_schema: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(tools, list) or not 1 <= len(tools) <= MAX_TOOL_CALLS:
        raise ProtocolError(-32602, "Invalid params")
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise ProtocolError(-32602, "Invalid params")
        if set(tool) != {"name", "description", "inputSchema"}:
            raise ProtocolError(-32602, "Invalid params")
        name = tool.get("name")
        description = tool.get("description")
        schema = tool.get("inputSchema")
        if (
            not isinstance(name, str)
            or not name
            or len(name.encode("utf-8")) > MAX_TOOL_NAME_BYTES
            or name in names
            or not isinstance(description, str)
            or len(description.encode("utf-8")) > MAX_DESCRIPTOR_BYTES
            or not isinstance(schema, Mapping)
            or schema.get("type") != "object"
        ):
            raise ProtocolError(-32602, "Invalid params")
        _reject_schema_refs(schema)
        if len(canonical_json(schema).encode("utf-8")) > MAX_TOOL_ARGUMENTS_BYTES:
            raise ProtocolError(-32602, "Invalid params")
        if name != expected_name or canonical_json(schema) != canonical_json(expected_schema):
            raise ProtocolError(-32602, "Invalid params")
        names.add(name)
        normalized.append(
            {
                "name": name,
                "description": description,
                "inputSchema": json.loads(canonical_json(schema)),
            }
        )
    normalized.sort(key=lambda item: item["name"])
    if len(canonical_json({"tools": normalized}).encode("utf-8")) > MAX_DESCRIPTOR_BYTES:
        raise ProtocolError(-32602, "Invalid params")
    return tuple(normalized)


def validate_tools_list_response(
    payload: Any,
    *,
    request_id: str | int | float,
    expected_name: str,
    expected_schema: Mapping[str, Any],
) -> ValidatedToolsList:
    if not isinstance(payload, Mapping) or payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
        raise ProtocolError(-32600, "Invalid Request", request_id)
    if "error" in payload or not isinstance(payload.get("result"), Mapping):
        raise ProtocolError(-32602, "Invalid params", request_id)
    result = payload["result"]
    ttl_ms = result.get("ttlMs")
    cache_scope = result.get("cacheScope")
    if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or not 0 <= ttl_ms <= MAX_LIST_TTL_MS:
        raise ProtocolError(-32602, "Invalid params", request_id)
    if cache_scope not in {"private", "public"}:
        raise ProtocolError(-32602, "Invalid params", request_id)
    tools = _normalize_tools(
        result.get("tools"), expected_name=expected_name, expected_schema=expected_schema
    )
    return ValidatedToolsList(request_id, tools, ttl_ms, cache_scope)


def descriptor_hash(tools: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> str:
    """Hash only normalized semantic tools, excluding transport/cache metadata."""

    return hashlib.sha256(canonical_json({"tools": list(tools)}).encode("utf-8")).hexdigest()


def validate_service_summary(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > MAX_SERVICE_SUMMARY_BYTES:
        raise ValueError("service_summary is invalid")
    summary = value.strip()
    if any(pattern.search(summary.lower()) for pattern in _PROMPT_INJECTION_PATTERNS):
        raise ValueError("service_summary must be descriptive metadata")
    return summary


def validate_community_tool_arguments(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"context"}:
        raise ProtocolError(-32602, "Invalid params")
    context = value.get("context")
    if not isinstance(context, str):
        raise ProtocolError(-32602, "Invalid params")
    normalized = {"context": context}
    if len(canonical_json(normalized).encode("utf-8")) > MAX_TOOL_ARGUMENTS_BYTES:
        raise ProtocolError(-32602, "Invalid params")
    return normalized


def request_body_limit() -> int:
    return MAX_REQUEST_BODY_BYTES
