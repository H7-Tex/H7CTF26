"""Read-only Registry client used by the internal Incident Agent."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .config import MAX_DESCRIPTOR_BYTES, MAX_TOOL_CALLS
from .mcp_protocol import COMMUNITY_INPUT_SCHEMA, COMMUNITY_TOOL_NAME, ToolIdentity, qualify_tool_identity
from .store import canonical_json


class RegistryCatalogError(RuntimeError):
    """A safe failure while fetching or validating a live Registry catalog."""


@dataclass(frozen=True, slots=True)
class CatalogTool:
    identity: ToolIdentity
    description: str
    input_schema: dict[str, Any]

    def for_model(self) -> dict[str, Any]:
        return {
            "server_id": self.identity.server_id,
            "tool_name": self.identity.tool_name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class RegistryCatalogClient(Protocol):
    async def get_catalog(self, instance_id: str, integration_id: str) -> tuple[CatalogTool, ...]:
        ...


def validate_catalog(payload: Any, integration_id: str) -> tuple[CatalogTool, ...]:
    if not isinstance(payload, Mapping):
        raise RegistryCatalogError("catalog response rejected")
    if payload.get("integration_id") != integration_id or payload.get("status") != "approved":
        raise RegistryCatalogError("catalog response rejected")
    tools = payload.get("tools")
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise RegistryCatalogError("catalog response rejected")
    if not 1 <= len(tools) <= MAX_TOOL_CALLS:
        raise RegistryCatalogError("catalog response rejected")
    normalized: list[CatalogTool] = []
    for tool in tools:
        if not isinstance(tool, Mapping) or set(tool) != {"name", "description", "inputSchema"}:
            raise RegistryCatalogError("catalog response rejected")
        if tool.get("name") != COMMUNITY_TOOL_NAME or not isinstance(tool.get("description"), str):
            raise RegistryCatalogError("catalog response rejected")
        schema = tool.get("inputSchema")
        if not isinstance(schema, Mapping) or canonical_json(schema) != canonical_json(COMMUNITY_INPUT_SCHEMA):
            raise RegistryCatalogError("catalog response rejected")
        descriptor = canonical_json(tool)
        if len(descriptor.encode("utf-8")) > MAX_DESCRIPTOR_BYTES:
            raise RegistryCatalogError("catalog response rejected")
        normalized.append(
            CatalogTool(
                identity=qualify_tool_identity(integration_id, COMMUNITY_TOOL_NAME),
                description=tool["description"],
                input_schema=dict(schema),
            )
        )
    if len({tool.identity for tool in normalized}) != len(normalized):
        raise RegistryCatalogError("catalog response rejected")
    return tuple(normalized)


class HttpRegistryCatalogClient:
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

    async def get_catalog(self, instance_id: str, integration_id: str) -> tuple[CatalogTool, ...]:
        try:
            response = await self._client.get(
                f"/internal/agents/catalog/{integration_id}",
                headers={
                    "Authorization": f"Bearer {self._credential}",
                    "X-Argus-Instance": instance_id,
                },
            )
            if response.status_code >= 400 or len(response.content) > MAX_DESCRIPTOR_BYTES:
                raise RegistryCatalogError("catalog request rejected")
            return validate_catalog(response.json(), integration_id)
        except RegistryCatalogError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise RegistryCatalogError("catalog response rejected") from exc
