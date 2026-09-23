"""Registry approval lifecycle and live community MCP catalog."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .config import MAX_PUBLIC_EVENT_HISTORY, MAX_REQUEST_BODY_BYTES, Settings
from .mcp_client import HttpMCPClient, MCPClient, MCPClientError
from .mcp_protocol import (
    ValidatedToolsList,
    descriptor_hash,
    qualify_tool_identity,
    validate_service_summary,
)
from .store import canonical_json, encode_timestamp, open_database, transaction, utc_now


KNOWN_PACKAGE_ID = "vendor-incident-review"
INTERNAL_SERVER_REF = "community-review"
KNOWN_PACKAGE_MANIFEST = {
    "name": KNOWN_PACKAGE_ID,
    "version": "1.0.0",
    "publisher_class": "community",
    "runtime": "mcp",
}
_FORBIDDEN_REGISTRATION_FIELDS = frozenset(
    {
        "url",
        "endpoint",
        "callback",
        "mcp_url",
        "server_url",
        "host",
        "hostname",
        "package_digest",
        "descriptor",
        "tools",
        "inputSchema",
    }
)


class RegistryError(RuntimeError):
    """A safe registry operation failure."""


class RegistryNotFound(RegistryError):
    pass


class RegistryConflict(RegistryError):
    """The requested registry state conflicts with an active integration."""


class RegistryService:
    def __init__(self, settings: Settings, mcp_client: MCPClient | None = None):
        self.settings = settings
        self.mcp_client = mcp_client or HttpMCPClient(
            settings.mcp_base_url or "http://mcp:8083",
            settings.credential("registry_mcp"),
        )
        self._owns_mcp_client = mcp_client is None

    async def close(self) -> None:
        if self._owns_mcp_client and isinstance(self.mcp_client, HttpMCPClient):
            await self.mcp_client.close()

    @staticmethod
    def package_digest(manifest: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()

    @staticmethod
    def _manifest(row: Mapping[str, Any]) -> dict[str, Any]:
        try:
            manifest = json.loads(row["package_manifest_json"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RegistryError("integration package state is unavailable") from exc
        if not isinstance(manifest, dict):
            raise RegistryError("integration package state is unavailable")
        return manifest

    @classmethod
    def _package_is_current(cls, row: Mapping[str, Any]) -> bool:
        try:
            manifest = cls._manifest(row)
        except RegistryError:
            return False
        return (
            manifest.get("name") == KNOWN_PACKAGE_ID
            and manifest.get("publisher_class") == "community"
            and manifest.get("runtime") == "mcp"
            and row["publisher_class"] == "community"
            and row["endpoint"] == INTERNAL_SERVER_REF
            and cls.package_digest(manifest) == row["package_digest"]
        )

    def _row(self, integration_id: str) -> Any:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                "SELECT * FROM integrations WHERE instance_id = ? AND id = ?",
                (self.settings.instance_id, integration_id),
            ).fetchone()
        if row is None:
            raise RegistryNotFound("integration not found")
        return row

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        try:
            manifest = json.loads(row["package_manifest_json"])
        except (KeyError, TypeError, json.JSONDecodeError):
            manifest = {}
        if not isinstance(manifest, dict):
            manifest = {}
        return {
            "integration_id": row["id"],
            "publisher_class": row["publisher_class"],
            "package": {
                "name": manifest.get("name", ""),
                "version": manifest.get("version", ""),
                "runtime": manifest.get("runtime", ""),
            },
            "package_digest": row["package_digest"],
            "status": row["status"],
            "approved_at": row["approved_at"],
        }

    async def register_known_package(self, package_id: str) -> dict[str, Any]:
        if package_id != KNOWN_PACKAGE_ID:
            raise RegistryError("unknown package")
        manifest = dict(KNOWN_PACKAGE_MANIFEST)
        integration_id = secrets.token_hex(8)
        manifest_json = canonical_json(manifest)
        package_digest = self.package_digest(manifest)
        try:
            with open_database(self.settings.database_path, self.settings.instance_id) as connection:
                with transaction(connection):
                    existing = connection.execute(
                        """
                        SELECT 1
                        FROM integrations
                        WHERE instance_id = ?
                          AND publisher_class = 'community'
                          AND endpoint = ?
                          AND status IN ('registered', 'pending', 'approved')
                        LIMIT 1
                        """,
                        (self.settings.instance_id, INTERNAL_SERVER_REF),
                    ).fetchone()
                    if existing is not None:
                        raise RegistryConflict("package already registered")
                    connection.execute(
                        """
                        INSERT INTO integrations
                            (instance_id, id, publisher_class, package_digest, endpoint,
                             status, package_manifest_json)
                        VALUES (?, ?, ?, ?, ?, 'pending', ?)
                        """,
                        (
                            self.settings.instance_id,
                            integration_id,
                            "community",
                            package_digest,
                            INTERNAL_SERVER_REF,
                            manifest_json,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            # The partial unique index closes the race between the service
            # check and the insert without exposing database details.
            raise RegistryConflict("package already registered") from exc
        try:
            await self.mcp_client.provision(self.settings.instance_id, integration_id)
        except (MCPClientError, OSError) as exc:
            with open_database(self.settings.database_path, self.settings.instance_id) as connection:
                with transaction(connection):
                    connection.execute(
                        "DELETE FROM integrations WHERE instance_id = ? AND id = ?",
                        (self.settings.instance_id, integration_id),
                    )
            raise RegistryError("MCP provisioning failed") from exc
        return self._public(self._row(integration_id))

    async def approve(self, integration_id: str) -> dict[str, Any]:
        row = self._row(integration_id)
        if not self._package_is_current(row):
            raise RegistryError("package approval is no longer valid")
        try:
            catalog = await self.mcp_client.list_tools(self.settings.instance_id, integration_id)
        except MCPClientError as exc:
            raise RegistryError("MCP catalog unavailable") from exc
        self._record_snapshot(integration_id, catalog)
        approved_at = encode_timestamp(utc_now())
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    UPDATE integrations
                    SET status = 'approved', approved_at = ?, approved_descriptor_hash = ?
                    WHERE instance_id = ? AND id = ?
                    """,
                    (
                        approved_at,
                        descriptor_hash(catalog.tools),
                        self.settings.instance_id,
                        integration_id,
                    ),
                )
        return self._public(self._row(integration_id))

    def _record_snapshot(self, integration_id: str, catalog: ValidatedToolsList) -> None:
        tools_by_identity = catalog.by_identity(integration_id)
        descriptor = canonical_json({"tools": list(tools_by_identity.values())})
        observed_at = encode_timestamp(utc_now())
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO tool_snapshots
                        (instance_id, integration_id, descriptor_hash, descriptor_json, observed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        self.settings.instance_id,
                        integration_id,
                        descriptor_hash(catalog.tools),
                        descriptor,
                        observed_at,
                    ),
                )

    async def runtime_catalog(self, integration_id: str) -> dict[str, Any]:
        row = self._row(integration_id)
        if row["status"] != "approved" or not self._package_is_current(row):
            raise RegistryError("integration is not approved")
        try:
            catalog = await self.mcp_client.list_tools(self.settings.instance_id, integration_id)
        except MCPClientError as exc:
            raise RegistryError("MCP catalog unavailable") from exc
        self._record_snapshot(integration_id, catalog)
        # Refresh current package metadata for the catalog response.
        return {
            "integration_id": row["id"],
            "publisher_class": row["publisher_class"],
            "package": {
                "name": self._manifest(row).get("name", ""),
                "version": self._manifest(row).get("version", ""),
            },
            "status": row["status"],
            "tools": list(catalog.by_identity(row["id"]).values()),
        }

    async def update_runtime_metadata(self, integration_id: str, service_summary: str) -> dict[str, Any]:
        summary = validate_service_summary(service_summary)
        row = self._row(integration_id)
        if row["status"] != "approved":
            raise RegistryError("runtime metadata is available after approval")
        try:
            await self.mcp_client.update_runtime_metadata(
                self.settings.instance_id, integration_id, summary
            )
        except MCPClientError as exc:
            raise RegistryError("MCP metadata update failed") from exc
        return self._public(self._row(integration_id))

    def list_integrations(self) -> list[dict[str, Any]]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            rows = connection.execute(
                "SELECT * FROM integrations WHERE instance_id = ? ORDER BY id",
                (self.settings.instance_id,),
            ).fetchall()
        return [self._public(row) for row in rows]

    def list_deliveries(self, integration_id: str) -> dict[str, Any]:
        row = self._row(integration_id)
        if row["status"] != "approved" or not self._package_is_current(row):
            raise RegistryError("integration is not approved")
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            total_count = connection.execute(
                """
                SELECT COUNT(*) FROM community_deliveries
                WHERE instance_id = ? AND integration_id = ?
                """,
                (self.settings.instance_id, integration_id),
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT id, incident_id, received_context_json, created_at
                FROM community_deliveries
                WHERE instance_id = ? AND integration_id = ?
                ORDER BY created_at, id
                LIMIT ?
                """,
                (self.settings.instance_id, integration_id, MAX_PUBLIC_EVENT_HISTORY),
            ).fetchall()
        deliveries: list[dict[str, Any]] = []
        for delivery in rows:
            try:
                received_context = json.loads(delivery["received_context_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise RegistryError("delivery state is unavailable") from exc
            if not isinstance(received_context, dict):
                raise RegistryError("delivery state is unavailable")
            deliveries.append(
                {
                    "delivery_id": delivery["id"],
                    "incident_id": delivery["incident_id"],
                    "received_context": received_context,
                    "created_at": delivery["created_at"],
                }
            )
        return {
            "integration_id": integration_id,
            "delivery_count": total_count,
            "deliveries": deliveries,
        }

    def replace_package_manifest(self, integration_id: str, manifest: Mapping[str, Any]) -> None:
        """Trusted organizer/package-state primitive; not exposed as a player route."""

        if (
            manifest.get("name") != KNOWN_PACKAGE_ID
            or manifest.get("publisher_class") != "community"
            or manifest.get("runtime") != "mcp"
        ):
            raise RegistryError("package manifest is not a supported community package")
        manifest_json = canonical_json(dict(manifest))
        package_digest = self.package_digest(manifest)
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            with transaction(connection):
                changed = connection.execute(
                    """
                    UPDATE integrations
                    SET package_digest = ?, package_manifest_json = ?, status = 'registered',
                        approved_at = NULL, approved_descriptor_hash = NULL
                    WHERE instance_id = ? AND id = ?
                    """,
                    (
                        package_digest,
                        manifest_json,
                        self.settings.instance_id,
                        integration_id,
                    ),
                ).rowcount
                if changed != 1:
                    raise RegistryNotFound("integration not found")


def _unauthorized() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})


async def _read_object(request: Request) -> tuple[dict[str, Any] | None, Response | None]:
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        return None, JSONResponse({"error": "request rejected"}, status_code=413)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)
    if not isinstance(value, dict):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)
    return value, None


def create_app(settings: Settings, *, mcp_client: MCPClient | None = None) -> FastAPI:
    service = RegistryService(settings, mcp_client)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            await service.close()

    app = FastAPI(
        title="ARGUS Registry",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.registry_service = service

    def authorized(request: Request) -> bool:
        try:
            secret = settings.credential("portal_registry")
        except KeyError:
            return False
        from .mcp_protocol import authenticated_edge

        return authenticated_edge(request.headers, {"portal_registry": secret}) == "portal_registry"

    def agents_authorized(request: Request) -> bool:
        try:
            secret = settings.credential("agents_registry")
        except KeyError:
            return False
        from .mcp_protocol import authenticated_edge

        return authenticated_edge(request.headers, {"agents_registry": secret}) == "agents_registry"

    @app.get("/healthz")
    async def healthz() -> Mapping[str, str]:
        return {"role": "registry", "status": "ok"}

    @app.post("/api/integrations")
    async def register(request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        body, error = await _read_object(request)
        if error is not None:
            return error
        assert body is not None
        if _FORBIDDEN_REGISTRATION_FIELDS & body.keys() or set(body) != {"package_id"}:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            result = await service.register_known_package(body["package_id"])
        except RegistryConflict:
            return JSONResponse({"error": "registration rejected"}, status_code=409)
        except RegistryError:
            return JSONResponse({"error": "registration rejected"}, status_code=400)
        return JSONResponse(result, status_code=201)

    @app.get("/api/integrations")
    async def integrations(request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        return JSONResponse({"integrations": service.list_integrations()})

    @app.get("/internal/agents/catalog/{integration_id}")
    async def agents_catalog(integration_id: str, request: Request) -> Response:
        if not agents_authorized(request):
            return _unauthorized()
        if request.headers.get("X-Argus-Instance") != settings.instance_id:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            return JSONResponse(await service.runtime_catalog(integration_id))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)
        except RegistryError:
            return JSONResponse({"error": "catalog unavailable"}, status_code=409)

    @app.get("/api/catalog")
    async def catalog(request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        results: list[dict[str, Any]] = []
        try:
            for item in service.list_integrations():
                if item["status"] == "approved":
                    results.append(await service.runtime_catalog(item["integration_id"]))
        except RegistryError:
            return JSONResponse({"error": "catalog unavailable"}, status_code=409)
        return JSONResponse({"integrations": results})

    @app.post("/api/integrations/{integration_id}/approve")
    async def approve(integration_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(await service.approve(integration_id))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)
        except RegistryError:
            return JSONResponse({"error": "approval rejected"}, status_code=409)

    @app.patch("/api/integrations/{integration_id}/runtime-metadata")
    async def runtime_metadata(integration_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        body, error = await _read_object(request)
        if error is not None:
            return error
        assert body is not None
        if set(body) != {"service_summary"}:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        try:
            return JSONResponse(await service.update_runtime_metadata(integration_id, body["service_summary"]))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)
        except ValueError:
            return JSONResponse({"error": "invalid request"}, status_code=400)
        except RegistryError:
            return JSONResponse({"error": "runtime metadata unavailable"}, status_code=409)

    @app.get("/api/integrations/{integration_id}/tools")
    async def integration_tools(integration_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(await service.runtime_catalog(integration_id))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)
        except RegistryError:
            return JSONResponse({"error": "catalog unavailable"}, status_code=409)

    @app.get("/api/integrations/{integration_id}/deliveries")
    async def deliveries(integration_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(service.list_deliveries(integration_id))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)
        except RegistryError:
            return JSONResponse({"error": "deliveries unavailable"}, status_code=409)

    @app.get("/api/integrations/{integration_id}")
    async def integration(integration_id: str, request: Request) -> Response:
        if not authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(service._public(service._row(integration_id)))
        except RegistryNotFound:
            return JSONResponse({"error": "not found"}, status_code=404)

    return app
