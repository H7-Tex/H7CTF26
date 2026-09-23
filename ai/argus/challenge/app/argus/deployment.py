"""Trusted Deployment role for the final ARGUS actuator phase."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .config import MAX_REQUEST_BODY_BYTES, Settings
from .domain import GrantedCapability, canonical_approval_claims
from .kubernetes import (
    BrokerKubernetesAdapter,
    DeploymentProfile,
    EvidenceSnapshot,
    HttpKubernetesAdapter,
    KubernetesAdapter,
    KubernetesAdapterError,
    ReadinessResult,
    build_profile_manifest,
    namespace_authority,
    namespace_for_instance,
    profile_for_capability,
    validate_shared_worker_spec,
    validate_trusted_profile_manifest,
    workload_name_for_deployment,
)
from .mcp_protocol import authenticated_edge
from .store import (
    canonical_json,
    claim_security_approval_and_insert_deployment,
    encode_timestamp,
    open_database,
    parse_timestamp,
    update_k8s_deployment,
    utc_now,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_APPROVAL_FIELDS = frozenset(
    {
        "approval_id",
        "task_id",
        "control_id",
        "target",
        "granted_capability",
        "expires_at",
        "key_id",
        "signature",
    }
)


class ApprovalRejected(ValueError):
    """The submitted approval is not valid authority for this instance."""


def _unauthorized() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})


async def _read_json(request: Request) -> tuple[Any | None, Response | None]:
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        return None, JSONResponse({"error": "request rejected"}, status_code=413)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "invalid request"}, status_code=400)
    return value, None


def _bounded_text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ApprovalRejected(f"invalid {field}")
    return value


def _approval_body(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _APPROVAL_FIELDS:
        raise ApprovalRejected("approval fields are invalid")
    result = {
        "approval_id": _bounded_text(value["approval_id"], "approval_id"),
        "task_id": _bounded_text(value["task_id"], "task_id"),
        "control_id": _bounded_text(value["control_id"], "control_id"),
        "target": _bounded_text(value["target"], "target"),
        "granted_capability": _bounded_text(value["granted_capability"], "granted_capability", 64),
        "expires_at": _bounded_text(value["expires_at"], "expires_at", 64),
        "key_id": _bounded_text(value["key_id"], "key_id", 128),
        "signature": _bounded_text(value["signature"], "signature", 128),
    }
    if not _IDENTIFIER.fullmatch(result["approval_id"]):
        raise ApprovalRejected("approval identifier is invalid")
    if not _IDENTIFIER.fullmatch(result["task_id"]):
        raise ApprovalRejected("task identifier is invalid")
    if not _IDENTIFIER.fullmatch(result["control_id"]):
        raise ApprovalRejected("control identifier is invalid")
    if not _IDENTIFIER.fullmatch(result["target"]):
        raise ApprovalRejected("target is invalid")
    if not _SIGNATURE.fullmatch(result["signature"]):
        raise ApprovalRejected("signature is invalid")
    try:
        capability = GrantedCapability(result["granted_capability"])
    except ValueError as exc:
        raise ApprovalRejected("capability is invalid") from exc
    result["granted_capability"] = capability.value
    try:
        parse_timestamp(result["expires_at"])
    except ValueError as exc:
        raise ApprovalRejected("expiry is invalid") from exc
    return result


def _verify_approval(settings: Settings, connection: Any, submitted: Mapping[str, str]) -> GrantedCapability:
    try:
        capability = GrantedCapability(submitted["granted_capability"])
    except ValueError as exc:
        raise ApprovalRejected("capability is invalid") from exc
    if submitted["key_id"] != settings.approval_signing_key_id:
        raise ApprovalRejected("approval key is not configured")
    if settings.approval_signing_algorithm != "HMAC-SHA256" or not settings.approval_signing_key:
        raise ApprovalRejected("approval verification is unavailable")
    expires_at = parse_timestamp(submitted["expires_at"])
    now = utc_now()
    if expires_at <= now:
        raise ApprovalRejected("approval is expired")
    claims = canonical_approval_claims(
        instance_id=settings.instance_id,
        approval_id=submitted["approval_id"],
        task_id=submitted["task_id"],
        control_id=submitted["control_id"],
        target=submitted["target"],
        granted_capability=capability,
        expires_at=submitted["expires_at"],
        key_id=submitted["key_id"],
    )
    expected = hmac.new(
        settings.approval_signing_key.encode("utf-8"), claims.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, submitted["signature"]):
        raise ApprovalRejected("approval signature is invalid")
    row = connection.execute(
        """
        SELECT instance_id, id, task_id, control_id, target, granted_capability,
               expires_at, key_id, signature, consumed_at
        FROM security_approvals
        WHERE instance_id = ? AND id = ?
        """,
        (settings.instance_id, submitted["approval_id"]),
    ).fetchone()
    if row is None or row["consumed_at"] is not None:
        raise ApprovalRejected("approval is unavailable")
    for field in (
        "instance_id",
        "id",
        "task_id",
        "control_id",
        "target",
        "granted_capability",
        "expires_at",
        "key_id",
        "signature",
    ):
        expected_value = settings.instance_id if field == "instance_id" else submitted.get(
            "approval_id" if field == "id" else field
        )
        if row[field] != expected_value:
            raise ApprovalRejected("approval persistence binding rejected")
    if parse_timestamp(row["expires_at"]) <= now:
        raise ApprovalRejected("approval is expired")
    return capability


def _handle_is_trusted(
    handle: Any,
    instance_id: str,
    deployment_id: str,
    profile: DeploymentProfile,
    manifest_hash: str,
    namespace_prefix: str,
) -> bool:
    return (
        handle.instance_id == instance_id
        and handle.deployment_id == deployment_id
        and handle.namespace == namespace_for_instance(instance_id, namespace_prefix)
        and handle.workload == workload_name_for_deployment(instance_id, deployment_id)
        and handle.profile is profile
        and handle.service_account == namespace_authority(profile).service_account
        and handle.manifest_hash == manifest_hash
    )


def _evidence_payload(readiness: ReadinessResult, snapshot: EvidenceSnapshot) -> str:
    return canonical_json(
        {
            "readiness": {"ready": readiness.ready, "status": readiness.status},
            "status": snapshot.status,
            "events": list(snapshot.event_summary),
        }
    )


class DeploymentService:
    def __init__(self, settings: Settings, adapter: KubernetesAdapter | None):
        self.settings = settings
        self.adapter = adapter

    def create(self, submitted: Mapping[str, str]) -> tuple[dict[str, Any], int]:
        if self.adapter is None:
            raise RuntimeError("Deployment Kubernetes adapter is unavailable")
        deployment_id = f"deployment-{secrets.token_hex(8)}"
        capability = GrantedCapability(submitted["granted_capability"])
        profile = profile_for_capability(capability)
        namespace = namespace_for_instance(self.settings.instance_id, self.settings.k8s_namespace_prefix)
        workload = workload_name_for_deployment(self.settings.instance_id, deployment_id)
        authority = namespace_authority(profile)
        workload_image = (
            self.settings.elevated_workload_image or self.settings.trusted_workload_image
            if profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED
            else self.settings.trusted_workload_image
        )
        manifest = build_profile_manifest(
            instance_id=self.settings.instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=workload_image,
            namespace_prefix=self.settings.k8s_namespace_prefix,
        )
        validate_trusted_profile_manifest(
            manifest,
            instance_id=self.settings.instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=workload_image,
            namespace_prefix=self.settings.k8s_namespace_prefix,
        )
        validate_shared_worker_spec(manifest)
        manifest_hash = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()
        now = encode_timestamp(utc_now())
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            _verify_approval(self.settings, connection, submitted)
            try:
                claimed = claim_security_approval_and_insert_deployment(
                    connection,
                    instance_id=self.settings.instance_id,
                    approval_id=submitted["approval_id"],
                    task_id=submitted["task_id"],
                    control_id=submitted["control_id"],
                    target=submitted["target"],
                    granted_capability=capability,
                    key_id=submitted["key_id"],
                    signature=submitted["signature"],
                    now=now,
                    consumed_at=now,
                    deployment_id=deployment_id,
                    namespace=namespace,
                    workload=workload,
                    profile=profile.value,
                    service_account=authority.service_account,
                    manifest_hash=manifest_hash,
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalRejected("approval was already consumed") from exc
            if not claimed:
                raise ApprovalRejected("approval was already consumed")
        handle = None
        try:
            handle = self.adapter.create_workload(self.settings.instance_id, deployment_id, profile)
            if not _handle_is_trusted(
                handle,
                self.settings.instance_id,
                deployment_id,
                profile,
                manifest_hash,
                self.settings.k8s_namespace_prefix,
            ):
                raise KubernetesAdapterError("adapter returned an untrusted workload handle")
            readiness = self.adapter.wait_ready(handle, self.settings.k8s_ready_timeout_seconds)
            if not readiness.ready:
                raise KubernetesAdapterError("workload did not become ready")
            snapshot = self.adapter.snapshot_evidence(handle, readiness)
            if snapshot.profile is not profile or snapshot.namespace != namespace or snapshot.workload != workload:
                raise KubernetesAdapterError("adapter returned untrusted evidence")
            if profile is DeploymentProfile.TEAM_NAMESPACE and snapshot.verification_result is not None:
                raise KubernetesAdapterError("normal runtime returned a verification result")
            if snapshot.status != "ready":
                raise KubernetesAdapterError("workload evidence is not ready")
            with open_database(self.settings.database_path, self.settings.instance_id) as connection:
                update_k8s_deployment(
                    connection,
                    instance_id=self.settings.instance_id,
                    deployment_id=deployment_id,
                    status="ready",
                    ready_at=readiness.observed_at,
                    evidence_json=_evidence_payload(readiness, snapshot),
                    verification_result=snapshot.verification_result,
                )
            return self.get(deployment_id), 201
        except Exception:
            try:
                if handle is not None and _handle_is_trusted(
                    handle,
                    self.settings.instance_id,
                    deployment_id,
                    profile,
                    manifest_hash,
                    self.settings.k8s_namespace_prefix,
                ):
                    try:
                        self.adapter.delete_workload(handle)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                with open_database(self.settings.database_path, self.settings.instance_id) as connection:
                    update_k8s_deployment(
                        connection,
                        instance_id=self.settings.instance_id,
                        deployment_id=deployment_id,
                        status="failed",
                        evidence_json=canonical_json({"status": "failed", "events": ["workload activation failed"]}),
                    )
            except Exception:
                pass
            raise

    def get(self, deployment_id: str) -> dict[str, Any]:
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                """
                SELECT d.id, d.approval_id, a.task_id, d.namespace, d.workload,
                       d.profile, d.service_account, d.manifest_hash, d.status,
                       d.cleaned_at, d.ready_at, d.evidence_json, d.verification_result
                FROM k8s_deployments AS d
                JOIN security_approvals AS a
                  ON a.instance_id = d.instance_id AND a.id = d.approval_id
                WHERE d.instance_id = ? AND d.id = ?
                """,
                (self.settings.instance_id, deployment_id),
            ).fetchone()
        if row is None:
            raise LookupError("deployment not found")
        try:
            evidence = json.loads(row["evidence_json"])
        except (TypeError, json.JSONDecodeError):
            evidence = {"status": "unavailable", "events": []}
        result: dict[str, Any] = {
            "deployment_id": row["id"],
            "approval_id": row["approval_id"],
            "task_id": row["task_id"],
            "status": row["status"],
            "profile": row["profile"],
            "namespace": row["namespace"],
            "workload": row["workload"],
            "service_account": row["service_account"],
            "manifest_hash": row["manifest_hash"],
            "readiness": evidence.get("readiness", {"ready": row["status"] == "ready"}),
            "evidence": {"status": evidence.get("status", "unavailable"), "events": evidence.get("events", [])},
        }
        if row["verification_result"] is not None:
            result["verification_result"] = row["verification_result"]
        return result

    def delete(self, deployment_id: str) -> dict[str, Any]:
        if self.adapter is None:
            raise RuntimeError("Deployment Kubernetes adapter is unavailable")
        with open_database(self.settings.database_path, self.settings.instance_id) as connection:
            row = connection.execute(
                "SELECT id, namespace, workload, profile, service_account, manifest_hash, status FROM k8s_deployments WHERE instance_id=? AND id=?",
                (self.settings.instance_id, deployment_id),
            ).fetchone()
        if row is None:
            raise LookupError("deployment not found")
        if row["status"] != "deleted":
            profile = DeploymentProfile(row["profile"])
            from .kubernetes import WorkloadHandle

            handle = WorkloadHandle(
                instance_id=self.settings.instance_id,
                deployment_id=deployment_id,
                namespace=row["namespace"],
                workload=row["workload"],
                profile=profile,
                service_account=row["service_account"],
                manifest_hash=row["manifest_hash"],
            )
            if not _handle_is_trusted(
                handle,
                self.settings.instance_id,
                deployment_id,
                profile,
                row["manifest_hash"],
                self.settings.k8s_namespace_prefix,
            ):
                raise KubernetesAdapterError("persisted workload handle is not trusted")
            self.adapter.delete_workload(handle)
            with open_database(self.settings.database_path, self.settings.instance_id) as connection:
                update_k8s_deployment(
                    connection,
                    instance_id=self.settings.instance_id,
                    deployment_id=deployment_id,
                    status="deleted",
                    cleaned_at=encode_timestamp(utc_now()),
                )
        return self.get(deployment_id)


def create_app(settings: Settings, *, kubernetes_adapter: KubernetesAdapter | None = None) -> FastAPI:
    adapter = kubernetes_adapter
    if adapter is None and settings.k8s_enabled:
        adapter = (
            BrokerKubernetesAdapter(settings)
            if settings.environment == "h7"
            else HttpKubernetesAdapter(settings)
        )
    service = DeploymentService(settings, adapter)
    app = FastAPI(
        title="ARGUS Deployment",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.deployment_service = service

    def edge_secret() -> str:
        try:
            return settings.credential("portal_deployment")
        except KeyError:
            return ""

    def allowed(request: Request) -> bool:
        return authenticated_edge(request.headers, {"portal_deployment": edge_secret()}) == "portal_deployment"

    @app.get("/healthz")
    async def healthz() -> Mapping[str, str]:
        return {"role": "deployment", "status": "ok"}

    @app.post("/api/deployments")
    async def create_deployment(request: Request) -> Response:
        if not allowed(request):
            return _unauthorized()
        body, error = await _read_json(request)
        if error is not None:
            return error
        try:
            submitted = _approval_body(body)
            result, status = service.create(submitted)
            return JSONResponse(result, status_code=status)
        except ApprovalRejected:
            return JSONResponse({"error": "approval rejected"}, status_code=400)
        except (ValueError, LookupError):
            return JSONResponse({"error": "request rejected"}, status_code=400)
        except KubernetesAdapterError:
            return JSONResponse({"error": "deployment activation failed"}, status_code=502)
        except RuntimeError:
            return JSONResponse({"error": "deployment unavailable"}, status_code=503)

    @app.get("/api/deployments/{deployment_id}")
    async def get_deployment(deployment_id: str, request: Request) -> Response:
        if not allowed(request):
            return _unauthorized()
        if not _IDENTIFIER.fullmatch(deployment_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            return JSONResponse(service.get(deployment_id))
        except LookupError:
            return JSONResponse({"error": "not found"}, status_code=404)

    @app.delete("/api/deployments/{deployment_id}")
    async def delete_deployment(deployment_id: str, request: Request) -> Response:
        if not allowed(request):
            return _unauthorized()
        if not _IDENTIFIER.fullmatch(deployment_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        try:
            return JSONResponse(service.delete(deployment_id))
        except LookupError:
            return JSONResponse({"error": "not found"}, status_code=404)
        except KubernetesAdapterError:
            return JSONResponse({"error": "cleanup failed"}, status_code=502)
        except RuntimeError:
            return JSONResponse({"error": "deployment unavailable"}, status_code=503)

    return app
