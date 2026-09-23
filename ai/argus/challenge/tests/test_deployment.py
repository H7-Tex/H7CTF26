from datetime import UTC, datetime, timedelta
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from argus.config import Settings
from argus.domain import GrantedCapability, canonical_approval_claims
from argus.deployment import create_app
from argus.kubernetes import (
    DeploymentProfile,
    EvidenceSnapshot,
    KubernetesAdapterError,
    ReadinessResult,
    WorkloadHandle,
    build_profile_manifest,
    namespace_authority,
    namespace_for_instance,
    workload_name_for_deployment,
)
from argus.store import canonical_json, connect_database, encode_timestamp, initialize_schema, insert_security_approval


KEY = "deployment-test-signing-key"
KEY_ID = "argus-test-key"
PORTAL_TOKEN = "portal-deployment-secret"
IMAGE = "argus/workload:foundation"


def _settings(tmp_path: Path, *, instance_id: str = "team-a", key: str = KEY) -> Settings:
    return Settings(
        role="deployment",
        instance_id=instance_id,
        data_dir=tmp_path,
        database_path=tmp_path / "argus.sqlite3",
        ollama_url="http://ollama:11434",
        ollama_model="qwen2.5-coder:7b",
        ollama_digest="a" * 64,
        model_seed=7,
        model_temperature=0.0,
        model_context_tokens=1024,
        model_strict_json=True,
        environment="development",
        service_credentials={"portal_deployment": PORTAL_TOKEN},
        approval_signing_key=key,
        approval_signing_key_id=KEY_ID,
        trusted_workload_image=IMAGE,
        k8s_namespace_prefix="argus",
        k8s_ready_timeout_seconds=1,
    )


def _signed_approval(settings: Settings, *, approval_id: str, task_id: str = "task-1", capability=GrantedCapability.PROTECTED_RUNTIME, expires_at: str | None = None) -> dict[str, str]:
    expiry = expires_at or encode_timestamp(datetime.now(UTC) + timedelta(minutes=10))
    claims = canonical_approval_claims(
        instance_id=settings.instance_id,
        approval_id=approval_id,
        task_id=task_id,
        control_id="control-team-a",
        target="team-runtime",
        granted_capability=capability,
        expires_at=expiry,
        key_id=settings.approval_signing_key_id,
    )
    import hashlib
    import hmac

    signature = hmac.new(settings.approval_signing_key.encode(), claims.encode(), hashlib.sha256).hexdigest()
    return {
        "approval_id": approval_id,
        "task_id": task_id,
        "control_id": "control-team-a",
        "target": "team-runtime",
        "granted_capability": capability.value,
        "expires_at": expiry,
        "key_id": settings.approval_signing_key_id,
        "signature": signature,
    }


def _seed_approval(settings: Settings, body: dict[str, str]) -> None:
    connection = connect_database(settings.database_path)
    initialize_schema(connection)
    connection.execute(
        """
        INSERT INTO a2a_tasks
            (instance_id,id,caller_service,origin_subject,owner_class,skill_id,
             artifact_kind,artifact_json,status)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (settings.instance_id, body["task_id"], "coordinator", "external-partner", "external-partner", "deployment-control-review", "deployment-review", "{}", "completed"),
    )
    connection.commit()
    insert_security_approval(
        connection,
        instance_id=settings.instance_id,
        approval_id=body["approval_id"],
        task_id=body["task_id"],
        control_id=body["control_id"],
        target=body["target"],
        granted_capability=GrantedCapability(body["granted_capability"]),
        expires_at=body["expires_at"],
        signature=body["signature"],
        key_id=body["key_id"],
    )
    connection.close()


class FakeKubernetesAdapter:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.created: list[WorkloadHandle] = []
        self.deleted: list[WorkloadHandle] = []

    def namespace_for_instance(self, instance_id: str) -> str:
        return namespace_for_instance(instance_id, self.settings.k8s_namespace_prefix)

    def create_workload(self, instance_id: str, deployment_id: str, profile: DeploymentProfile) -> WorkloadHandle:
        manifest = build_profile_manifest(
            instance_id=instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=self.settings.trusted_workload_image,
            namespace_prefix=self.settings.k8s_namespace_prefix,
        )
        import hashlib

        handle = WorkloadHandle(
            instance_id=instance_id,
            deployment_id=deployment_id,
            namespace=self.namespace_for_instance(instance_id),
            workload=workload_name_for_deployment(instance_id, deployment_id),
            profile=profile,
            service_account=namespace_authority(profile).service_account,
            manifest_hash=hashlib.sha256(canonical_json(manifest).encode()).hexdigest(),
        )
        self.created.append(handle)
        return handle

    def wait_ready(self, workload: WorkloadHandle, timeout_seconds: int) -> ReadinessResult:
        return ReadinessResult(True, "ready", encode_timestamp(datetime.now(UTC)))

    def snapshot_evidence(self, workload: WorkloadHandle, readiness: ReadinessResult) -> EvidenceSnapshot:
        verification_result = "H7CTF{dummy}" if workload.profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED else None
        return EvidenceSnapshot(
            namespace=workload.namespace,
            workload=workload.workload,
            profile=workload.profile,
            service_account=workload.service_account,
            manifest_hash=workload.manifest_hash,
            status="ready",
            event_summary=("workload ready", "runtime profile isolation verified"),
            verification_result=verification_result,
        )

    def delete_workload(self, workload: WorkloadHandle) -> None:
        self.deleted.append(workload)

    def request_namespace_cleanup(self, instance_id: str) -> None:
        raise AssertionError("the service must not own namespace cleanup")


class WrongHandleAdapter(FakeKubernetesAdapter):
    def __init__(self, settings: Settings, field: str):
        super().__init__(settings)
        self.field = field

    def create_workload(self, instance_id: str, deployment_id: str, profile: DeploymentProfile) -> WorkloadHandle:
        handle = super().create_workload(instance_id, deployment_id, profile)
        wrong = {
            "profile": DeploymentProfile.TEAM_NAMESPACE if profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED else DeploymentProfile.TEAM_NAMESPACE_ELEVATED,
            "namespace": "argus-other-team",
            "workload": "argus-workload-wrong",
            "service_account": "argus-wrong",
        }[self.field]
        return replace(handle, **{self.field: wrong})


class VerificationResultAdapter(FakeKubernetesAdapter):
    def snapshot_evidence(self, workload: WorkloadHandle, readiness: ReadinessResult) -> EvidenceSnapshot:
        snapshot = super().snapshot_evidence(workload, readiness)
        return replace(snapshot, verification_result="unexpected-result")


class FailingActivationAdapter(FakeKubernetesAdapter):
    def snapshot_evidence(self, workload: WorkloadHandle, readiness: ReadinessResult) -> EvidenceSnapshot:
        raise KubernetesAdapterError("malformed runtime result")


def _client(tmp_path: Path, *, instance_id: str = "team-a", key: str = KEY):
    settings = _settings(tmp_path, instance_id=instance_id, key=key)
    adapter = FakeKubernetesAdapter(settings)
    app = create_app(settings, kubernetes_adapter=adapter)
    return settings, adapter, TestClient(app)


def test_protected_approval_maps_to_elevated_profile_and_bounded_evidence(tmp_path):
    settings, adapter, client = _client(tmp_path)
    body = _signed_approval(settings, approval_id="approval-1")
    _seed_approval(settings, body)
    headers = {"Authorization": f"Bearer {PORTAL_TOKEN}"}

    response = client.post("/api/deployments", json=body, headers=headers)
    assert response.status_code == 201
    result = response.json()
    assert result["approval_id"] == "approval-1"
    assert result["profile"] == "team-namespace-elevated"
    assert result["service_account"] == "argus-elevated"
    assert result["status"] == "ready"
    assert result["verification_result"] == "H7CTF{dummy}"
    assert len(adapter.created) == 1
    deployment_id = result["deployment_id"]

    replay = client.post("/api/deployments", json=body, headers=headers)
    assert replay.status_code == 400
    assert len(adapter.created) == 1
    fetched = client.get(f"/api/deployments/{deployment_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["profile"] == "team-namespace-elevated"
    assert fetched.json()["verification_result"] == "H7CTF{dummy}"

    deleted = client.delete(f"/api/deployments/{deployment_id}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"
    assert len(adapter.deleted) == 1


def test_standard_approval_is_normal_profile_without_verification_result(tmp_path):
    settings, adapter, client = _client(tmp_path)
    body = _signed_approval(settings, approval_id="approval-standard", capability=GrantedCapability.STANDARD_RUNTIME)
    _seed_approval(settings, body)
    response = client.post(
        "/api/deployments",
        json=body,
        headers={"Authorization": f"Bearer {PORTAL_TOKEN}"},
    )
    assert response.status_code == 201
    result = response.json()
    assert result["profile"] == "team-namespace"
    assert result["service_account"] == "argus-worker"
    assert "verification_result" not in result
    assert adapter.created[0].profile is DeploymentProfile.TEAM_NAMESPACE


@pytest.mark.parametrize("field", ["task_id", "control_id", "target", "granted_capability", "expires_at", "key_id", "signature"])
def test_modified_signed_claim_is_rejected(tmp_path, field):
    settings, _, client = _client(tmp_path)
    body = _signed_approval(settings, approval_id=f"approval-{field}")
    _seed_approval(settings, body)
    changed = dict(body)
    changed[field] = {
        "granted_capability": GrantedCapability.STANDARD_RUNTIME.value,
        "expires_at": encode_timestamp(datetime.now(UTC) + timedelta(hours=1)),
        "signature": "0" * 64,
    }.get(field, "changed")
    response = client.post(
        "/api/deployments",
        json=changed,
        headers={"Authorization": f"Bearer {PORTAL_TOKEN}"},
    )
    assert response.status_code == 400


def test_unknown_public_authority_fields_and_missing_auth_are_rejected(tmp_path):
    settings, _, client = _client(tmp_path)
    body = _signed_approval(settings, approval_id="approval-fields")
    _seed_approval(settings, body)
    for field in ("profile", "namespace", "service_account", "image", "manifest", "command", "args", "env", "secret", "resource_name"):
        changed = dict(body)
        changed[field] = "attacker-controlled"
        response = client.post("/api/deployments", json=changed, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
        assert response.status_code == 400
    assert client.post("/api/deployments", json=body).status_code == 401


def test_cross_instance_lookup_is_not_visible(tmp_path):
    settings, _, client = _client(tmp_path, instance_id="team-a")
    body = _signed_approval(settings, approval_id="approval-cross")
    _seed_approval(settings, body)
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    deployment_id = response.json()["deployment_id"]
    other_settings, _, other_client = _client(tmp_path, instance_id="team-b")
    assert other_settings.instance_id == "team-b"
    assert other_client.get(f"/api/deployments/{deployment_id}", headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 404
    assert other_client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 400


def test_expired_approval_is_rejected_before_claim(tmp_path):
    settings, adapter, client = _client(tmp_path)
    body = _signed_approval(
        settings,
        approval_id="approval-expired",
        expires_at=encode_timestamp(datetime.now(UTC) - timedelta(minutes=1)),
    )
    _seed_approval(settings, body)
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    assert response.status_code == 400
    assert not adapter.created


def test_wrong_configured_signing_key_is_rejected(tmp_path):
    signer = _settings(tmp_path, key=KEY)
    body = _signed_approval(signer, approval_id="approval-wrong-key")
    _seed_approval(signer, body)
    verifier = _settings(tmp_path, key="different-signing-key")
    client = TestClient(create_app(verifier, kubernetes_adapter=FakeKubernetesAdapter(verifier)))
    assert client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 400


@pytest.mark.parametrize(
    "field,value",
    [
        ("granted_capability", "unknown-capability"),
        ("signature", "not-a-signature"),
        ("expires_at", "2030-01-01T00:00:00Z"),
    ],
)
def test_malformed_approval_material_is_rejected(tmp_path, field, value):
    settings, _, client = _client(tmp_path)
    body = _signed_approval(settings, approval_id=f"approval-malformed-{field}")
    _seed_approval(settings, body)
    changed = {**body, field: value}
    assert client.post("/api/deployments", json=changed, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 400


@pytest.mark.parametrize("field", ["profile", "namespace", "workload", "service_account"])
def test_untrusted_adapter_handle_is_rejected_without_cleanup(tmp_path, field):
    settings = _settings(tmp_path)
    body = _signed_approval(settings, approval_id=f"approval-handle-{field}")
    _seed_approval(settings, body)
    adapter = WrongHandleAdapter(settings, field)
    client = TestClient(create_app(settings, kubernetes_adapter=adapter))
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    assert response.status_code == 502
    assert not adapter.deleted


def test_normal_profile_verification_result_is_rejected_and_trusted_workload_cleaned(tmp_path):
    settings = _settings(tmp_path)
    body = _signed_approval(settings, approval_id="approval-normal-runtime", capability=GrantedCapability.STANDARD_RUNTIME)
    _seed_approval(settings, body)
    adapter = VerificationResultAdapter(settings)
    client = TestClient(create_app(settings, kubernetes_adapter=adapter))
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    assert response.status_code == 502
    assert len(adapter.deleted) == 1
    assert client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 400


def test_activation_failure_cleans_only_workload_and_replay_stays_consumed(tmp_path):
    settings = _settings(tmp_path)
    body = _signed_approval(settings, approval_id="approval-activation-failure")
    _seed_approval(settings, body)
    adapter = FailingActivationAdapter(settings)
    client = TestClient(create_app(settings, kubernetes_adapter=adapter))
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    assert response.status_code == 502
    assert len(adapter.created) == len(adapter.deleted) == 1
    handle = adapter.deleted[0]
    assert handle.namespace == namespace_for_instance(settings.instance_id)
    assert client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"}).status_code == 400
    connection = connect_database(settings.database_path)
    assert connection.execute("SELECT consumed_at FROM security_approvals WHERE id=?", (body["approval_id"],)).fetchone()[0]
    connection.close()


def test_deployment_does_not_expose_fastapi_development_surfaces(tmp_path):
    settings, _, client = _client(tmp_path)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_competition_without_kubernetes_adapter_fails_closed(tmp_path):
    settings = _settings(tmp_path)
    body = _signed_approval(settings, approval_id="approval-no-adapter")
    _seed_approval(settings, body)
    client = TestClient(create_app(settings))
    response = client.post("/api/deployments", json=body, headers={"Authorization": f"Bearer {PORTAL_TOKEN}"})
    assert response.status_code == 503
