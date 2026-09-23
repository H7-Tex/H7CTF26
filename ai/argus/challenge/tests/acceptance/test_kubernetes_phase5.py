"""Opt-in end-to-end Phase 5 test for a real pre-provisioned Kubernetes cluster.

The test intentionally has no fake adapter.  It requires the competition
Deployment settings, a team namespace with both workload ServiceAccounts and
RBAC bindings, and a protected Secret containing base64-encoded ``verification_result``.
"""

import hashlib
import hmac
import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

if os.getenv("ARGUS_RUN_K8S_ACCEPTANCE") != "1":
    pytest.skip("set ARGUS_RUN_K8S_ACCEPTANCE=1 for a real Kubernetes acceptance run", allow_module_level=True)

from argus.config import Settings
from argus.deployment import create_app
from argus.domain import GrantedCapability, canonical_approval_claims
from argus.main import prepare_database
from argus.store import connect_database, encode_timestamp, insert_security_approval


def _approval(settings: Settings, approval_id: str, task_id: str, capability: GrantedCapability) -> dict[str, str]:
    expires_at = encode_timestamp(datetime.now(UTC) + timedelta(minutes=10))
    control_id = os.environ.get("ARGUS_ACCEPTANCE_CONTROL_ID", os.environ.get("ARGUS_BOOTSTRAP_CONTROL_ID", ""))
    if not control_id:
        raise RuntimeError("set ARGUS_ACCEPTANCE_CONTROL_ID to the generated instance control")
    claims = canonical_approval_claims(
        instance_id=settings.instance_id,
        approval_id=approval_id,
        task_id=task_id,
        control_id=control_id,
        target="team-runtime",
        granted_capability=capability,
        expires_at=expires_at,
        key_id=settings.approval_signing_key_id,
    )
    signature = hmac.new(settings.approval_signing_key.encode(), claims.encode(), hashlib.sha256).hexdigest()
    return {
        "approval_id": approval_id,
        "task_id": task_id,
        "control_id": control_id,
        "target": "team-runtime",
        "granted_capability": capability.value,
        "expires_at": expires_at,
        "key_id": settings.approval_signing_key_id,
        "signature": signature,
    }


def test_real_preprovisioned_cluster_enforces_both_profiles():
    settings = Settings.load("deployment")
    prepare_database(settings)
    connection = connect_database(settings.database_path)
    bodies = [
        _approval(settings, "acceptance-standard", "acceptance-task-standard", GrantedCapability.STANDARD_RUNTIME),
        _approval(settings, "acceptance-protected", "acceptance-task-protected", GrantedCapability.PROTECTED_RUNTIME),
    ]
    for body in bodies:
        connection.execute(
            """
            INSERT INTO a2a_tasks
                (instance_id,id,caller_service,origin_subject,owner_class,skill_id,
                 artifact_kind,artifact_json,status)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (settings.instance_id, body["task_id"], "acceptance", "external-partner", "external-partner", "deployment-control-review", "deployment-review", "{}", "completed"),
        )
    connection.commit()
    for body in bodies:
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

    token = settings.credential("portal_deployment")
    headers = {"Authorization": f"Bearer {token}"}
    client = TestClient(create_app(settings))
    normal = client.post("/api/deployments", json=bodies[0], headers=headers)
    protected = client.post("/api/deployments", json=bodies[1], headers=headers)
    assert normal.status_code == 201
    assert protected.status_code == 201
    assert normal.json()["profile"] == "team-namespace"
    assert normal.json()["service_account"] == "argus-worker"
    assert "verification_result" not in normal.json()
    assert "runtime profile isolation verified" in normal.json()["evidence"]["events"]
    assert protected.json()["profile"] == "team-namespace-elevated"
    assert protected.json()["service_account"] == "argus-elevated"
    assert protected.json()["verification_result"]
    assert "runtime profile isolation verified" in protected.json()["evidence"]["events"]
    assert client.post("/api/deployments", json=bodies[1], headers=headers).status_code == 400

    protected_id = protected.json()["deployment_id"]
    assert client.delete(f"/api/deployments/{protected_id}", headers=headers).json()["status"] == "deleted"
