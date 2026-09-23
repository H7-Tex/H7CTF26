import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1] / "host_provisioner"))

from argus.kubernetes import DeploymentProfile
from argus_host_provisioner import broker
from argus_host_provisioner.common import parse_create_request, workload


@pytest.mark.parametrize(
    "payload",
    [
        {"deployment_id": "d-1", "profile": "team-namespace", "namespace": "other"},
        {"deployment_id": "d-1", "profile": "team-namespace", "image": "evil"},
        {"deployment_id": "d-1", "profile": "team-namespace", "manifest": {}},
        {"deployment_id": "d-1", "profile": "team-namespace", "command": ["sh"]},
        {"deployment_id": "../secret", "profile": "team-namespace"},
        {"deployment_id": "d-1", "profile": "cluster-admin"},
        [],
    ],
)
def test_broker_rejects_unbounded_create_fields(payload):
    with pytest.raises(ValueError):
        parse_create_request(payload)


def test_broker_workload_builder_fixes_namespace_image_and_runtime_bounds():
    result = workload(
        "team-a",
        "deployment-1",
        DeploymentProfile.TEAM_NAMESPACE_ELEVATED,
        "anvil-namespace",
        "registry/worker@sha256:" + "a" * 64,
        "registry/elevated@sha256:" + "b" * 64,
    )
    assert result["metadata"]["namespace"] == "anvil-namespace"
    container = result["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "registry/elevated@sha256:" + "b" * 64
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["resources"]["limits"] == {"cpu": "100m", "memory": "64Mi"}


def test_broker_http_auth_and_create_schema_reject_player_authority(monkeypatch):
    monkeypatch.setattr(broker, "NAMESPACE", "anvil-instance-a")
    monkeypatch.setattr(broker, "INSTANCE_ID", "team-a")
    monkeypatch.setattr(broker, "TOKEN", "derived-broker-token")
    monkeypatch.setattr(broker, "WORKER_IMAGE", "registry/worker@sha256:" + "a" * 64)
    monkeypatch.setattr(broker, "ELEVATED_IMAGE", "registry/elevated@sha256:" + "b" * 64)
    applied = []

    def fake_kube(method, path, body=None):
        applied.append((method, path, body))
        return {}

    monkeypatch.setattr(broker, "_kube", fake_kube)
    client = TestClient(broker.app)
    denied = client.post("/v1/workloads", json={"deployment_id": "deployment-1", "profile": "team-namespace"})
    assert denied.status_code == 401

    headers = {"Authorization": "Bearer derived-broker-token"}
    rejected = client.post(
        "/v1/workloads",
        headers=headers,
        json={"deployment_id": "deployment-1", "profile": "team-namespace", "namespace": "other"},
    )
    assert rejected.status_code == 400
    assert not applied

    created = client.post(
        "/v1/workloads",
        headers=headers,
        json={"deployment_id": "deployment-1", "profile": "team-namespace-elevated"},
    )
    assert created.status_code == 200 and created.json() == {"created": True}
    method, path, manifest = applied[0]
    assert method == "POST"
    assert path == "/apis/apps/v1/namespaces/anvil-instance-a/deployments"
    assert manifest["metadata"]["namespace"] == "anvil-instance-a"
    assert manifest["spec"]["template"]["spec"]["containers"][0]["image"] == "registry/elevated@sha256:" + "b" * 64
