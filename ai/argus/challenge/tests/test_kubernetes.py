from copy import deepcopy
import json

import pytest

from argus.domain import GrantedCapability
import argus.kubernetes as kubernetes
from argus.kubernetes import (
    DeploymentProfile,
    HttpKubernetesAdapter,
    ReadinessResult,
    WorkloadHandle,
    build_profile_manifest,
    deployment_label_for_id,
    ensure_trusted_namespace,
    namespace_authority,
    namespace_for_instance,
    profile_for_capability,
    validate_runtime_result,
    validate_shared_worker_spec,
    validate_trusted_profile_manifest,
    workload_name_for_deployment,
)


WORKLOAD_IMAGE = "argus/workload:foundation"


def test_namespace_derivation_and_collision_resistance():
    assert namespace_for_instance("team-a") == "argus-team-a"
    assert namespace_for_instance("team_a") != namespace_for_instance("team-a")
    assert namespace_for_instance("TEAM-A") != namespace_for_instance("team-a")
    ensure_trusted_namespace("team-a", "argus-team-a")
    with pytest.raises(ValueError):
        ensure_trusted_namespace("team-a", "argus-team-b")


def test_workload_names_are_stable_bounded_and_deployment_specific():
    first = workload_name_for_deployment("team-a", "deploy-1")
    assert first == workload_name_for_deployment("team-a", "deploy-1")
    assert first != workload_name_for_deployment("team-a", "deploy-2")
    assert len(first) <= 63
    assert first.startswith("argus-workload-")
    with pytest.raises(ValueError):
        workload_name_for_deployment("bad/id", "deploy-1")
    with pytest.raises(ValueError):
        workload_name_for_deployment("team-a", "bad/id")


def test_capability_maps_only_to_trusted_profiles():
    assert profile_for_capability(GrantedCapability.STANDARD_RUNTIME) is DeploymentProfile.TEAM_NAMESPACE
    assert profile_for_capability(GrantedCapability.PROTECTED_RUNTIME) is DeploymentProfile.TEAM_NAMESPACE_ELEVATED
    with pytest.raises(ValueError):
        profile_for_capability("team-namespace-elevated")


def test_deployment_labels_are_deterministic_and_unique():
    first = deployment_label_for_id("team-a", "deploy-a")
    assert first == deployment_label_for_id("team-a", "deploy-a")
    assert first != deployment_label_for_id("team-a", "deploy-b")
    assert first.startswith("d-")
    assert len(first) <= 63


def test_external_rbac_authority_is_explicit_and_resource_scoped():
    normal = namespace_authority(DeploymentProfile.TEAM_NAMESPACE)
    assert normal.service_account == "argus-worker"
    assert (normal.resource_kind, normal.resource_name) == ("ConfigMap", "argus-public")
    assert normal.verbs == ("get",)
    assert normal.resource_names == ("argus-public",)

    elevated = namespace_authority(DeploymentProfile.TEAM_NAMESPACE_ELEVATED)
    assert elevated.service_account == "argus-elevated"
    assert (elevated.resource_kind, elevated.resource_name) == ("Secret", "argus-protected")
    assert elevated.verbs == ("get",)
    assert elevated.resource_names == ("argus-protected",)


def test_only_trusted_profiles_build_one_known_deployment():
    normal = build_profile_manifest(
        instance_id="team-a",
        deployment_id="deployment-1",
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image=WORKLOAD_IMAGE,
    )
    elevated = build_profile_manifest(
        instance_id="team-a",
        deployment_id="deployment-1",
        profile=DeploymentProfile.TEAM_NAMESPACE_ELEVATED,
        workload_image=WORKLOAD_IMAGE,
    )
    assert [item["kind"] for item in normal["objects"]] == ["Deployment"]
    assert normal["objects"][0]["spec"]["template"]["spec"]["serviceAccountName"] == "argus-worker"
    assert elevated["objects"][0]["spec"]["template"]["spec"]["serviceAccountName"] == "argus-elevated"
    container = normal["objects"][0]["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["python", "-m", "argus.workload"]
    assert container["env"] == [{"name": "ARGUS_RUNTIME_PROFILE", "value": "team-namespace"}]
    assert normal["objects"][0]["spec"]["selector"]["matchLabels"] == {
        "argus.instance": "argus-team-a",
        "argus.deployment": deployment_label_for_id("team-a", "deployment-1"),
    }
    validate_trusted_profile_manifest(
        normal,
        instance_id="team-a",
        deployment_id="deployment-1",
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image=WORKLOAD_IMAGE,
    )
    with pytest.raises(ValueError):
        build_profile_manifest(
            instance_id="team-a",
            deployment_id="deployment-1",
            profile="team-namespace",
            workload_image=WORKLOAD_IMAGE,
        )


def test_profile_output_has_no_host_or_cluster_privilege():
    for profile in DeploymentProfile:
        manifest = build_profile_manifest(
            instance_id="team-a",
            deployment_id="deployment-1",
            profile=profile,
            workload_image=WORKLOAD_IMAGE,
        )
        text = repr(manifest).lower()
        for forbidden in ("privileged", "hostpid", "hostipc", "hostnetwork", "hostpath", "clusterrole"):
            assert forbidden not in text
        assert all(
            obj.get("metadata", {}).get("namespace") == "argus-team-a"
            for obj in manifest["objects"]
        )
        assert all(
            obj.get("kind") not in {"ClusterRole", "ClusterRoleBinding", "Namespace", "Role", "RoleBinding", "ServiceAccount"}
            for obj in manifest["objects"]
        )


def test_same_profile_deployments_have_non_overlapping_selectors():
    manifest_a = build_profile_manifest(
        instance_id="team-a",
        deployment_id="deploy-a",
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image=WORKLOAD_IMAGE,
    )
    manifest_b = build_profile_manifest(
        instance_id="team-a",
        deployment_id="deploy-b",
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image=WORKLOAD_IMAGE,
    )
    deployment_a = manifest_a["objects"][0]
    deployment_b = manifest_b["objects"][0]
    assert deployment_a["metadata"]["name"] != deployment_b["metadata"]["name"]
    selector_a = deployment_a["spec"]["selector"]["matchLabels"]
    selector_b = deployment_b["spec"]["selector"]["matchLabels"]
    assert selector_a != selector_b
    assert deployment_a["spec"]["template"]["metadata"]["labels"] != deployment_b["spec"]["template"]["metadata"]["labels"]
    assert selector_a["argus.deployment"] != selector_b["argus.deployment"]
    assert manifest_a == build_profile_manifest(
        instance_id="team-a",
        deployment_id="deploy-a",
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image=WORKLOAD_IMAGE,
    )
def test_profile_tampering_image_namespace_and_service_account_is_rejected():
    manifest = deepcopy(
        build_profile_manifest(
            instance_id="team-a",
            deployment_id="deployment-1",
            profile=DeploymentProfile.TEAM_NAMESPACE,
            workload_image=WORKLOAD_IMAGE,
        )
    )
    for mutate in (
        lambda value: value["objects"][0]["metadata"].__setitem__("namespace", "other-team"),
        lambda value: value["objects"][0]["spec"]["template"]["spec"].__setitem__("serviceAccountName", "argus-elevated"),
        lambda value: value["objects"][0]["spec"]["template"]["spec"]["containers"][0].__setitem__("image", "attacker/image:latest"),
    ):
        changed = deepcopy(manifest)
        mutate(changed)
        with pytest.raises(ValueError):
            validate_trusted_profile_manifest(
                changed,
                instance_id="team-a",
                deployment_id="deployment-1",
                profile=DeploymentProfile.TEAM_NAMESPACE,
                workload_image=WORKLOAD_IMAGE,
            )


def test_profile_builder_rejects_untrusted_image_reference():
    with pytest.raises(ValueError):
        build_profile_manifest(
            instance_id="team-a",
            deployment_id="deployment-1",
            profile=DeploymentProfile.TEAM_NAMESPACE,
            workload_image="attacker/image with spaces:latest",
        )


def test_shared_worker_deny_list_is_defense_in_depth():
    with pytest.raises(ValueError):
        validate_shared_worker_spec({"spec": {"hostPath": {}}})


def test_runtime_result_is_exact_and_profile_bound():
    normal = {
        "kind": "argus-runtime-result",
        "profile": "team-namespace",
        "resource": "argus-public",
        "status": "ok",
        "isolation_verified": True,
        "verification_result": None,
    }
    elevated = {
        "kind": "argus-runtime-result",
        "profile": "team-namespace-elevated",
        "resource": "argus-protected",
        "status": "ok",
        "isolation_verified": True,
        "verification_result": "flag",
    }
    assert validate_runtime_result(normal, DeploymentProfile.TEAM_NAMESPACE) is None
    assert validate_runtime_result(elevated, DeploymentProfile.TEAM_NAMESPACE_ELEVATED) == "flag"
    invalid = (
        {key: value for key, value in normal.items() if key != "isolation_verified"},
        {**normal, "isolation_verified": False},
        {**normal, "isolation_verified": "true"},
        {**normal, "extra": "rejected"},
        {**normal, "resource": "argus-protected"},
        {**normal, "profile": "team-namespace-elevated"},
        {**normal, "status": "failed"},
        {**normal, "verification_result": "protected"},
        {**elevated, "verification_result": ""},
        {**elevated, "verification_result": "x" * 4_097},
    )
    for result in invalid:
        with pytest.raises(ValueError):
            validate_runtime_result(
                result,
                DeploymentProfile.TEAM_NAMESPACE_ELEVATED
                if result.get("profile") == "team-namespace-elevated"
                else DeploymentProfile.TEAM_NAMESPACE,
            )


def test_http_adapter_retries_empty_runtime_result_until_workload_emits_it(monkeypatch):
    adapter = object.__new__(HttpKubernetesAdapter)
    adapter._result_timeout_seconds = 1
    workload = WorkloadHandle(
        instance_id="team-a",
        deployment_id="deployment-1",
        namespace=namespace_for_instance("team-a"),
        workload=workload_name_for_deployment("team-a", "deployment-1"),
        profile=DeploymentProfile.TEAM_NAMESPACE,
        service_account="argus-worker",
        manifest_hash="a" * 64,
    )
    adapter._json = lambda *_args: {
        "items": [
            {
                "metadata": {
                    "name": "argus-workload-pod",
                    "namespace": workload.namespace,
                    "labels": {
                        "argus.instance": workload.namespace,
                        "argus.deployment": deployment_label_for_id("team-a", "deployment-1"),
                        "argus.profile": workload.profile.value,
                    },
                },
                "spec": {"serviceAccountName": "argus-worker"},
            }
        ]
    }
    responses = iter(
        [
            b"\n",
            json.dumps(
                {
                    "kind": "argus-runtime-result",
                    "profile": "team-namespace",
                    "resource": "argus-public",
                    "status": "ok",
                    "isolation_verified": True,
                    "verification_result": None,
                }
            ).encode("utf-8"),
        ]
    )
    adapter._request_bytes = lambda *_args: next(responses)
    monkeypatch.setattr(kubernetes.time, "sleep", lambda _seconds: None)

    evidence = adapter.snapshot_evidence(workload, ReadinessResult(True, "ready", "2026-01-01T00:00:00.000000Z"))
    assert evidence.verification_result is None
    assert evidence.event_summary == ("workload ready", "runtime profile isolation verified")
