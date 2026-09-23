"""Opt-in acceptance checks for the Windows Docker Desktop + kind topology."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from argus.kubernetes import namespace_for_instance


if os.getenv("ARGUS_RUN_LOCAL_KIND_ACCEPTANCE") != "1":
    pytest.skip(
        "set ARGUS_RUN_LOCAL_KIND_ACCEPTANCE=1 for local kind acceptance",
        allow_module_level=True,
    )


ROOT = Path(__file__).parents[2]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def _can_i(namespace: str, service_account: str, resource: str, name: str) -> str:
    result = _run(
        [
            "kubectl",
            "auth",
            "can-i",
            "get",
            f"{resource}/{name}",
            "--as",
            f"system:serviceaccount:{namespace}:{service_account}",
            "-n",
            namespace,
        ]
    )
    assert result.returncode in {0, 1}, result.stderr
    return result.stdout.strip().lower()


def test_local_kind_deployment_reaches_kubernetes_and_rbac_stays_bounded():
    current = _run(["kubectl", "config", "current-context"])
    assert current.returncode == 0, current.stderr
    assert current.stdout.strip() == "kind-argus"

    instance_id = os.getenv("INSTANCE_ID", "team-a")
    namespace = namespace_for_instance(instance_id, os.getenv("ARGUS_K8S_NAMESPACE_PREFIX", "argus"))

    assert _can_i(namespace, "argus-worker", "configmap", "argus-public") == "yes"
    assert _can_i(namespace, "argus-worker", "secret", "argus-protected") == "no"
    assert _can_i(namespace, "argus-elevated", "secret", "argus-protected") == "yes"
    assert _can_i(namespace, "argus-elevated", "configmap", "argus-public") == "no"
    assert _can_i(namespace, "argus-elevated", "secret", "not-argus-protected") == "no"
    assert _can_i(namespace, "argus-deployer", "secret", "argus-protected") == "no"

    probe = """
from argus.config import Settings
from argus.kubernetes import DeploymentProfile, HttpKubernetesAdapter

settings = Settings.load("deployment")
adapter = HttpKubernetesAdapter(settings)
for profile, suffix in (
    (DeploymentProfile.TEAM_NAMESPACE, "normal"),
    (DeploymentProfile.TEAM_NAMESPACE_ELEVATED, "elevated"),
):
    workload = None
    try:
        workload = adapter.create_workload(settings.instance_id, f"local-kind-probe-{suffix}", profile)
        readiness = adapter.wait_ready(workload, 120)
        assert readiness.ready
        evidence = adapter.snapshot_evidence(workload, readiness)
        assert "runtime profile isolation verified" in evidence.event_summary
        if profile is DeploymentProfile.TEAM_NAMESPACE:
            assert evidence.verification_result is None
        else:
            assert evidence.verification_result
    finally:
        if workload is not None:
            adapter.delete_workload(workload)
print("kubernetes-reachable")
""".strip()
    result = _run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.dev.yml",
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python",
            "deployment",
            "-c",
            probe,
        ]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("kubernetes-reachable")
