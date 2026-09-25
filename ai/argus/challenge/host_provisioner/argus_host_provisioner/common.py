from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping

from argus.kubernetes import DeploymentProfile, build_profile_manifest


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# on GKE the workers run in the gVisor sandbox like the challenge pods, instead of
# landing on the platform nodes with runc. empty = cluster default (kind/local).
RUNTIME_CLASS = os.getenv("ARGUS_RUNTIME_CLASS", "")


def parse_create_request(value: object) -> tuple[str, DeploymentProfile]:
    if not isinstance(value, Mapping) or set(value) != {"deployment_id", "profile"}:
        raise ValueError("invalid workload request")
    deployment_id, profile_value = value["deployment_id"], value["profile"]
    if not isinstance(deployment_id, str) or not _ID.fullmatch(deployment_id):
        raise ValueError("invalid workload request")
    try:
        profile = DeploymentProfile(profile_value)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid workload request") from exc
    return deployment_id, profile


def workload(instance_id: str, deployment_id: str, profile: DeploymentProfile, namespace: str, worker_image: str, elevated_image: str) -> dict:
    if not _ID.fullmatch(instance_id) or not _ID.fullmatch(deployment_id):
        raise ValueError("invalid workload identity")
    image = elevated_image if profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED else worker_image
    manifest = build_profile_manifest(
        instance_id=instance_id,
        deployment_id=deployment_id,
        profile=profile,
        workload_image=image,
        namespace_prefix="argus",
    )["objects"][0]
    manifest["metadata"]["namespace"] = namespace
    for labels in (manifest["metadata"]["labels"], manifest["spec"]["template"]["metadata"]["labels"]):
        labels["argus.instance"] = namespace
    manifest["spec"]["selector"]["matchLabels"]["argus.instance"] = namespace
    manifest["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
    if RUNTIME_CLASS:
        manifest["spec"]["template"]["spec"]["runtimeClassName"] = RUNTIME_CLASS
    return manifest


def workload_name(instance_id: str, deployment_id: str) -> str:
    manifest = build_profile_manifest(
        instance_id=instance_id,
        deployment_id=deployment_id,
        profile=DeploymentProfile.TEAM_NAMESPACE,
        workload_image="argus/worker:fixed",
        namespace_prefix="argus",
    )
    return manifest["objects"][0]["metadata"]["name"]


def runtime_label(instance_id: str, deployment_id: str) -> str:
    return "d-" + hashlib.sha256(f"{instance_id}\0{deployment_id}".encode()).hexdigest()[:10]
