"""The fixed, non-player-controlled ARGUS runtime workload."""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .kubernetes import DeploymentProfile, namespace_authority


API_ROOT = "https://kubernetes.default.svc"
SERVICE_ACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
MAX_RESPONSE_BYTES = 64 * 1024

_FORBIDDEN_RESOURCES = {
    DeploymentProfile.TEAM_NAMESPACE: ("secrets", "argus-protected"),
    DeploymentProfile.TEAM_NAMESPACE_ELEVATED: ("configmaps", "argus-public"),
}


def _profile() -> DeploymentProfile:
    try:
        return DeploymentProfile(os.environ["ARGUS_RUNTIME_PROFILE"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("trusted runtime profile is unavailable") from exc


def _request_resource(namespace: str, resource: str, resource_name: str) -> dict:
    token = open(f"{SERVICE_ACCOUNT_DIR}/token", encoding="utf-8").read().strip()
    context = ssl.create_default_context(cafile=f"{SERVICE_ACCOUNT_DIR}/ca.crt")
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/{resource}/{quote(resource_name, safe='')}"
    request = Request(
        f"{API_ROOT}{path}",
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urlopen(request, context=context, timeout=10) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("trusted runtime resource is too large")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError("trusted runtime resource is invalid")
    metadata = value.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("namespace") != namespace:
        raise RuntimeError("trusted runtime resource namespace mismatch")
    if metadata.get("name") != resource_name:
        raise RuntimeError("trusted runtime resource name mismatch")
    return value


def _read_resource(profile: DeploymentProfile, namespace: str) -> dict:
    authority = namespace_authority(profile)
    resource = "configmaps" if authority.resource_kind == "ConfigMap" else "secrets"
    return _request_resource(namespace, resource, authority.resource_name)


def _expect_forbidden_resource(namespace: str, resource: str, resource_name: str) -> None:
    token = open(f"{SERVICE_ACCOUNT_DIR}/token", encoding="utf-8").read().strip()
    context = ssl.create_default_context(cafile=f"{SERVICE_ACCOUNT_DIR}/ca.crt")
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/{resource}/{quote(resource_name, safe='')}"
    request = Request(
        f"{API_ROOT}{path}",
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request, context=context, timeout=10) as response:
            raise RuntimeError("trusted runtime resource was unexpectedly accessible")
    except HTTPError as exc:
        try:
            if exc.code != 403:
                raise RuntimeError("trusted runtime denial check failed") from exc
        finally:
            exc.close()


def run() -> dict[str, object]:
    profile = _profile()
    namespace = open(f"{SERVICE_ACCOUNT_DIR}/namespace", encoding="utf-8").read().strip()
    if not namespace:
        raise RuntimeError("trusted runtime namespace is unavailable")
    forbidden_resource, forbidden_name = _FORBIDDEN_RESOURCES[profile]
    _expect_forbidden_resource(namespace, forbidden_resource, forbidden_name)
    resource = namespace_authority(profile).resource_name
    value = _read_resource(profile, namespace)
    verification_result: str | None = None
    if profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED:
        data = value.get("data")
        encoded = data.get("verification_result") if isinstance(data, dict) else None
        if not isinstance(encoded, str):
            raise RuntimeError("verification result is unavailable")
        try:
            verification_result = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("verification result is invalid") from exc
        if not verification_result or len(verification_result.encode("utf-8")) > 4_096:
            raise RuntimeError("verification result is invalid")
    return {
        "kind": "argus-runtime-result",
        "profile": profile.value,
        "resource": resource,
        "status": "ok",
        "isolation_verified": True,
        "verification_result": verification_result,
    }


def _emit_result(result: dict[str, object]) -> None:
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")), flush=True)


def main() -> None:
    _emit_result(run())
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
