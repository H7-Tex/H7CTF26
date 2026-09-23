"""Trusted, namespace-scoped Kubernetes contract for Project ARGUS.

The profile builder is the primary safety boundary. The deny-list validator is
defense in depth for future adapter/controller checks, not tenant isolation.
This foundation module performs no cluster calls and accepts no raw manifests.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .domain import GrantedCapability
from .store import canonical_json, utc_now, encode_timestamp


DEFAULT_NAMESPACE_PREFIX = "argus"
MAX_NAMESPACE_LENGTH = 63
MAX_RESOURCE_NAME_LENGTH = 63
MAX_EVIDENCE_EVENTS = 32
MAX_RUNTIME_RESULT_BYTES = 8_192
MAX_KUBERNETES_RESPONSE_BYTES = 256_000

_INSTANCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DEPLOYMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DNS_LABEL = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9./:_-]+(?:@sha256:[0-9a-f]{64})?$")


class DeploymentProfile(str, Enum):
    """The only profile identities accepted by the trusted builder."""

    TEAM_NAMESPACE = "team-namespace"
    TEAM_NAMESPACE_ELEVATED = "team-namespace-elevated"


def profile_for_capability(capability: GrantedCapability) -> DeploymentProfile:
    """Map Security authority to a trusted runtime profile; never accept a fallback."""

    if not isinstance(capability, GrantedCapability):
        raise ValueError("granted_capability must be a known GrantedCapability")
    if capability is GrantedCapability.STANDARD_RUNTIME:
        return DeploymentProfile.TEAM_NAMESPACE
    if capability is GrantedCapability.PROTECTED_RUNTIME:
        return DeploymentProfile.TEAM_NAMESPACE_ELEVATED
    raise ValueError("unsupported granted capability")


@dataclass(frozen=True, slots=True)
class NamespaceAuthority:
    """Pre-provisioned, resourceName-scoped authority for one profile."""

    service_account: str
    resource_kind: str
    resource_name: str
    verbs: tuple[str, ...] = ("get",)
    resource_names: tuple[str, ...] = ()


def namespace_authority(profile: DeploymentProfile) -> NamespaceAuthority:
    """Describe the external RBAC contract without creating RBAC objects."""

    if not isinstance(profile, DeploymentProfile):
        raise ValueError("deployment profile must be a trusted DeploymentProfile")
    if profile is DeploymentProfile.TEAM_NAMESPACE:
        return NamespaceAuthority(
            service_account="argus-worker",
            resource_kind="ConfigMap",
            resource_name="argus-public",
            resource_names=("argus-public",),
        )
    if profile is DeploymentProfile.TEAM_NAMESPACE_ELEVATED:
        return NamespaceAuthority(
            service_account="argus-elevated",
            resource_kind="Secret",
            resource_name="argus-protected",
            resource_names=("argus-protected",),
        )
    raise ValueError("unsupported deployment profile")


def _validate_prefix(prefix: str) -> str:
    prefix = prefix.strip().lower()
    if not prefix or len(prefix) > 20 or not _DNS_LABEL.fullmatch(prefix):
        raise ValueError("namespace prefix must be a short DNS label")
    return prefix


def namespace_for_instance(instance_id: str, prefix: str = DEFAULT_NAMESPACE_PREFIX) -> str:
    """Derive one deterministic DNS namespace from trusted instance state."""

    if not isinstance(instance_id, str) or not _INSTANCE_ID.fullmatch(instance_id):
        raise ValueError("instance_id is not a valid trusted ARGUS identifier")
    prefix = _validate_prefix(prefix)
    lowered = instance_id.lower()
    normalized = re.sub(r"[^a-z0-9-]+", "-", lowered).strip("-")
    if not normalized:
        raise ValueError("instance_id cannot produce a Kubernetes namespace")

    digest = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()[:8]
    changed = normalized != lowered or instance_id != lowered
    suffix = f"{normalized}-{digest}" if changed else normalized
    available = MAX_NAMESPACE_LENGTH - len(prefix) - 1
    if len(suffix) > available:
        suffix = f"{suffix[: available - 9].rstrip('-')}-{digest}"
    namespace = f"{prefix}-{suffix}".strip("-")
    if not _DNS_LABEL.fullmatch(namespace) or len(namespace) > MAX_NAMESPACE_LENGTH:
        raise ValueError("derived namespace is not a valid Kubernetes DNS label")
    return namespace


def ensure_trusted_namespace(instance_id: str, namespace: str, prefix: str = DEFAULT_NAMESPACE_PREFIX) -> None:
    """Reject a namespace that was not derived from trusted instance state."""

    if namespace != namespace_for_instance(instance_id, prefix):
        raise ValueError("namespace does not match the trusted instance")


def workload_name_for_deployment(instance_id: str, deployment_id: str) -> str:
    """Derive a stable, collision-resistant workload name from trusted state."""

    if not isinstance(instance_id, str) or not _INSTANCE_ID.fullmatch(instance_id):
        raise ValueError("instance_id is not a valid trusted ARGUS identifier")
    if not isinstance(deployment_id, str) or not _DEPLOYMENT_ID.fullmatch(deployment_id):
        raise ValueError("deployment_id must be a bounded trusted identifier")
    normalized = re.sub(r"[^a-z0-9-]+", "-", deployment_id.lower()).strip("-")
    digest = hashlib.sha256(f"{instance_id}\0{deployment_id}".encode("utf-8")).hexdigest()[:10]
    prefix = "argus-workload-"
    available = MAX_RESOURCE_NAME_LENGTH - len(prefix) - len(digest) - 1
    slug = normalized[:available].rstrip("-")
    name = f"{prefix}{slug}-{digest}"
    if not _DNS_LABEL.fullmatch(name):
        raise ValueError("derived workload name is not a valid Kubernetes DNS label")
    return name


def deployment_label_for_id(instance_id: str, deployment_id: str) -> str:
    """Derive a bounded label that isolates each workload selector."""

    if not isinstance(instance_id, str) or not _INSTANCE_ID.fullmatch(instance_id):
        raise ValueError("instance_id is not a valid trusted ARGUS identifier")
    if not isinstance(deployment_id, str) or not _DEPLOYMENT_ID.fullmatch(deployment_id):
        raise ValueError("deployment_id must be a bounded trusted identifier")
    digest = hashlib.sha256(f"{instance_id}\0{deployment_id}".encode("utf-8")).hexdigest()[:10]
    return f"d-{digest}"


def _build_profile_manifest(
    *,
    instance_id: str,
    deployment_id: str,
    profile: DeploymentProfile,
    namespace_prefix: str,
    workload_image: str,
) -> dict[str, Any]:
    namespace = namespace_for_instance(instance_id, namespace_prefix)
    service_account = namespace_authority(profile).service_account
    workload = workload_name_for_deployment(instance_id, deployment_id)
    deployment_label = deployment_label_for_id(instance_id, deployment_id)
    if not _IMAGE_REFERENCE.fullmatch(workload_image):
        raise ValueError("workload image is not a valid trusted image reference")
    labels = {
        "argus.instance": namespace,
        "argus.profile": profile.value,
        "argus.deployment": deployment_label,
    }
    selector_labels = {"argus.instance": namespace, "argus.deployment": deployment_label}
    return {
        "objects": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": workload, "namespace": namespace, "labels": labels},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": selector_labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "serviceAccountName": service_account,
                            "automountServiceAccountToken": True,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "workload",
                                    "image": workload_image,
                                    "imagePullPolicy": "IfNotPresent",
                                    "command": ["python", "-m", "argus.workload"],
                                    "env": [
                                        {
                                            "name": "ARGUS_RUNTIME_PROFILE",
                                            "value": profile.value,
                                        }
                                    ],
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "resources": {
                                        "requests": {"cpu": "10m", "memory": "16Mi"},
                                        "limits": {"cpu": "100m", "memory": "64Mi"},
                                    },
                                }
                            ],
                        },
                    },
                },
            }
        ]
    }


def build_profile_manifest(
    *,
    instance_id: str,
    deployment_id: str,
    profile: DeploymentProfile,
    workload_image: str,
    namespace_prefix: str = DEFAULT_NAMESPACE_PREFIX,
) -> Mapping[str, Any]:
    """Build one trusted Deployment from Deployment-owned trusted image state.

    Only the future Deployment role may pass ``settings.trusted_workload_image``;
    public requests must never supply an image or image reference.
    """

    return _build_profile_manifest(
        instance_id=instance_id,
        deployment_id=deployment_id,
        profile=profile,
        namespace_prefix=namespace_prefix,
        workload_image=workload_image,
    )


def validate_trusted_profile_manifest(
    manifest: Mapping[str, Any],
    *,
    instance_id: str,
    deployment_id: str,
    profile: DeploymentProfile,
    workload_image: str,
    namespace_prefix: str = DEFAULT_NAMESPACE_PREFIX,
) -> None:
    """Ensure a manifest is exactly the output of the trusted builder."""

    expected = _build_profile_manifest(
        instance_id=instance_id,
        deployment_id=deployment_id,
        profile=profile,
        namespace_prefix=namespace_prefix,
        workload_image=workload_image,
    )
    if manifest != expected:
        raise ValueError("manifest is not an unmodified trusted ARGUS profile")


_BOOLEAN_RESTRICTIONS = frozenset({"privileged", "hostpid", "hostipc", "hostnetwork"})
_OBJECT_RESTRICTIONS = frozenset(
    {
        "hostpath",
        "devicemounts",
        "devices",
        "runtimesocket",
        "runtimesockets",
        "dockersocket",
        "containersocket",
        "clusterrole",
        "clusterrolebinding",
    }
)
_FORBIDDEN_KINDS = frozenset(
    {"clusterrole", "clusterrolebinding", "namespace", "node", "persistentvolume"}
)


def validate_shared_worker_spec(spec: Mapping[str, Any]) -> None:
    """Defense-in-depth check; this is not the tenant-isolation boundary."""

    if not isinstance(spec, Mapping):
        raise ValueError("Kubernetes profile data must be an object")

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized in _BOOLEAN_RESTRICTIONS and child:
                    raise ValueError(f"shared-worker profile rejects {key}")
                if normalized in _OBJECT_RESTRICTIONS:
                    raise ValueError(f"shared-worker profile rejects {key}")
                if normalized == "kind" and str(child).lower() in _FORBIDDEN_KINDS:
                    raise ValueError("shared-worker profile rejects cluster-scoped resources")
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(spec)


@dataclass(frozen=True, slots=True)
class WorkloadHandle:
    instance_id: str
    deployment_id: str
    namespace: str
    workload: str
    profile: DeploymentProfile
    service_account: str
    manifest_hash: str


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    ready: bool
    status: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """Safe, bounded deployment evidence; never a Kubernetes secret dump."""

    namespace: str
    workload: str
    profile: DeploymentProfile
    service_account: str
    manifest_hash: str
    status: str
    event_summary: tuple[str, ...] = ()
    verification_result: str | None = None

    def __post_init__(self) -> None:
        if len(self.event_summary) > MAX_EVIDENCE_EVENTS:
            raise ValueError("Kubernetes evidence event history exceeds its limit")
        if any(len(event.encode("utf-8")) > 1_024 for event in self.event_summary):
            raise ValueError("Kubernetes evidence event is too large")
        if self.verification_result is not None and (
            not isinstance(self.verification_result, str)
            or not self.verification_result
            or len(self.verification_result.encode("utf-8")) > 4_096
        ):
            raise ValueError("Kubernetes verification result is invalid")


class KubernetesAdapter(Protocol):
    """The only cluster operations the Deployment role will need."""

    def namespace_for_instance(self, instance_id: str) -> str:
        ...

    def create_workload(
        self, instance_id: str, deployment_id: str, profile: DeploymentProfile
    ) -> WorkloadHandle:
        ...

    def wait_ready(self, workload: WorkloadHandle, timeout_seconds: int) -> ReadinessResult:
        ...

    def snapshot_evidence(
        self, workload: WorkloadHandle, readiness: ReadinessResult
    ) -> EvidenceSnapshot:
        ...

    def delete_workload(self, workload: WorkloadHandle) -> None:
        ...

    def request_namespace_cleanup(self, instance_id: str) -> None:
        """Request cleanup; an external CTF janitor remains authoritative."""

        ...


def validate_runtime_result(value: Any, profile: DeploymentProfile) -> str | None:
    """Validate the one fixed result object emitted by the trusted workload."""

    if not isinstance(value, Mapping) or set(value) != {
        "kind",
        "profile",
        "resource",
        "status",
        "isolation_verified",
        "verification_result",
    }:
        raise ValueError("workload result is not the bounded ARGUS result format")
    authority = namespace_authority(profile)
    if (
        value["kind"] != "argus-runtime-result"
        or value["profile"] != profile.value
        or value["resource"] != authority.resource_name
        or value["status"] != "ok"
        or value["isolation_verified"] is not True
    ):
        raise ValueError("workload result does not match the trusted profile")
    verification_result = value["verification_result"]
    if profile is DeploymentProfile.TEAM_NAMESPACE:
        if verification_result is not None:
            raise ValueError("normal workload returned a verification result")
        return None
    if not isinstance(verification_result, str) or not verification_result or len(verification_result.encode("utf-8")) > 4_096:
        raise ValueError("restricted workload verification result is invalid")
    return verification_result


class KubernetesAdapterError(RuntimeError):
    """A bounded, non-sensitive Kubernetes adapter failure."""


class HttpKubernetesAdapter:
    """Narrow HTTPS client for the pre-provisioned ARGUS Kubernetes contract."""

    def __init__(self, settings: Any):
        api_url = getattr(settings, "k8s_api_url", "")
        credential = getattr(settings, "k8s_credential", "")
        ca_file = getattr(settings, "k8s_ca_file", None)
        if not getattr(settings, "k8s_enabled", False) or not api_url or not credential or ca_file is None:
            raise ValueError("competition Kubernetes configuration is unavailable")
        if urlparse(api_url).scheme != "https":
            raise ValueError("Kubernetes API access requires HTTPS")
        try:
            self._context = ssl.create_default_context(cafile=str(ca_file))
        except (OSError, ssl.SSLError) as exc:
            raise ValueError("Kubernetes CA configuration is invalid") from exc
        self._base_url = api_url.rstrip("/")
        self._credential = credential
        self._namespace_prefix = settings.k8s_namespace_prefix
        self._image = settings.trusted_workload_image
        self._result_timeout_seconds = max(
            1, min(int(getattr(settings, "k8s_ready_timeout_seconds", 120)), 3_600)
        )

    def namespace_for_instance(self, instance_id: str) -> str:
        return namespace_for_instance(instance_id, self._namespace_prefix)

    def _url(self, path: str) -> str:
        if not path.startswith("/") or ".." in path:
            raise KubernetesAdapterError("invalid trusted Kubernetes path")
        return f"{self._base_url}{path}"

    def _request_bytes(self, method: str, path: str, body: bytes | None = None) -> bytes:
        request = Request(
            self._url(path),
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._credential}",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urlopen(request, context=self._context, timeout=15) as response:
                data = response.read(MAX_KUBERNETES_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise KubernetesAdapterError("Kubernetes operation failed") from exc
        if len(data) > MAX_KUBERNETES_RESPONSE_BYTES:
            raise KubernetesAdapterError("Kubernetes response is too large")
        return data

    def _json(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        payload = canonical_json(body).encode("utf-8") if body is not None else None
        try:
            value = json.loads(self._request_bytes(method, path, payload))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KubernetesAdapterError("Kubernetes returned invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise KubernetesAdapterError("Kubernetes returned an invalid object")
        return value

    def create_workload(self, instance_id: str, deployment_id: str, profile: DeploymentProfile) -> WorkloadHandle:
        namespace = self.namespace_for_instance(instance_id)
        workload = workload_name_for_deployment(instance_id, deployment_id)
        manifest = build_profile_manifest(
            instance_id=instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=self._image,
            namespace_prefix=self._namespace_prefix,
        )
        validate_trusted_profile_manifest(
            manifest,
            instance_id=instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=self._image,
            namespace_prefix=self._namespace_prefix,
        )
        validate_shared_worker_spec(manifest)
        self._json(
            "POST",
            f"/apis/apps/v1/namespaces/{quote(namespace, safe='')}/deployments",
            manifest["objects"][0],
        )
        return WorkloadHandle(
            instance_id=instance_id,
            deployment_id=deployment_id,
            namespace=namespace,
            workload=workload,
            profile=profile,
            service_account=namespace_authority(profile).service_account,
            manifest_hash=hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
        )

    def wait_ready(self, workload: WorkloadHandle, timeout_seconds: int) -> ReadinessResult:
        deadline = time.monotonic() + max(1, min(int(timeout_seconds), 3_600))
        path = f"/apis/apps/v1/namespaces/{quote(workload.namespace, safe='')}/deployments/{quote(workload.workload, safe='')}"
        while time.monotonic() < deadline:
            deployment = self._json("GET", path)
            metadata = deployment.get("metadata")
            spec = deployment.get("spec")
            status = deployment.get("status")
            if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(status, Mapping):
                raise KubernetesAdapterError("Kubernetes returned an invalid Deployment")
            generation = metadata.get("generation")
            observed = status.get("observedGeneration")
            replicas = spec.get("replicas")
            available = status.get("availableReplicas", 0)
            if (
                metadata.get("namespace") == workload.namespace
                and metadata.get("name") == workload.workload
                and isinstance(generation, int)
                and observed == generation
                and replicas == 1
                and isinstance(available, int)
                and available >= 1
            ):
                return ReadinessResult(True, "ready", encode_timestamp(utc_now()))
            time.sleep(0.2)
        return ReadinessResult(False, "timeout", encode_timestamp(utc_now()))

    def snapshot_evidence(self, workload: WorkloadHandle, readiness: ReadinessResult) -> EvidenceSnapshot:
        if not readiness.ready:
            return EvidenceSnapshot(
                namespace=workload.namespace,
                workload=workload.workload,
                profile=workload.profile,
                service_account=workload.service_account,
                manifest_hash=workload.manifest_hash,
                status="not-ready",
                event_summary=("workload did not become ready",),
            )
        selector = urlencode(
            {
                "labelSelector": f"argus.instance={workload.namespace},argus.deployment={deployment_label_for_id(workload.instance_id, workload.deployment_id)}"
            }
        )
        pods = self._json("GET", f"/api/v1/namespaces/{quote(workload.namespace, safe='')}/pods?{selector}")
        items = pods.get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
            raise KubernetesAdapterError("trusted workload selector did not identify one pod")
        pod = items[0]
        metadata = pod.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("namespace") != workload.namespace:
            raise KubernetesAdapterError("trusted workload pod namespace mismatch")
        labels = metadata.get("labels")
        expected_label = deployment_label_for_id(workload.instance_id, workload.deployment_id)
        if (
            not isinstance(labels, Mapping)
            or labels.get("argus.instance") != workload.namespace
            or labels.get("argus.deployment") != expected_label
            or labels.get("argus.profile") != workload.profile.value
        ):
            raise KubernetesAdapterError("trusted workload pod selector mismatch")
        pod_spec = pod.get("spec")
        if not isinstance(pod_spec, Mapping) or pod_spec.get("serviceAccountName") != workload.service_account:
            raise KubernetesAdapterError("trusted workload service account mismatch")
        pod_name = metadata.get("name")
        if not isinstance(pod_name, str) or not _DNS_LABEL.fullmatch(pod_name):
            raise KubernetesAdapterError("trusted workload pod name is invalid")
        log_path = (
            f"/api/v1/namespaces/{quote(workload.namespace, safe='')}/pods/"
            f"{quote(pod_name, safe='')}/log?container=workload"
        )
        deadline = time.monotonic() + self._result_timeout_seconds
        verification_result: str | None = None
        while True:
            raw = self._request_bytes("GET", log_path)
            if len(raw) > MAX_RUNTIME_RESULT_BYTES:
                raise KubernetesAdapterError("trusted workload result is too large")
            if raw.strip():
                try:
                    result = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise KubernetesAdapterError("trusted workload result is invalid") from exc
                verification_result = validate_runtime_result(result, workload.profile)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise KubernetesAdapterError("trusted workload result was not produced")
            time.sleep(min(0.2, remaining))
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
        if workload.namespace != self.namespace_for_instance(workload.instance_id) or workload.workload != workload_name_for_deployment(workload.instance_id, workload.deployment_id):
            raise KubernetesAdapterError("workload handle is not trusted")
        self._request_bytes(
            "DELETE",
            f"/apis/apps/v1/namespaces/{quote(workload.namespace, safe='')}/deployments/{quote(workload.workload, safe='')}",
        )

    def request_namespace_cleanup(self, instance_id: str) -> None:
        """Namespace cleanup remains the external janitor's responsibility."""

        namespace_for_instance(instance_id, self._namespace_prefix)


class BrokerKubernetesAdapter:
    """Bounded client for the organizer-managed namespace-local broker."""

    def __init__(self, settings: Any):
        self._base_url = settings.k8s_broker_url.rstrip("/")
        self._token = settings.k8s_broker_token
        self._namespace_prefix = settings.k8s_namespace_prefix
        self._images = {
            DeploymentProfile.TEAM_NAMESPACE: settings.trusted_workload_image,
            DeploymentProfile.TEAM_NAMESPACE_ELEVATED: settings.elevated_workload_image,
        }
        self._result_timeout_seconds = max(1, min(int(settings.k8s_ready_timeout_seconds), 3_600))

    def namespace_for_instance(self, instance_id: str) -> str:
        return namespace_for_instance(instance_id, self._namespace_prefix)

    def _call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        request = Request(
            f"{self._base_url}{path}",
            data=canonical_json(body).encode("utf-8") if body is not None else None,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urlopen(request, timeout=15) as response:
                raw = response.read(MAX_KUBERNETES_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise KubernetesAdapterError("Kubernetes broker operation failed") from exc
        if len(raw) > MAX_KUBERNETES_RESPONSE_BYTES:
            raise KubernetesAdapterError("Kubernetes broker response is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KubernetesAdapterError("Kubernetes broker returned invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise KubernetesAdapterError("Kubernetes broker returned an invalid response")
        return value

    def create_workload(self, instance_id: str, deployment_id: str, profile: DeploymentProfile) -> WorkloadHandle:
        if profile not in self._images or not self._images[profile]:
            raise KubernetesAdapterError("trusted workload profile is unavailable")
        manifest = build_profile_manifest(
            instance_id=instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=self._images[profile],
            namespace_prefix=self._namespace_prefix,
        )
        validate_trusted_profile_manifest(
            manifest,
            instance_id=instance_id,
            deployment_id=deployment_id,
            profile=profile,
            workload_image=self._images[profile],
            namespace_prefix=self._namespace_prefix,
        )
        validate_shared_worker_spec(manifest)
        value = self._call("POST", "/v1/workloads", {"deployment_id": deployment_id, "profile": profile.value})
        if value != {"created": True}:
            raise KubernetesAdapterError("Kubernetes broker rejected workload creation")
        return WorkloadHandle(
            instance_id=instance_id,
            deployment_id=deployment_id,
            namespace=self.namespace_for_instance(instance_id),
            workload=workload_name_for_deployment(instance_id, deployment_id),
            profile=profile,
            service_account=namespace_authority(profile).service_account,
            manifest_hash=hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
        )

    def wait_ready(self, workload: WorkloadHandle, timeout_seconds: int) -> ReadinessResult:
        _validate_broker_handle(workload, self._namespace_prefix)
        deadline = time.monotonic() + max(1, min(int(timeout_seconds), 3_600))
        while time.monotonic() < deadline:
            value = self._call("GET", f"/v1/workloads/{quote(workload.deployment_id, safe='')}/readiness")
            if value.get("ready") is True:
                return ReadinessResult(True, "ready", encode_timestamp(utc_now()))
            time.sleep(0.2)
        return ReadinessResult(False, "timeout", encode_timestamp(utc_now()))

    def snapshot_evidence(self, workload: WorkloadHandle, readiness: ReadinessResult) -> EvidenceSnapshot:
        _validate_broker_handle(workload, self._namespace_prefix)
        if not readiness.ready:
            raise KubernetesAdapterError("workload is not ready")
        value = self._call("GET", f"/v1/workloads/{quote(workload.deployment_id, safe='')}/evidence")
        required = {"ready", "runtime_result"}
        if set(value) != required or value["ready"] is not True:
            raise KubernetesAdapterError("Kubernetes broker returned invalid evidence")
        verification_result = validate_runtime_result(value["runtime_result"], workload.profile)
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
        _validate_broker_handle(workload, self._namespace_prefix)
        value = self._call("DELETE", f"/v1/workloads/{quote(workload.deployment_id, safe='')}")
        if value != {"deleted": True}:
            raise KubernetesAdapterError("Kubernetes broker rejected workload cleanup")

    def request_namespace_cleanup(self, instance_id: str) -> None:
        self.namespace_for_instance(instance_id)


def _validate_broker_handle(workload: WorkloadHandle, namespace_prefix: str) -> None:
    if (
        workload.namespace != namespace_for_instance(workload.instance_id, namespace_prefix)
        or workload.workload != workload_name_for_deployment(workload.instance_id, workload.deployment_id)
        or workload.service_account != namespace_authority(workload.profile).service_account
    ):
        raise KubernetesAdapterError("workload handle is not trusted")
