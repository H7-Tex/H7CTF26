from pathlib import Path

from argus.kubernetes import namespace_for_instance


ROOT = Path(__file__).parents[1]


def test_local_kind_contract_is_development_only_and_uses_the_trusted_namespace_rule():
    overlay = (ROOT / "docker-compose.dev.yml").read_text(encoding="utf-8")
    production = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    script = (ROOT / "ops" / "local-kind.ps1").read_text(encoding="utf-8")
    contract = (ROOT / "ops" / "kubernetes" / "team-namespace.yaml").read_text(encoding="utf-8")
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "name: kind" in overlay
    assert "ARGUS_K8S_API_URL: https://argus-control-plane:6443" in overlay
    assert 'ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS: "180"' in overlay
    assert "ARGUS_K8S_NAMESPACE_PREFIX" in overlay
    assert "/run/secrets/k8s-ca.crt" in overlay
    assert "/run/secrets/k8s-deployer-token" in overlay
    assert "kubeconfig" not in overlay.lower()
    assert "kind" not in production
    assert "ARGUS_DEPLOYMENT_UPSTREAM_TIMEOUT_SECONDS" not in production
    assert ".argus-local-kind/" in ignored
    assert "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: argus-worker-resource-reader" in contract

    assert "kind-argus" in script
    assert "current-context" in script
    assert "namespace_for_instance" in script
    assert "team-namespace.yaml" in script
    assert "create token argus-deployer" in script
    assert "certificate-authority-data" in script
    assert '"delete", "namespace"' in script
    assert namespace_for_instance("team-a") == "argus-team-a"


def test_local_kind_image_is_verifiable_as_non_root():
    dockerfile = (ROOT / "app" / "Dockerfile").read_text(encoding="utf-8")
    trusted_builder = (ROOT / "app" / "argus" / "kubernetes.py").read_text(encoding="utf-8")

    assert "USER 100:101" in dockerfile
    assert "USER argus" not in dockerfile
    assert '"runAsNonRoot": True' in trusted_builder
