import pytest

from argus.config import Settings


def test_credentials_are_edge_specific_and_hidden(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_REGISTRY", "registry-secret")
    settings = Settings.load()
    assert settings.credential("portal_registry") == "registry-secret"
    assert "registry-secret" not in repr(settings)

    monkeypatch.setenv("ARGUS_CREDENTIAL_REGISTRY_MCP", "wrong-edge")
    with pytest.raises(ValueError, match="not valid"):
        Settings.load()


def test_credentials_cannot_reuse_a_secret_across_visible_edges(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_REGISTRY", "shared-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "shared-secret")
    with pytest.raises(ValueError, match="unique") as exc_info:
        Settings.load()
    assert "shared-secret" not in str(exc_info.value)


def test_signing_key_is_only_loaded_by_signing_roles(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "ignored-by-portal")
    assert Settings.load().approval_signing_key == ""

    monkeypatch.setenv("ARGUS_ROLE", "mcp")
    monkeypatch.delenv("ARGUS_APPROVAL_SIGNING_KEY")
    with pytest.raises(ValueError, match="SIGNING_KEY"):
        Settings.load()
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "mcp-secret")
    assert Settings.load().approval_signing_key == "mcp-secret"


def test_ollama_settings_are_agents_only(clean_argus_env, monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://untrusted.example")
    monkeypatch.setenv("OLLAMA_MODEL", "untrusted-model")
    portal = Settings.load()
    assert portal.ollama_url == ""
    assert portal.ollama_model == ""
    assert portal.model_context_tokens == 0

    monkeypatch.setenv("ARGUS_ROLE", "agents")
    agents = Settings.load()
    assert agents.ollama_url == "http://untrusted.example"
    assert agents.ollama_model == "untrusted-model"


def test_competition_agents_require_reproducible_model_settings(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "a" * 64)
    monkeypatch.setenv("OLLAMA_SEED", "7")
    monkeypatch.setenv("OLLAMA_TEMPERATURE", "0")
    monkeypatch.setenv("ARGUS_MODEL_STRICT_JSON", "true")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_COORDINATOR", "agents-coordinator")
    with pytest.raises(ValueError, match="OLLAMA_MODEL"):
        Settings.load()

    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("ARGUS_A2A_INTERFACE_URL", "https://agents.example")
    assert Settings.load().model_strict_json is True
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
    with pytest.raises(ValueError, match="requires OLLAMA_MODEL"):
        Settings.load()
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("OLLAMA_TEMPERATURE", "0.1")
    with pytest.raises(ValueError, match="temperature"):
        Settings.load()


def test_competition_agents_require_https_a2a_interface(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "a" * 64)
    monkeypatch.setenv("OLLAMA_SEED", "7")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_COORDINATOR", "agents-coordinator")
    with pytest.raises(ValueError, match="A2A_INTERFACE_URL"):
        Settings.load()
    monkeypatch.setenv("ARGUS_A2A_INTERFACE_URL", "http://agents.example")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings.load()


def test_competition_deployment_requires_pinned_image_and_secure_kubernetes(
    clean_argus_env, monkeypatch, tmp_path
):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "deployment-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_DEPLOYMENT", "portal-deployment")
    with pytest.raises(ValueError, match="WORKLOAD_IMAGE"):
        Settings.load()

    monkeypatch.setenv("ARGUS_WORKLOAD_IMAGE", "argus/workload:latest")
    with pytest.raises(ValueError, match="digest-pinned"):
        Settings.load()

    monkeypatch.setenv("ARGUS_WORKLOAD_IMAGE", "registry.example/argus/workload@sha256:" + "b" * 64)
    monkeypatch.setenv("ARGUS_K8S_ENABLED", "true")
    monkeypatch.setenv("ARGUS_K8S_API_URL", "https://kubernetes.example")
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("not-empty", encoding="utf-8")
    monkeypatch.setenv("ARGUS_K8S_CA_FILE", str(ca_file))
    monkeypatch.setenv("ARGUS_K8S_DEPLOYER_TOKEN", "token")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_DEPLOYMENT", "portal-deployment")
    settings = Settings.load()
    assert settings.trusted_workload_image.endswith("b" * 64)
    assert settings.k8s_credential == "token"


def test_competition_deployment_requires_kubernetes(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "deployment-secret")
    monkeypatch.setenv("ARGUS_WORKLOAD_IMAGE", "argus/workload@sha256:" + "c" * 64)
    with pytest.raises(ValueError, match="K8S_ENABLED"):
        Settings.load()


def test_competition_kubernetes_ca_must_be_readable_non_empty_file(
    clean_argus_env, monkeypatch, tmp_path
):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "deployment-secret")
    monkeypatch.setenv("ARGUS_WORKLOAD_IMAGE", "argus/workload@sha256:" + "d" * 64)
    monkeypatch.setenv("ARGUS_K8S_ENABLED", "true")
    monkeypatch.setenv("ARGUS_K8S_API_URL", "https://kubernetes.example")
    monkeypatch.setenv("ARGUS_K8S_DEPLOYER_TOKEN", "token")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_DEPLOYMENT", "portal-deployment")

    missing = tmp_path / "missing.pem"
    monkeypatch.setenv("ARGUS_K8S_CA_FILE", str(missing))
    with pytest.raises(ValueError, match="CA_FILE"):
        Settings.load()

    ca_directory = tmp_path / "ca-directory"
    ca_directory.mkdir()
    monkeypatch.setenv("ARGUS_K8S_CA_FILE", str(ca_directory))
    with pytest.raises(ValueError, match="CA_FILE"):
        Settings.load()

    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    monkeypatch.setenv("ARGUS_K8S_CA_FILE", str(empty))
    with pytest.raises(ValueError, match="CA_FILE"):
        Settings.load()

    valid = tmp_path / "valid.pem"
    valid.write_bytes(b"ca-data")
    monkeypatch.setenv("ARGUS_K8S_CA_FILE", str(valid))
    assert Settings.load().k8s_ca_file == valid


def test_development_deployment_defaults_are_bounded(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "deployment-secret")
    settings = Settings.load()
    assert settings.trusted_workload_image == "argus/workload:foundation"
    assert settings.k8s_enabled is False

    monkeypatch.setenv("ARGUS_K8S_NAMESPACE_PREFIX", "Bad_Prefix")
    with pytest.raises(ValueError, match="namespace prefix"):
        Settings.load()


def test_h7_qwen_digest_is_an_explicit_attestation_setting(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "agents")
    monkeypatch.setenv("ARGUS_ENV", "h7")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "a" * 64)
    monkeypatch.setenv("OLLAMA_SEED", "7")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_REGISTRY", "agents-registry")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_MCP", "agents-mcp")
    monkeypatch.setenv("ARGUS_CREDENTIAL_AGENTS_COORDINATOR", "agents-coordinator")
    with pytest.raises(ValueError, match="ARGUS_H7_QWEN_MODEL_DIGEST"):
        Settings.load()

    monkeypatch.setenv("ARGUS_H7_QWEN_MODEL_DIGEST", "a" * 64)
    assert Settings.load().ollama_url == "https://qwen.h7tex.com"
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    with pytest.raises(ValueError, match="endpoint is fixed"):
        Settings.load()
    monkeypatch.setenv("OLLAMA_URL", "https://qwen.h7tex.com")
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "b" * 64)
    with pytest.raises(ValueError, match="matching"):
        Settings.load()


def test_h7_deployment_has_only_the_authenticated_internal_broker(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_ENV", "h7")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "derived-approval-key")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_DEPLOYMENT", "portal-deployment")
    monkeypatch.setenv("ARGUS_K8S_ENABLED", "true")
    monkeypatch.setenv("ARGUS_K8S_BROKER_TOKEN", "derived-broker-token")
    settings = Settings.load()
    assert settings.k8s_broker_url == "http://argus-k8s-broker:8085"
    assert settings.k8s_broker_token == "derived-broker-token"
    assert settings.k8s_api_url == ""
    assert settings.k8s_ca_file is None
    assert settings.k8s_credential == ""


def test_portal_has_fixed_service_urls_and_public_url(clean_argus_env, monkeypatch):
    settings = Settings.load()
    assert settings.registry_base_url == "http://registry:8081"
    assert settings.agents_base_url == "http://agents:8082"
    assert settings.deployment_base_url == "http://deployment:8084"
    assert settings.public_base_url == "http://localhost:8080"

    monkeypatch.setenv("ARGUS_ENV", "competition")
    with pytest.raises(ValueError, match="REGISTRY_BASE_URL"):
        Settings.load()
    monkeypatch.setenv("ARGUS_REGISTRY_BASE_URL", "http://registry:8081")
    monkeypatch.setenv("ARGUS_AGENTS_BASE_URL", "http://agents:8082")
    monkeypatch.setenv("ARGUS_DEPLOYMENT_BASE_URL", "http://deployment:8084")
    monkeypatch.setenv("ARGUS_PUBLIC_BASE_URL", "http://portal.example")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_REGISTRY", "portal-registry")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_AGENTS", "portal-agents")
    monkeypatch.setenv("ARGUS_CREDENTIAL_PORTAL_DEPLOYMENT", "portal-deployment")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings.load()
    monkeypatch.setenv("ARGUS_PUBLIC_BASE_URL", "https://portal.example")
    assert Settings.load().public_base_url == "https://portal.example"


def test_deployment_has_no_obsolete_security_edge(clean_argus_env, monkeypatch):
    monkeypatch.setenv("ARGUS_ROLE", "deployment")
    monkeypatch.setenv("ARGUS_APPROVAL_SIGNING_KEY", "deployment-secret")
    monkeypatch.setenv("ARGUS_CREDENTIAL_DEPLOYMENT_SECURITY", "unused")
    with pytest.raises(ValueError, match="not valid"):
        Settings.load()
