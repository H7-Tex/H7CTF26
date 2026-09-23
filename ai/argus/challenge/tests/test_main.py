import os
import subprocess
import pytest

from argus.config import SUPPORTED_ROLES
from argus.config import Settings
from argus.main import StartupError, _all_child_environment, build_parser, load_role_factory, main, run_all


def test_help_and_role_choices(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--help"])
    assert exit_info.value.code == 0
    role_action = next(action for action in build_parser()._actions if action.dest == "role")
    assert set(role_action.choices) == SUPPORTED_ROLES | {"all"}
    assert "usage:" in capsys.readouterr().out


def test_portal_factory_is_real_role():
    assert callable(load_role_factory("portal"))


def test_registry_and_mcp_factories_are_real_roles():
    assert callable(load_role_factory("registry"))
    assert callable(load_role_factory("mcp"))


def test_agents_factory_is_real_role():
    assert callable(load_role_factory("agents"))


def test_h7_child_secrets_are_role_scoped(clean_argus_env, monkeypatch):
    monkeypatch.setenv("INSTANCE_ID", "team-a")
    monkeypatch.setenv("ARGUS_H7_QWEN_MODEL_DIGEST", "a" * 64)
    root = b"instance-root-token"
    agents = _all_child_environment("agents", root)
    deployment = _all_child_environment("deployment", root)

    assert agents["ARGUS_CREDENTIAL_PORTAL_AGENTS"] != agents["ARGUS_CREDENTIAL_AGENTS_MCP"]
    assert "ARGUS_APPROVAL_SIGNING_KEY" not in agents
    assert "ARGUS_K8S_BROKER_TOKEN" not in agents
    assert "ARGUS_APPROVAL_SIGNING_KEY" in deployment
    assert "ARGUS_K8S_BROKER_TOKEN" in deployment
    assert "INTERNAL_TOKEN" not in deployment
    assert "FLAG" not in deployment
    assert "ARGUS_CREDENTIAL_PORTAL_REGISTRY" not in deployment


def test_h7_all_child_roles_load_settings_and_construct_apps(clean_argus_env, monkeypatch):
    monkeypatch.setenv("INTERNAL_TOKEN", "root-token-for-role-startup-test")
    monkeypatch.setenv("ARGUS_H7_QWEN_MODEL_DIGEST", "d" * 64)
    monkeypatch.setenv("ARGUS_DATABASE_PATH", str(clean_argus_env / "shared.sqlite3"))
    root = b"root-token-for-role-startup-test"
    from argus.store import connect_database, initialize_schema

    connection = connect_database(clean_argus_env / "shared.sqlite3")
    try:
        initialize_schema(connection)
    finally:
        connection.close()

    for role in sorted(SUPPORTED_ROLES):
        role_env = _all_child_environment(role, root)
        with monkeypatch.context() as child_env:
            for name in list(os.environ):
                if name.startswith(("ARGUS_", "OLLAMA_")) or name in {"INSTANCE_ID", "ROLE", "INTERNAL_TOKEN", "FLAG"}:
                    child_env.delenv(name, raising=False)
            for name, value in role_env.items():
                child_env.setenv(name, value)
            settings = Settings.load(role)
            app = load_role_factory(role)(settings)
            assert app is not None


def test_h7_all_bootstraps_once_and_stops_all_roles_when_one_exits(clean_argus_env, monkeypatch):
    monkeypatch.setenv("INTERNAL_TOKEN", "root-token-for-startup-test")
    monkeypatch.setenv("ARGUS_H7_QWEN_MODEL_DIGEST", "c" * 64)
    children = []

    class Child:
        def __init__(self, command, *, env):
            self.command, self.env = command, env
            self.returncode = 1 if not children else None
            children.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(subprocess, "Popen", Child)
    with pytest.raises(StartupError, match="critical ARGUS role exited"):
        run_all()

    assert len(children) == len(SUPPORTED_ROLES)
    assert all(child.env["ARGUS_ENV"] == "h7" for child in children)
    assert all("INTERNAL_TOKEN" not in child.env and "FLAG" not in child.env for child in children)
    assert children[0].returncode == 1
    assert all(child.returncode == -15 for child in children[1:])
