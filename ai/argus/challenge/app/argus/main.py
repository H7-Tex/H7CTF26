"""Role-based entry point for the single ARGUS service image."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable

from .config import ROLE_CREDENTIAL_EDGES, ROLE_LABELS, SUPPORTED_ROLES, Settings
from .store import connect_database, initialize_schema


ROLE_MODULES = {
    "portal": "argus.portal",
    "registry": "argus.registry",
    "agents": "argus.agents",
    "mcp": "argus.mcp",
    "deployment": "argus.deployment",
}

ROLE_PORTS = {
    "portal": 8080,
    "registry": 8081,
    "agents": 8082,
    "mcp": 8083,
    "deployment": 8084,
}


class StartupError(RuntimeError):
    """A user-actionable role startup failure."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m argus.main")
    parser.add_argument("role", choices=[*sorted(SUPPORTED_ROLES), "all"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=_port, default=None)
    return parser


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def load_role_factory(role: str) -> Callable[[Settings], Any]:
    """Import a role factory only after that role was explicitly selected."""

    module_name = ROLE_MODULES[role]
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            raise StartupError(
                f"the {role} role is not implemented yet; expected {module_name}.py"
            ) from exc
        raise StartupError(f"could not load the {role} role dependencies") from exc
    factory = getattr(module, "create_app", None)
    if not callable(factory):
        raise StartupError(f"{module_name}.py does not expose a create_app(settings) factory")
    return factory


def prepare_database(settings: Settings) -> None:
    """Create the state directory and idempotently bootstrap its SQLite schema."""

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    connection = connect_database(settings.database_path)
    try:
        initialize_schema(connection)
    finally:
        connection.close()


def run_role(role: str, *, host: str = "0.0.0.0", port: int | None = None) -> None:
    settings = Settings.load(role)
    if os.getenv("ARGUS_ALL_CHILD") != "1":
        prepare_database(settings)
    factory = load_role_factory(role)
    app = factory(settings)

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on deployment image
        raise StartupError("uvicorn is required to run an ARGUS role") from exc
    uvicorn.run(
        app,
        host=host,
        port=port or ROLE_PORTS[role],
        proxy_headers=settings.environment == "h7",
        forwarded_allow_ips=os.getenv("ARGUS_TRUSTED_PROXY_IPS", "127.0.0.1"),
    )


def _derive(root: bytes, label: str) -> str:
    return hmac.new(root, label.encode("ascii"), hashlib.sha256).hexdigest()


def _all_child_environment(role: str, root: bytes) -> dict[str, str]:
    env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "WINDIR", "PYTHONPATH") if name in os.environ}
    env.update({
        "ARGUS_ROLE": role,
        "ARGUS_ENV": "h7",
        "ARGUS_ALL_CHILD": "1",
        "INSTANCE_ID": os.environ["INSTANCE_ID"],
        "ARGUS_STATE_DIR": os.getenv("ARGUS_STATE_DIR", "/var/lib/argus"),
        "ARGUS_DATABASE_PATH": os.getenv("ARGUS_DATABASE_PATH", "/var/lib/argus/argus.sqlite3"),
        "ARGUS_APPROVAL_SIGNING_KEY_ID": os.environ["INSTANCE_ID"],
        "OLLAMA_URL": "https://qwen.h7tex.com",
        "OLLAMA_MODEL": "qwen2.5-coder:7b",
        "OLLAMA_MODEL_DIGEST": os.environ["ARGUS_H7_QWEN_MODEL_DIGEST"],
        "ARGUS_H7_QWEN_MODEL_DIGEST": os.environ["ARGUS_H7_QWEN_MODEL_DIGEST"],
        "OLLAMA_SEED": "7",
        "OLLAMA_TEMPERATURE": "0",
        "ARGUS_MODEL_STRICT_JSON": "true",
        "ARGUS_TRUSTED_PROXY_IPS": os.getenv("ARGUS_TRUSTED_PROXY_IPS", "127.0.0.1"),
    })
    for edge in ROLE_CREDENTIAL_EDGES[role]:
        label = ROLE_LABELS[edge]
        env[f"ARGUS_CREDENTIAL_{edge.upper()}"] = _derive(root, label)
    if role in {"mcp", "deployment"}:
        env["ARGUS_APPROVAL_SIGNING_KEY"] = _derive(root, "argus/approval-signing")
    if role == "deployment":
        env.update({
            "ARGUS_K8S_ENABLED": "true",
            "ARGUS_K8S_BROKER_URL": "http://argus-k8s-broker:8085",
            "ARGUS_K8S_BROKER_TOKEN": _derive(root, "argus/k8s-broker"),
            "ARGUS_WORKLOAD_IMAGE": os.getenv("ARGUS_WORKER_IMAGE", "h7ctf26/argus-worker:1"),
            "ARGUS_ELEVATED_WORKLOAD_IMAGE": os.getenv("ARGUS_ELEVATED_IMAGE", "h7ctf26/argus-elevated:1"),
        })
    return env


def run_all() -> None:
    root_token = os.getenv("INTERNAL_TOKEN", "").strip()
    instance_id = os.getenv("INSTANCE_ID", "").strip()
    digest = os.getenv("ARGUS_H7_QWEN_MODEL_DIGEST", "").strip()
    if not root_token or not instance_id:
        raise StartupError("INTERNAL_TOKEN and INSTANCE_ID are required in H7 mode")
    if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
        raise StartupError("ARGUS_H7_QWEN_MODEL_DIGEST must be a 64-character hexadecimal digest")
    root = root_token.encode("utf-8")
    data_dir = Path(os.getenv("ARGUS_STATE_DIR", "/var/lib/argus"))
    database_path = Path(os.getenv("ARGUS_DATABASE_PATH", str(data_dir / "argus.sqlite3")))
    data_dir.mkdir(parents=True, exist_ok=True)
    connection = connect_database(database_path)
    try:
        initialize_schema(connection)
    finally:
        connection.close()
    children: list[subprocess.Popen[bytes]] = []
    previous_handlers: dict[int, Any] = {}

    def stop(_signum: int, _frame: Any) -> None:
        for child in children:
            if child.poll() is None:
                child.terminate()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, stop)
    try:
        for role in sorted(SUPPORTED_ROLES):
            host = "0.0.0.0" if role == "portal" else "127.0.0.1"
            child = subprocess.Popen(
                [sys.executable, "-m", "argus.main", role, "--host", host, "--port", str(ROLE_PORTS[role])],
                env=_all_child_environment(role, root),
            )
            children.append(child)
        while True:
            exited = next((child for child in children if child.poll() is not None), None)
            if exited is not None:
                raise StartupError(f"critical ARGUS role exited with status {exited.returncode}")
            time.sleep(0.2)
    finally:
        stop(0, None)
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.role == "all":
            run_all()
        else:
            run_role(args.role, host=args.host, port=args.port)
    except (StartupError, ValueError) as exc:
        parser.exit(2, f"argus startup error: {exc}\n")


if __name__ == "__main__":
    main()
