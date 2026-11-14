"""Verify the two-service deployment and run the real player-browser solve."""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

CHALLENGE = Path(__file__).resolve().parents[1]
REPOSITORY = CHALLENGE.parent


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(command, *, cwd, env, check=True, timeout=300):
    return subprocess.run(command, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, timeout=timeout)


def main():
    project = "zwplayer" + secrets.token_hex(5)
    image = project + "-default"
    port = unused_port()
    flag = "H7CTF{compose-player-owned-" + secrets.token_hex(12) + "}"
    checkpoint_flag = "H7CTF{compose-reconciliation-" + secrets.token_hex(12) + "}"
    token = secrets.token_hex(32)
    env = dict(os.environ, FLAG=flag, CHECKPOINT_FLAG=checkpoint_flag, EXPORTER_TOKEN=token, RELAY_HOST_PORT=str(port),
               DISPATCH_COLLECTION_SECONDS=os.environ.get("ZW_TEST_COLLECTION_SECONDS", "5"),
               DISPATCH_COOLDOWN_SECONDS=os.environ.get("ZW_TEST_COOLDOWN_SECONDS", "2"))

    def compose(*args, check=True):
        return run(["docker", "compose", "-p", project, "-f", str(CHALLENGE / "docker-compose.yml"), *args],
                   cwd=CHALLENGE, env=env, check=check)

    try:
        compose("config", "--quiet")
        built = run(["docker", "build", "--tag", image, "."], cwd=CHALLENGE, env=env)
        print(built.stdout)
        default = json.loads(run(["docker", "image", "inspect", "--format", "{{json .Config}}", image], cwd=CHALLENGE, env=env).stdout)
        assert "relay.main:app" in default["Cmd"] and default["User"] == "10001:10001"
        compose("up", "--build", "--detach")
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if httpx.get(base + "/api/meta", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.5)
        else:
            raise AssertionError("Relay did not start")

        relay_id, exporter_id = (compose("ps", "-q", name).stdout.strip() for name in ("relay", "exporter"))
        assert relay_id and exporter_id
        assert set(compose("config", "--services").stdout.split()) == {"relay", "exporter"}
        inspect = lambda container, template: json.loads(run(["docker", "inspect", "--format", template, container], cwd=CHALLENGE, env=env).stdout)
        relay_env = dict(item.split("=", 1) for item in inspect(relay_id, "{{json .Config.Env}}"))
        exporter_env = dict(item.split("=", 1) for item in inspect(exporter_id, "{{json .Config.Env}}"))
        assert "FLAG" not in relay_env and exporter_env.get("FLAG") == flag
        assert relay_env.get("CHECKPOINT_FLAG") == checkpoint_flag and "CHECKPOINT_FLAG" not in exporter_env
        assert relay_env["EXPORTER_TOKEN"] == exporter_env["EXPORTER_TOKEN"] == token
        assert relay_env["DISPATCH_COLLECTION_SECONDS"] == env["DISPATCH_COLLECTION_SECONDS"]
        for name, container, memory, pids in (("relay", relay_id, 256, 128), ("exporter", exporter_id, 128, 64)):
            host = inspect(container, "{{json .HostConfig}}")
            assert host["Memory"] == memory * 1024 * 1024 and host["PidsLimit"] == pids
            output_ports = inspect(container, "{{json .HostConfig.PortBindings}}")
            if name == "relay":
                assert output_ports.get("8080/tcp")
            else:
                assert all(not values for values in (output_ports or {}).values())
            image_id = run(["docker", "inspect", "--format", "{{.Image}}", container], cwd=CHALLENGE, env=env).stdout.strip()
            history = run(["docker", "history", "--no-trunc", image_id], cwd=CHALLENGE, env=env).stdout
            assert flag not in history
        network = json.loads(run(["docker", "network", "inspect", "--format", "{{json .Options}}", f"{project}_relay-private"], cwd=CHALLENGE, env=env).stdout)
        assert network.get("com.docker.network.bridge.enable_ip_masquerade") == "false"
        print("[PASS] two-service deployment isolates CHECKPOINT_FLAG in Relay and final FLAG in private exporter; Relay is public and non-root")

        solve = run([sys.executable, str(REPOSITORY / "solution" / "solve.py"), "--url", base,
                     "--timeout", "120", "--expect-flag", flag], cwd=REPOSITORY, env=env,
                    check=False, timeout=240)
        print(solve.stdout)
        assert solve.returncode == 0, solve.stdout
        assert "[PASS] genuine browser skew" in solve.stdout and f"final flag: {flag}" in solve.stdout
        assert "[PASS] staged semantic conversion returned the sync reference" in solve.stdout
        logs = compose("logs", "--no-color", "relay").stdout
        assert flag not in logs
        print("[PASS] player's own browser established legacy active/current waiting and completed the exported report")
        print("[PASS] runtime flag is absent from Relay logs")

        dispatch = httpx.get(base + "/internal/dispatch-metrics", headers={"Authorization": f"Bearer {token}"}).json()
        def memory_bytes(raw):
            match = re.fullmatch(r"([\d.]+)([A-Za-z]+)", raw.replace(" ", ""))
            if not match:
                raise AssertionError(f"unrecognized Docker memory measurement: {raw!r}")
            number, unit = match.groups()
            scale = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}[unit]
            return int(float(number) * scale)
        memory = {}
        for name, container in (("relay", relay_id), ("exporter", exporter_id)):
            raw = run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container], cwd=CHALLENGE, env=env).stdout.strip()
            memory[name + "_memory_bytes"] = memory_bytes(raw.split("/", 1)[0].strip())
        metric_payload = {"cycle_duration_seconds": dispatch.get("cycle_duration_seconds"),
                          "stage_latency_seconds": dispatch.get("stage_latency_seconds"),
                          "replay_attempts": dispatch.get("replay_attempts", 0), "retry_count": 0,
                          "browser_heap_used_bytes": None, "relay_container_memory_bytes": memory["relay_memory_bytes"],
                          "exporter_container_memory_bytes": memory["exporter_memory_bytes"], "cycle_stuck": False}
        assert metric_payload["cycle_duration_seconds"] is not None and metric_payload["stage_latency_seconds"] is not None, dispatch
        print("[METRIC] " + json.dumps(metric_payload, sort_keys=True))
    finally:
        down = compose("down", "--rmi", "local", "--volumes", "--remove-orphans", check=False)
        if down.returncode:
            print(down.stdout, file=sys.stderr)
            raise RuntimeError("failed to clean isolated Compose project")
        run(["docker", "image", "rm", "--force", image], cwd=CHALLENGE, env=env, check=False)


if __name__ == "__main__":
    main()
