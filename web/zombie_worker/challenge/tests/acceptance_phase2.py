"""Browser acceptance proving the player's own stale worker performs replay."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Error as PlaywrightError, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FINAL_SENTINEL = "H7CTF{player-owned-worker-test-sentinel}"


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(process, url: str, name: str, timeout: int = 30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"{name} exited during startup")
        try:
            response = httpx.get(url, timeout=1)
            if response.status_code == 200:
                return response
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise AssertionError(f"{name} did not become ready at {url}")


def start_server(port: int, *, operation_ttl: str = "900", flag: str = FINAL_SENTINEL,
                 collection_seconds: str = "5", cooldown_seconds: str = "2"):
    env = dict(os.environ)
    for key in ("OPS_TOKEN", "RELEASE", "ROLLOUT_DELAY_SECONDS", "SYNC_OPERATION_TTL_SECONDS", "BUILD_SHA",
                "LEGACY_BUILD_SHA", "FLAG", "CHECKPOINT_FLAG", "EXPORTER_URL", "EXPORTER_TOKEN"):
        env.pop(key, None)
    exporter_port = unused_port()
    token = "acceptance-exporter-token-0123456789abcdef"
    exporter_env = dict(env, FLAG=flag, EXPORTER_TOKEN=token)
    exporter_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    exporter = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "exporter.main:app", "--host", "127.0.0.1", "--port", str(exporter_port)],
        cwd=ROOT, env=exporter_env, stdout=exporter_log, stderr=subprocess.STDOUT, text=True,
    )
    exporter_base = f"http://127.0.0.1:{exporter_port}"
    wait_http(exporter, exporter_base + "/health", "Exporter")
    env.update(APP_ENV="test", CHECKPOINT_FLAG="ZW-CHECKPOINT-browser-sentinel", RELAY_DEV_LOGS="1", SYNC_OPERATION_TTL_SECONDS=operation_ttl,
               EXPORTER_URL=exporter_base, EXPORTER_TOKEN=token,
               DISPATCH_COLLECTION_SECONDS=collection_seconds, DISPATCH_COOLDOWN_SECONDS=cooldown_seconds)
    relay_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    relay = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "relay.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, stdout=relay_log, stderr=subprocess.STDOUT, text=True,
    )
    relay.relay_log, relay.exporter_process, relay.exporter_log = relay_log, exporter, exporter_log
    relay.base = f"http://127.0.0.1:{port}"
    wait_http(relay, relay.base + "/api/meta", "Relay")
    return relay, relay.base


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=8)


def stop_server(process, *, output_on_failure=False):
    stop_process(process)
    process.relay_log.seek(0); relay_output = process.relay_log.read()[-20000:]; process.relay_log.close()
    stop_process(process.exporter_process)
    process.exporter_log.seek(0); exporter_output = process.exporter_log.read()[-8000:]; process.exporter_log.close()
    if output_on_failure:
        print("--- Relay output ---\n" + relay_output + "\n--- Exporter output ---\n" + exporter_output)


def launch(playwright):
    try:
        return playwright.chromium.launch(headless=True)
    except PlaywrightError:
        return playwright.chromium.launch(channel="chrome", headless=True)


def test_player_owned_lifecycle_and_signed_replay():
    relay, base = start_server(unused_port())
    failed = False
    try:
        # The HTTP-only path can save a valid pre-rollout preference but cannot
        # enroll the browser key or move the session to the current release.
        with httpx.Client() as plain:
            assert plain.get(base + "/api/meta").json()["api_version"] == "1.0"
            assert plain.put(base + "/api/jobs/JOB-3887/report-preference", json={
                "contract": "relay.report-package/v1", "profile": "complete"}).status_code == 200
            for _ in range(3):
                assert plain.get(base + "/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
            assert plain.get(base + "/api/meta").json()["api_version"] == "1.0"
        print("[PASS] bare HTTP preference write and polling did not roll out or publish")

        result = subprocess.run(
            [sys.executable, str(ROOT.parent / "solution" / "solve_phase2.py"), "--url", base,
             "--timeout", "90", "--expect-flag", FINAL_SENTINEL],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode:
            failed = True
            raise AssertionError(f"reference player solve failed:\n{result.stdout}\n{result.stderr}")
        assert "[PASS] genuine browser skew" in result.stdout
        assert "[PASS] staged semantic conversion returned the sync reference" in result.stdout
        assert "[PASS] deliberate MessageChannel replay" in result.stdout
        assert f"final flag: {FINAL_SENTINEL}" in result.stdout
        print(result.stdout)
        print("[PASS] player-owned browser lifecycle, durable outbox, deliberate replay, and export")
    except Exception:
        failed = True
        raise
    finally:
        stop_server(relay, output_on_failure=failed)


if __name__ == "__main__":
    raise SystemExit(pytest.main(["-s", __file__]))
