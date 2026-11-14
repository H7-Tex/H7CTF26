import time
import re
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient

from exporter import main


def test_compose_keeps_exporter_unpublished_and_flag_off_relay():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    relay = compose.split("  relay:\n", 1)[1].split("  exporter:\n", 1)[0]
    exporter = compose.split("  exporter:\n", 1)[1].split("\nnetworks:", 1)[0]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\s+FLAG:", relay)
    assert re.search(r"(?m)^\s+FLAG:", exporter)
    assert not re.search(r"(?m)^\s+ports:", exporter)
    assert "ARG FLAG" not in dockerfile
    assert "USER 10001:10001" in dockerfile and "USER 10002:10002" in dockerfile


def test_exporter_requires_internal_auth_and_builds_runtime_artifact(monkeypatch):
    monkeypatch.setattr(main, "SERVICE_TOKEN", "test-internal-token")
    monkeypatch.setattr(main, "FLAG", "H7CTF{exporter-test-sentinel}")
    main._packages.clear()
    main._packages_by_report.clear()
    client = TestClient(main.app)
    report = {"job_id": "JOB-3887", "title": "Telemetry drift report", "site": "North relay station",
              "diagnostic_reading": "Clock drift +184 ms · channel 4", "published_at": "2026-09-25T00:00:00+00:00",
              "report_version": 1, "package_metadata": {"contract":"relay.report-package/v1", "profile":"complete"}}
    assert client.post("/internal/exports", json=report).status_code == 404
    response = client.post("/internal/exports", json=report, headers={"Authorization": "Bearer test-internal-token"})
    assert response.status_code == 202
    export_id = response.json()["export_id"]
    repeated = client.post("/internal/exports", json=report, headers={"Authorization": "Bearer test-internal-token"})
    assert repeated.json()["export_id"] == export_id
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = client.get(f"/internal/exports/{export_id}", headers={"Authorization": "Bearer test-internal-token"})
        if status.json()["status"] == "complete":
            break
        time.sleep(.02)
    package = client.get(f"/internal/exports/{export_id}/package", headers={"Authorization": "Bearer test-internal-token"})
    assert package.status_code == 200
    with zipfile.ZipFile(BytesIO(package.content)) as archive:
        assert b"H7CTF{exporter-test-sentinel}" in archive.read("attachments/commissioning-note.txt")
    assert client.get("/openapi.json").status_code == 404


def test_current_package_scope_never_adds_commissioning_material(monkeypatch):
    monkeypatch.setattr(main, "SERVICE_TOKEN", "test-internal-token")
    monkeypatch.setattr(main, "FLAG", "H7CTF{exporter-test-sentinel}")
    main._packages.clear()
    main._packages_by_report.clear()
    client = TestClient(main.app)
    report = {"job_id":"JOB-3887", "title":"Telemetry", "site":"Station", "report_version":2,
              "package_metadata":{"contract":"relay.report-package/v2", "scope":"complete"}}
    response = client.post("/internal/exports", json=report, headers={"Authorization":"Bearer test-internal-token"})
    export_id = response.json()["export_id"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        state = client.get(f"/internal/exports/{export_id}", headers={"Authorization":"Bearer test-internal-token"}).json()
        if state["status"] == "complete": break
        time.sleep(.02)
    package = client.get(f"/internal/exports/{export_id}/package", headers={"Authorization":"Bearer test-internal-token"})
    with zipfile.ZipFile(BytesIO(package.content)) as archive:
        assert "attachments/commissioning-note.txt" not in archive.namelist()

    for version, profile in ((3, "summary"), (4, "record")):
        legacy_package = {"job_id":"JOB-3887", "title":"Telemetry", "site":"Station", "report_version":version,
                          "package_metadata":{"contract":"relay.report-package/v1", "profile":profile}}
        created = client.post("/internal/exports", json=legacy_package, headers={"Authorization":"Bearer test-internal-token"})
        package_id = created.json()["export_id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = client.get(f"/internal/exports/{package_id}", headers={"Authorization":"Bearer test-internal-token"}).json()
            if state["status"] == "complete": break
            time.sleep(.02)
        package = client.get(f"/internal/exports/{package_id}/package", headers={"Authorization":"Bearer test-internal-token"})
        with zipfile.ZipFile(BytesIO(package.content)) as archive:
            assert "attachments/commissioning-note.txt" not in archive.namelist()

    print("[PASS] normal v1 summary/record profiles export without commissioning material")
