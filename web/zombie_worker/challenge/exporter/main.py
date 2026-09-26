from __future__ import annotations

import io
import json
import os
import secrets
import time
import zipfile
from threading import Lock
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

FLAG = os.environ.get("FLAG", "")
SERVICE_TOKEN = os.environ.get("EXPORTER_TOKEN", "")
APP_ENV = os.environ.get("APP_ENV", "development").lower()

if APP_ENV == "production":
    if not FLAG.startswith("H7CTF{") or not FLAG.endswith("}"):
        raise RuntimeError("production exporter requires the runtime H7CTF flag in FLAG")
    if len(SERVICE_TOKEN) < 32:
        raise RuntimeError("production exporter requires a high-entropy EXPORTER_TOKEN (32+ characters)")
_lock = Lock()
_packages: dict[str, dict[str, Any]] = {}
_packages_by_report: dict[tuple[str, int], str] = {}
_package_ttl = 900
_package_limit = 128
app = FastAPI(title="Relay report packaging", docs_url=None, redoc_url=None, openapi_url=None)


class ReportPackage(BaseModel):
    job_id: str
    title: str
    site: str
    diagnostic_reading: str | None = None
    published_at: str | None = None
    report_version: int = 1
    package_metadata: dict[str, Any] | None = None


def authorize(authorization: str | None) -> None:
    if not SERVICE_TOKEN or not secrets.compare_digest(authorization or "", f"Bearer {SERVICE_TOKEN}"):
        raise HTTPException(404, "not found")


def prune_packages() -> None:
    now = time.monotonic()
    for export_id, record in list(_packages.items()):
        if record["expires"] <= now:
            _packages.pop(export_id, None)
            _packages_by_report.pop((record["report"]["job_id"], record["report"]["report_version"]), None)
    while len(_packages) > _package_limit:
        export_id, record = min(_packages.items(), key=lambda item: item[1]["created"])
        _packages.pop(export_id, None)
        _packages_by_report.pop((record["report"]["job_id"], record["report"]["report_version"]), None)


@app.get("/health")
async def health():
    return {"status": "ready"}


def build_package(export_id: str) -> None:
    time.sleep(0.15)
    with _lock:
        record = _packages.get(export_id)
        if not record:
            return
        report = record["report"]
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(report, indent=2))
        metadata = report.get("package_metadata") or {}
        if (report["job_id"] == "JOB-3887"
                and metadata == {"contract": "relay.report-package/v1", "profile": "complete"}):
            # The modern package reader maps the old v1 complete bundle to commissioning.
            note = (f"Commissioning note\nWork order: {report['job_id']}\n"
                    f"Site: {report['site']}\nObserved reading: {report['diagnostic_reading']}\n"
                    f"Reference: {FLAG}\n")
            archive.writestr("attachments/commissioning-note.txt", note)
    with _lock:
        if export_id in _packages:
            _packages[export_id]["content"] = content.getvalue()
            _packages[export_id]["status"] = "complete"


@app.post("/internal/exports", status_code=202)
async def create_export(report: ReportPackage, background: BackgroundTasks,
                        authorization: str | None = Header(default=None)):
    authorize(authorization)
    report_data = report.model_dump()
    with _lock:
        prune_packages()
        key = (report.job_id, report.report_version)
        existing = _packages_by_report.get(key)
        if existing and existing in _packages:
            record = _packages[existing]
            return {"export_id": existing, "status": record["status"]}
        export_id = secrets.token_urlsafe(24)
        _packages[export_id] = {"status": "processing", "report": report_data, "content": None,
                                "created": time.monotonic(), "expires": time.monotonic() + _package_ttl}
        _packages_by_report[key] = export_id
    background.add_task(build_package, export_id)
    return {"export_id": export_id, "status": "processing"}


@app.get("/internal/exports/{export_id}")
async def export_status(export_id: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    with _lock:
        prune_packages()
        record = _packages.get(export_id)
        if not record:
            raise HTTPException(404, "export not found")
        return {"status": record["status"]}


@app.get("/internal/exports/{export_id}/package")
async def export_package(export_id: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    with _lock:
        prune_packages()
        record = _packages.get(export_id)
        if not record:
            raise HTTPException(404, "export not found")
        if record["status"] != "complete":
            raise HTTPException(409, "package is still processing")
        package = record["content"]
    return Response(package, media_type="application/zip")
