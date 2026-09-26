from io import BytesIO
import base64
import os
from pathlib import Path
from datetime import datetime, timezone
import uuid
import zipfile

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
import httpx
from packaging.utils import canonicalize_name, parse_wheel_filename

from schrodinger.config import MAX_UPLOAD_BYTES, Settings
from schrodinger.models import (
    InspectionHistory,
    InspectionList,
    InspectionRecord,
    InspectionSummary,
    RuntimeJob,
    RuntimeJobResponse,
    RuntimeJobRequest,
    RuntimeResult,
)
from schrodinger.store import ArtifactStore


def create_api(store: ArtifactStore, settings: Settings) -> APIRouter:
    api = APIRouter()

    def package_record(artifact):
        inspections = store.inspections(artifact.artifact_id, limit=1)
        jobs = [job for job in store.runtime_jobs() if job.artifact_id == artifact.artifact_id]
        inspection = inspections[0] if inspections else None
        job = jobs[0] if jobs else None
        return {
            **artifact.model_dump(mode="json"),
            "package_id": artifact.artifact_id,
            "filename": artifact.original_filename,
            "upload_timestamp": artifact.created_at.isoformat(),
            "inspector_status": inspection.status if inspection else "not_inspected",
            "inspector_summary": inspection.summary if inspection else "",
            "runtime_status": job.status if job else "not_run",
            "runtime_logs": job.output if job else [],
        }

    def challenge_flag() -> str | None:
        value = os.getenv("FLAG", "").strip()
        path = Path(os.getenv("FLAG_FILE", str(Path(__file__).parents[2] / "flag.txt")))
        if not value:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError:
                return None
        return value if value.startswith("H7CTF{") and value.endswith("}") else None

    @api.post("/packages", status_code=201)
    async def upload_package(file: UploadFile = File(...)):
        filename = Path(file.filename or "").name
        if not filename.lower().endswith(".whl"):
            raise HTTPException(status_code=415, detail="expected a .whl file")
        try:
            distribution, version, _, _ = parse_wheel_filename(filename)
        except ValueError:
            raise HTTPException(status_code=422, detail="filename is not a valid wheel filename") from None
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="upload exceeds the 20 MiB limit")
        if not zipfile.is_zipfile(BytesIO(content)):
            raise HTTPException(status_code=415, detail="upload is not a ZIP-based wheel container")
        try:
            artifact = store.create(
                filename,
                content,
                package_name=str(distribution),
                version=str(version),
            )
            return package_record(artifact)
        except FileExistsError:
            raise HTTPException(status_code=409, detail="package already exists") from None

    @api.get("/packages")
    async def list_packages(
        q: str = "",
        limit: int = Query(default=100, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ):
        items = store.list_artifacts(q, limit, offset)
        rows = []
        for item in items:
            latest = store.inspections(item.artifact_id, limit=1)
            rows.append({**package_record(item), "assurance": latest[0].status if latest else "not_recorded"})
        return {"items": rows, "total": store.count_artifacts(q), "limit": limit, "offset": offset}

    @api.get("/packages/{artifact_id}")
    async def package_detail(artifact_id: str):
        artifact = store.get(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="package not found")
        history = store.inspections(artifact_id, limit=1)
        latest = InspectionSummary.model_validate(history[0].model_dump(exclude={"files"})) if history else None
        record = package_record(artifact)
        return {**record, "package": record, "latest_inspection": latest}

    @api.post("/packages/{artifact_id}/inspection", response_model=InspectionSummary, status_code=201)
    async def request_inspection(artifact_id: str):
        artifact = store.get(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="package not found")
        content = store.read_bytes(artifact_id)
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{settings.inspector_url}/inspections",
                    json={
                        "artifact_id": artifact_id,
                        "filename": artifact.original_filename,
                        "package_name": artifact.package_name,
                        "version": artifact.version,
                        "content_b64": base64.b64encode(content).decode(),
                    },
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="inspection service is unavailable") from None
        if response.status_code >= 500:
            raise HTTPException(status_code=503, detail="inspection service is unavailable")
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="inspection request could not be completed")
        record = InspectionRecord.model_validate(response.json())
        if record.artifact_id != artifact.artifact_id or record.sha256 != artifact.sha256:
            raise HTTPException(status_code=502, detail="inspection result failed integrity verification")
        store.record_inspection(record)
        return InspectionSummary.model_validate(record.model_dump(exclude={"files"}))

    @api.get("/packages/{artifact_id}/inspection", response_model=InspectionHistory)
    async def inspection_history(artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        history = [
            InspectionSummary.model_validate(item.model_dump(exclude={"files"}))
            for item in store.inspections(artifact_id)
        ]
        return InspectionHistory(latest=history[0] if history else None, items=history)

    @api.get("/packages/{artifact_id}/inspector")
    async def package_inspector_report(artifact_id: str):
        artifact = store.get(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="package not found")
        history = store.inspections(artifact_id, limit=1)
        record = package_record(artifact)
        return {
            "package": record,
            "inspector_status": record["inspector_status"],
            "inspector_summary": record["inspector_summary"],
            "inspection": history[0].model_dump(mode="json") if history else None,
        }

    @api.get("/packages/{artifact_id}/manifest")
    async def package_manifest(artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        history = store.inspections(artifact_id, limit=1)
        if not history:
            raise HTTPException(status_code=409, detail="package has no inspection record")
        record = history[0]
        return {"artifact_id": artifact_id, "sha256": record.sha256, "files": record.files}

    @api.get("/inspections", response_model=InspectionList)
    async def list_inspections(limit: int = Query(default=100, ge=1, le=200)):
        items = [
            InspectionSummary.model_validate(item.model_dump(exclude={"files"}))
            for item in store.inspections(limit=limit)
        ]
        return InspectionList(items=items, total=len(items))

    @api.get("/runtime/jobs")
    async def list_runtime_jobs():
        items = store.runtime_jobs()
        return {"items": items, "total": len(items)}

    async def run_package(artifact_id: str):
        artifact = store.get(artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="package not found")
        history = store.inspections(artifact.artifact_id, limit=1)
        if not history:
            raise HTTPException(status_code=409, detail="package has no inspection record")
        inspection = history[0]
        if inspection.status not in {"passed", "passed_with_advisories"}:
            raise HTTPException(status_code=409, detail="package is not eligible for a runtime session")
        if (
            inspection.sha256 != artifact.sha256
            or inspection.artifact_id != artifact.artifact_id
            or inspection.package_name != artifact.package_name
            or inspection.version != artifact.version
        ):
            raise HTTPException(status_code=409, detail="inspection digest does not match the stored package")

        content = store.read_bytes(artifact.artifact_id)
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{settings.runtime_url}/jobs",
                    json={
                        "artifact_id": artifact.artifact_id,
                        "inspection_id": inspection.inspection_id,
                        "filename": artifact.original_filename,
                        "package_name": artifact.package_name,
                        "expected_sha256": artifact.sha256,
                        "content_b64": base64.b64encode(content).decode(),
                    },
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="runtime service is unavailable") from None
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="package bytes not found")
        if response.status_code == 409:
            raise HTTPException(status_code=409, detail="runtime package verification failed")
        if response.status_code >= 500:
            raise HTTPException(status_code=503, detail="runtime service is unavailable")
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="runtime request could not be completed")

        result = RuntimeResult.model_validate(response.json())
        if (
            result.artifact_id != artifact.artifact_id
            or result.inspection_id != inspection.inspection_id
            or result.sha256 != artifact.sha256
            or result.installer_sha256 != artifact.sha256
        ):
            raise HTTPException(status_code=502, detail="runtime result failed artifact integrity verification")
        expected_module_path = (
            f"{str(canonicalize_name(artifact.package_name)).replace('-', '_')}/__init__.py"
        )
        inspector_module = next(
            (item for item in inspection.files if item.path == expected_module_path), None
        )
        valid_digest = lambda value: len(value) == 64 and all(char in "0123456789abcdef" for char in value)
        releases_flag = (
            result.status == "completed"
            and result.import_succeeded
            and result.module_path == expected_module_path
            and result.archive_occurrences > 1
            and result.selected_sha256 == result.installed_sha256
            and valid_digest(result.selected_sha256)
            and inspector_module is not None
            and valid_digest(inspector_module.sha256)
            and inspector_module.sha256 != result.installed_sha256
        )
        flag = challenge_flag() if releases_flag else None

        job = RuntimeJob(
            job_id=uuid.uuid4().hex,
            artifact_id=artifact.artifact_id,
            package_name=artifact.package_name,
            version=artifact.version,
            sha256=result.sha256,
            status=result.status,
            created_at=datetime.now(timezone.utc),
            duration_ms=result.duration_ms,
            output=result.output,
        )
        store.record_runtime_job(job)
        return RuntimeJobResponse(**job.model_dump(), flag=flag)

    @api.post("/runtime/jobs", response_model=RuntimeJobResponse, status_code=201)
    async def request_runtime_job(request: RuntimeJobRequest):
        return await run_package(request.artifact_id)

    @api.post("/packages/{artifact_id}/runtime", response_model=RuntimeJobResponse, status_code=201)
    async def request_package_runtime(artifact_id: str):
        return await run_package(artifact_id)

    @api.get("/packages/{artifact_id}/runtime/logs")
    async def package_runtime_logs(artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        jobs = [job.model_dump(mode="json") for job in store.runtime_jobs() if job.artifact_id == artifact_id]
        latest = jobs[0] if jobs else None
        return {
            "package_id": artifact_id,
            "runtime_status": latest["status"] if latest else "not_run",
            "runtime_logs": latest["output"] if latest else [],
            "sessions": jobs,
        }

    @api.get("/runtime/jobs/{job_id}")
    async def runtime_job(job_id: str):
        jobs = store.runtime_jobs(job_id)
        if not jobs:
            raise HTTPException(status_code=404, detail="runtime job not found")
        return jobs[0]

    @api.get("/policy")
    async def policy():
        return {
            "name": "Astra Python Package Inspection Policy",
            "revision": "2026.09",
            "checks": [
                {"code": "wheel_layout", "description": "Package includes its standard wheel metadata."},
                {"code": "metadata_identity", "description": "Package name and version match the wheel filename."},
                {"code": "inventory", "description": "Package files are recorded with size and SHA-256."},
                {"code": "license_metadata", "description": "Missing license metadata is recorded as informational."},
            ],
        }

    return api
