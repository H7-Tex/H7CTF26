from datetime import datetime, timezone
import hashlib
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from schrodinger.config import Settings
from schrodinger.models import InspectionRecord
from schrodinger.store import ArtifactStore
from schrodinger.inspector.parser import inspect_wheel


class InspectionRequest(BaseModel):
    artifact_id: str


def create_app(data_dir=None) -> FastAPI:
    settings = Settings.from_env()
    store = ArtifactStore(data_dir or settings.artifact_data_dir)
    app = FastAPI(title="Schrödinger Package Inspector")
    app.state.store = store

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "inspector"}

    @app.post("/inspections", response_model=InspectionRecord, status_code=201)
    async def inspect(request: InspectionRequest):
        artifact = store.get(request.artifact_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="package not found")
        try:
            content = store.read_bytes(artifact.artifact_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="package bytes not found") from None
        if hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise HTTPException(status_code=409, detail="stored package bytes do not match recorded SHA-256")

        result = inspect_wheel(artifact.original_filename, content)
        record = InspectionRecord(
            inspection_id=uuid.uuid4().hex,
            artifact_id=artifact.artifact_id,
            package_name=artifact.package_name,
            version=artifact.version,
            sha256=artifact.sha256,
            status=result.status,
            summary=result.summary,
            parsed_metadata=result.parsed_metadata,
            findings=result.findings,
            files=result.files,
            file_count=len(result.files),
            created_at=datetime.now(timezone.utc),
        )
        store.record_inspection(record)
        return record

    @app.get("/inspections/{artifact_id}", response_model=list[InspectionRecord])
    async def inspection_history(artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        return store.inspections(artifact_id)

    return app


app = create_app()
