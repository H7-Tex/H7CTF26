from datetime import datetime, timezone
import base64
import hashlib
import uuid

from fastapi import FastAPI, HTTPException

from schrodinger.models import InspectionRecord, InternalInspectionRequest
from schrodinger.inspector.parser import inspect_wheel


def create_app() -> FastAPI:
    app = FastAPI(title="Schrödinger Package Inspector")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "inspector"}

    @app.post("/inspections", response_model=InspectionRecord, status_code=201)
    async def inspect(request: InternalInspectionRequest):
        try:
            content = base64.b64decode(request.content_b64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="content is not valid base64") from None

        result = inspect_wheel(request.filename, content)
        return InspectionRecord(
            inspection_id=uuid.uuid4().hex,
            artifact_id=request.artifact_id,
            package_name=request.package_name,
            version=request.version,
            sha256=hashlib.sha256(content).hexdigest(),
            status=result.status,
            summary=result.summary,
            parsed_metadata=result.parsed_metadata,
            findings=result.findings,
            files=result.files,
            file_count=len(result.files),
            created_at=datetime.now(timezone.utc),
        )

    return app


app = create_app()
