import httpx
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import re

from schrodinger.config import Settings
from schrodinger.store import ArtifactStore
from schrodinger.portal.api import create_api
from schrodinger.portal.middleware import UploadLimitMiddleware
from schrodinger.portal.routes import create_routes
from schrodinger.portal.seed import seed_platform


PORTAL_DIR = Path(__file__).parent
FLAG_PATTERN = re.compile(r"H7CTF\{[^}\r\n]{0,256}\}")


def create_app(data_dir: Path | None = None, settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_env()
    store = ArtifactStore(data_dir or config.artifact_data_dir)
    for job in store.runtime_jobs():
        sanitized = [FLAG_PATTERN.sub("H7CTF{redacted}", line) for line in job.output]
        if sanitized != job.output:
            store.update_runtime_job_output(job.job_id, sanitized)
    seed_platform(store)
    templates = Jinja2Templates(directory=str(PORTAL_DIR / "templates"))

    app = FastAPI(title="Astra Package Exchange")
    app.add_middleware(UploadLimitMiddleware)
    app.state.store = store
    app.state.settings = config
    app.mount("/static", StaticFiles(directory=PORTAL_DIR / "static"), name="static")
    app.include_router(create_routes(store, templates))
    api = create_api(store, config)
    app.include_router(api, prefix="/api")
    app.include_router(api, prefix="/api/v1", include_in_schema=False)

    @app.get("/health")
    async def health():
        checks = {}
        async with httpx.AsyncClient(timeout=2.0) as client:
            for name, base_url in (
                ("inspector", config.inspector_url),
                ("runtime", config.runtime_url),
            ):
                try:
                    response = await client.get(f"{base_url}/health")
                    response.raise_for_status()
                    checks[name] = "ok"
                except httpx.HTTPError:
                    checks[name] = "unavailable"
        if any(status != "ok" for status in checks.values()):
            raise HTTPException(status_code=503, detail={"services": checks})
        return {"status": "ok", "services": checks}

    return app
