from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from schrodinger.store import ArtifactStore


def create_routes(store: ArtifactStore, templates: Jinja2Templates) -> APIRouter:
    pages = APIRouter()

    def render(request: Request, name: str, active: str, **context):
        return templates.TemplateResponse(
            request=request,
            name=name,
            context={"request": request, "active_nav": active, **context},
        )

    @pages.get("/", response_class=HTMLResponse)
    @pages.get("/registry", response_class=HTMLResponse)
    async def registry(request: Request):
        return render(request, "registry.html", "registry")

    @pages.get("/packages/{artifact_id}", response_class=HTMLResponse)
    async def package(request: Request, artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        return render(request, "package.html", "registry", artifact_id=artifact_id)

    @pages.get("/packages/{artifact_id}/inspector", response_class=HTMLResponse)
    async def inspector_report(request: Request, artifact_id: str):
        if store.get(artifact_id) is None:
            raise HTTPException(status_code=404, detail="package not found")
        return render(request, "inspector.html", "inspections", artifact_id=artifact_id)

    @pages.get("/inspections", response_class=HTMLResponse)
    async def inspections(request: Request):
        return render(request, "inspections.html", "inspections")

    @pages.get("/runtime", response_class=HTMLResponse)
    async def runtime(request: Request):
        return render(request, "runtime.html", "runtime")

    @pages.get("/policy", response_class=HTMLResponse)
    async def policy(request: Request):
        return render(request, "policy.html", "policy")

    @pages.get("/api-help", response_class=HTMLResponse)
    async def api_help(request: Request):
        return render(request, "api_help.html", "api-help")

    return pages
