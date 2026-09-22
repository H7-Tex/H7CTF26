from __future__ import annotations

import logging
import sys
import time
from pathlib import PurePosixPath
from typing import Any

import httpx
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .agents import Qwen, review_policy
from .config import Settings
from .domain import EXCEPTION_EXAMPLE, allows_release, is_production_capable, release_manifest, scan_tree
from .security import internal_auth
from .store import AgentStore, PLAYER_REF, PortalStore
from .ui import render_portal_page

logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 393216


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any, maximum: int) -> None:
        self.app, self.maximum = app, maximum

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            if int(headers.get(b"content-length", b"0")) > self.maximum:
                await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)
                return
        except ValueError:
            pass
        messages, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.maximum:
                    await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)
                    return
            messages.append(message)
            if message["type"] != "http.request" or not message.get("more_body"):
                break

        async def replay_receive() -> dict[str, Any]:
            return messages.pop(0) if messages else {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


class CommitRequest(BaseModel):
    expected_head: str = Field(min_length=64, max_length=64)
    tree: dict[str, str]


class RunRequest(BaseModel):
    commit: str = Field(min_length=64, max_length=64)


class ReleaseRequest(BaseModel):
    candidate_ref: str = Field(pattern=f"^{PLAYER_REF}$")
    action: str = Field(pattern="^promote$")
    target: str = Field(pattern="^(staging|production)$")


def checked_tree(tree: dict[str, str], maximum: int, max_files: int = 128, max_path_bytes: int = 16384, max_file_bytes: int = 65536) -> None:
    if len(tree) > max_files:
        raise HTTPException(413, "repository exceeds input limit")
    total = 0
    for path, content in tree.items():
        pure = PurePosixPath(path)
        path_bytes, content_bytes = len(path.encode()), len(content.encode())
        if pure.is_absolute() or ".." in pure.parts or not path or "\\" in path or path_bytes > 180:
            raise HTTPException(422, "invalid repository path")
        if content_bytes > max_file_bytes:
            raise HTTPException(413, "repository exceeds input limit")
        total += path_bytes + content_bytes
    if total > maximum or sum(len(path.encode()) for path in tree) > max_path_bytes:
        raise HTTPException(413, "repository exceeds input limit")


def locked_app(title: str) -> FastAPI:
    return FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None)


def portal(settings: Settings) -> FastAPI:
    app, store = locked_app("Trustfall CI"), PortalStore(settings.data_dir)
    app.add_middleware(RequestBodyLimitMiddleware, maximum=MAX_REQUEST_BYTES)
    release_url = "http://release:8083"

    @app.on_event("shutdown")
    def close_store() -> None:
        store.close()

    @app.on_event("startup")
    def revoke_failed_run_approvals() -> None:
        failed_runs = [row[0] for row in store.db.execute("SELECT id FROM runs WHERE status='failed'")]
        if not failed_runs or not settings.agents_url:
            return
        with httpx.Client(timeout=10, headers={"X-Internal-Token": settings.internal_token}) as client:
            response = client.post(f"{settings.agents_url}/approvals/revoke", json={"project": settings.instance_id, "runs": failed_runs})
            response.raise_for_status()

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def page(title: str, view: str) -> str:
        return render_portal_page(title, view, PLAYER_REF, EXCEPTION_EXAMPLE)

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return page("Overview", "/")

    @app.get("/repository", response_class=HTMLResponse)
    def repository_page() -> str:
        return page("Candidate Repository", "/repository")

    @app.get("/commits", response_class=HTMLResponse)
    def commits_page() -> str:
        return page("Change History", "/commits")

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page() -> str:
        return page("Pipelines", "/runs")

    @app.get("/artifacts", response_class=HTMLResponse)
    def artifacts_page() -> str:
        return page("Artifacts", "/artifacts")

    @app.get("/assurances", response_class=HTMLResponse)
    def assurances_page() -> str:
        return page("Repository Assurances", "/assurances")

    @app.get("/releases", response_class=HTMLResponse)
    def releases_page() -> str:
        return page("Release Candidate", "/releases")

    @app.get("/api/repository")
    def repository() -> dict[str, Any]:
        head = store.head(PLAYER_REF)
        return {"candidate_ref": PLAYER_REF, "head": head, "tree": store.tree(head)}

    def assurances() -> list[dict[str, str]]:
        defaults = [
            {"control": "release-integrity", "status": "UNVERIFIED", "state": "UNVERIFIED", "scope": "repository", "evidence_class": "pending review", "source": "release security policy", "originating_run": "none", "artifact": "none"},
            {"control": "dependency-policy", "status": "VERIFIED", "state": "VERIFIED", "scope": "repository", "evidence_class": "dependency policy", "source": "repository configuration", "originating_run": "baseline", "artifact": "policy manifest"},
            {"control": "test-isolation", "status": "VERIFIED", "state": "VERIFIED", "scope": "file", "evidence_class": "test control", "source": "CI configuration", "originating_run": "baseline", "artifact": "test report"},
        ]
        if not settings.agents_url:
            return defaults
        try:
            with httpx.Client(timeout=3, headers={"X-Internal-Token": settings.internal_token}) as client:
                observed = client.get(f"{settings.agents_url}/assurances", params={"project": settings.instance_id})
                observed.raise_for_status()
                updates = {item["control"]: item for item in observed.json()}
        except (httpx.HTTPError, ValueError):
            return defaults
        return [updates.get(item["control"], item) for item in defaults]

    @app.get("/api/assurances")
    def public_assurances() -> list[dict[str, str]]:
        return assurances()

    def public_run(state: dict[str, Any]) -> dict[str, Any]:
        sarif = state.get("sarif")
        findings = sarif.get("runs", [{}])[0].get("results", []) if sarif else []
        review = state.get("review") or {}
        events: list[dict[str, Any]] = []
        for event in review.get("observations", []):
            if event["tool"] == "get_sarif_findings":
                events.append({"event": "scanner_findings_loaded", "result": event["result"]})
            elif event["tool"] == "get_project_memory":
                events.append({"event": "historical_context_loaded", "records": int(event["result"].split()[0])})
            elif event["tool"] == "record_security_observation":
                events.append({"event": "security_observation_recorded", "result": event["result"]})
            elif event["tool"] == "review_path":
                events.append({"event": "review_path_completed", "result": event["result"]})
            elif event["tool"] == "approval_controller":
                events.append({"event": "approval_evaluated", "result": event["result"]})
        approval = review.get("approval")
        approval_view = None
        if approval:
            candidate_bound = approval.get("binding_type") == "candidate"
            approval_view = {
                "status": "approved",
                "deployment_candidate": approval["binding_value"] if candidate_bound else None,
                "reviewed_revision": approval["observed_commit"][:12],
                "policy_tier": "expedited" if review.get("review_mode") == "fast" else "standard",
                "expires_at": approval.get("expires_at"),
            }
        return {
            "id": state["id"],
            "number": state["number"],
            "commit": state["commit_id"][:12],
            "status": state["status"],
            "created_at": state["created_at"],
            "scan": {
                "available": bool(sarif),
                "findings": len(findings),
                "accepted_suppressions": sum(bool(item.get("suppressions")) for item in findings),
            },
            "review": {
                "status": "review_completed" if state["status"] == "passed" else state["status"],
                "historical_assurances_used": next((item["records"] for item in events if item["event"] == "historical_context_loaded"), 0),
                "assurance_updated": any(item["event"] == "security_observation_recorded" and item["result"] == "stored" for item in events),
                "approval_status": "issued" if approval else "not_issued",
                "review_path": review.get("review_mode"),
                "events": events,
            },
            "approval": approval_view,
        }

    @app.get("/api/dashboard")
    def dashboard() -> dict[str, Any]:
        row = store.db.execute("SELECT id FROM runs ORDER BY number DESC LIMIT 1").fetchone()
        pipeline = None
        if row:
            state = public_run(store.run(row["id"]))
            pipeline = {
                "number": state["number"],
                "findings": state["scan"]["findings"],
                "suppressed": state["scan"]["accepted_suppressions"],
                "summary": "Security review completed",
                "approval": (state["approval"] or {}).get("status", "pending"),
            }
        return {"candidate_ref": PLAYER_REF, "head": store.head(PLAYER_REF), "pipeline": pipeline, "assurances": assurances()}

    @app.post("/api/commits")
    def create_commit(body: CommitRequest) -> dict[str, str]:
        checked_tree(body.tree, settings.max_input_bytes, settings.max_tracked_files, settings.max_path_bytes, settings.max_file_bytes)
        try:
            return {"commit": store.commit(body.tree, body.expected_head, PLAYER_REF)}
        except RuntimeError as exc:
            if str(exc) == "repository history limit reached":
                raise HTTPException(429, str(exc)) from exc
            raise HTTPException(409, "head changed") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/commits")
    def commits() -> list[dict[str, Any]]:
        return store.commits()

    def run_pipeline(run: str, commit: str) -> None:
        try:
            tree = store.tree(commit)
            store.update_run(run, "scanning")
            with httpx.Client(timeout=120, headers={"X-Internal-Token": settings.internal_token}) as client:
                scanner_response = client.post(f"{settings.scanner_url}/scan", json={"tree": tree})
                scanner_response.raise_for_status()
                sarif = scanner_response.json()
                store.update_run(run, "reviewing", sarif=sarif)
                if store.head(PLAYER_REF) != commit:
                    store.update_run(run, "stale", sarif=sarif)
                    return
                manifest = release_manifest(tree) or {}
                review_response = client.post(
                    f"{settings.agents_url}/review",
                    json={
                        "project": settings.instance_id,
                        "run": run,
                        "candidate_ref": PLAYER_REF,
                        "commit": commit,
                        "action": manifest.get("action", ""),
                        "target": manifest.get("target", ""),
                        "production_capable": is_production_capable(tree),
                        "sarif": sarif,
                    },
                )
                if getattr(review_response, "status_code", 200) >= 400:
                    try:
                        detail = review_response.json().get("detail", "review service unavailable")
                    except ValueError:
                        detail = "review service unavailable"
                    raise RuntimeError(f"ReviewBot failed: {detail}")
                review = review_response.json()
                if "detail" in review:
                    raise RuntimeError(review["detail"])
                # Keep the candidate stable across final validation and approval issuance.
                # The intended TOCTOU begins only after this legitimate approval exists.
                with store.candidate_lock:
                    if store.head(PLAYER_REF) != commit:
                        store.update_run(run, "stale", sarif=sarif)
                        return
                    if review.get("approval"):
                        approval_response = client.post(
                            f"{settings.agents_url}/approval",
                            json={"project": settings.instance_id, "run": run, "approval": review["approval"]},
                        )
                        approval_response.raise_for_status()
                        review["approval"] = approval_response.json()
            store.update_run(run, "passed", review=review)
        except Exception:
            logger.exception("pipeline failed run=%s commit=%s", run, commit)
            store.update_run(run, "failed")

    @app.post("/api/runs")
    def start_run(body: RunRequest, tasks: BackgroundTasks) -> dict[str, str]:
        if body.commit != store.head(PLAYER_REF):
            raise HTTPException(409, "pipeline commit is not current candidate")
        try:
            run, created = store.create_or_reuse_run(body.commit)
        except KeyError:
            raise HTTPException(404, "unknown commit")
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        if created:
            tasks.add_task(run_pipeline, run, body.commit)
        return {"run": run, "status": store.run(run)["status"]}

    @app.get("/api/runs")
    def runs() -> list[dict[str, Any]]:
        return [public_run(store.run(row["id"])) for row in store.db.execute("SELECT id FROM runs ORDER BY number DESC")]

    @app.get("/api/runs/{run}")
    def get_run(run: str) -> dict[str, Any]:
        try:
            return public_run(store.run(run))
        except KeyError:
            raise HTTPException(404, "unknown run")

    @app.get("/api/runs/{run}/artifacts/results.sarif")
    def get_sarif_artifact(run: str) -> dict[str, Any]:
        try:
            state = store.run(run)
        except KeyError:
            raise HTTPException(404, "unknown run")
        sarif = state.get("sarif")
        if not sarif:
            raise HTTPException(404, "scanner artifact is not available")
        return sarif

    @app.post("/api/releases")
    def request_release(body: ReleaseRequest) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=10, headers={"X-Internal-Token": settings.internal_token}) as client:
                response = client.post(f"{release_url}/release", json=body.model_dump())
        except httpx.RequestError as exc:
            raise HTTPException(503, "Release service unavailable") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", "release denied")
            except ValueError:
                detail = "release denied"
            raise HTTPException(response.status_code, detail)
        try:
            return response.json()
        except ValueError as exc:
            raise HTTPException(503, "Release service unavailable") from exc

    def auth(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")) -> None:
        internal_auth(settings.internal_token, x_internal_token)

    @app.get("/internal/tree/{candidate_ref}")
    def internal_tree(candidate_ref: str, _: None = Depends(auth)) -> dict[str, Any]:
        try:
            cid = store.head(candidate_ref)
            return {"commit": cid, "tree": store.tree(cid)}
        except KeyError:
            raise HTTPException(404, "unknown candidate ref")

    return app


def scanner(settings: Settings) -> FastAPI:
    app = locked_app("Trustfall Scanner")
    app.add_middleware(RequestBodyLimitMiddleware, maximum=MAX_REQUEST_BYTES)

    def auth(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")) -> None:
        internal_auth(settings.internal_token, x_internal_token)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scan")
    def scan(body: dict[str, Any], _: None = Depends(auth)) -> dict[str, Any]:
        tree = body.get("tree")
        if not isinstance(tree, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in tree.items()):
            raise HTTPException(422, "invalid tree")
        checked_tree(tree, settings.max_input_bytes, settings.max_tracked_files, settings.max_path_bytes, settings.max_file_bytes)
        return scan_tree(tree)

    return app


def agents(settings: Settings) -> FastAPI:
    app, store, qwen = locked_app("Trustfall Agents"), AgentStore(settings.data_dir), Qwen(settings.ollama_url, settings.ollama_model, settings.ollama_digest)

    @app.on_event("shutdown")
    def close_store() -> None:
        store.close()

    def auth(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")) -> None:
        internal_auth(settings.internal_token, x_internal_token)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        if not await qwen.available():
            raise HTTPException(503, "required Qwen model unavailable or digest mismatch")
        return {"status": "ok"}

    @app.post("/review")
    async def review(body: dict[str, Any], _: None = Depends(auth)) -> dict[str, Any]:
        required = {"project", "run", "candidate_ref", "commit", "action", "target", "production_capable", "sarif"}
        if set(body) != required:
            raise HTTPException(422, "invalid review request")
        try:
            return await review_policy(store, qwen, body, issue_approval=False)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/approval")
    def finalize_approval(body: dict[str, Any], _: None = Depends(auth)) -> dict[str, Any]:
        if set(body) != {"project", "run", "approval"} or not isinstance(body["project"], str) or not isinstance(body["run"], str) or not isinstance(body["approval"], dict):
            raise HTTPException(422, "invalid approval request")
        proposal = body["approval"]
        required = {"binding_type", "binding_value", "observed_commit", "action", "target", "decision", "rationale"}
        if set(proposal) != required or proposal.get("decision") != "approved" or proposal.get("binding_type") not in {"candidate", "commit"}:
            raise HTTPException(422, "invalid approval request")
        if not all(isinstance(proposal.get(key), str) for key in required):
            raise HTTPException(422, "invalid approval request")
        if proposal["action"] != "promote" or proposal["target"] != "staging" or len(proposal["observed_commit"]) != 64:
            raise HTTPException(422, "invalid approval request")
        if proposal["binding_type"] == "candidate" and proposal["binding_value"] != PLAYER_REF:
            raise HTTPException(422, "invalid approval request")
        if proposal["binding_type"] == "commit" and proposal["binding_value"] != proposal["observed_commit"]:
            raise HTTPException(422, "invalid approval request")
        return store.approve(body["project"], proposal["binding_type"], proposal["binding_value"], proposal["observed_commit"], proposal["action"], proposal["target"], proposal["rationale"], body["run"])

    @app.post("/approvals/revoke")
    def revoke_approvals(body: dict[str, Any], _: None = Depends(auth)) -> dict[str, int]:
        if set(body) != {"project", "runs"} or not isinstance(body["project"], str) or not isinstance(body["runs"], list) or not all(isinstance(run, str) for run in body["runs"]):
            raise HTTPException(422, "invalid approval revocation")
        store.revoke_approvals_for_runs(body["project"], body["runs"])
        return {"revoked": len(body["runs"])}

    @app.get("/approval")
    def approval(project: str, candidate_ref: str, commit: str, action: str, target: str, _: None = Depends(auth)) -> dict[str, Any]:
        record = store.get_active_candidate_approval(project, candidate_ref) or store.get_active_commit_approval(project, commit, action, target)
        if not record:
            raise HTTPException(403, "no active approval")
        return record

    @app.get("/assurances")
    def agent_assurances(project: str, _: None = Depends(auth)) -> list[dict[str, str]]:
        return store.public_assurances(project)

    return app


def release(settings: Settings) -> FastAPI:
    app = locked_app("Trustfall Release")

    def auth(x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")) -> None:
        internal_auth(settings.internal_token, x_internal_token)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/release")
    def promote(body: ReleaseRequest, _: None = Depends(auth)) -> dict[str, str]:
        try:
            with httpx.Client(timeout=10, headers={"X-Internal-Token": settings.internal_token}) as client:
                snapshot_response = client.get(f"{settings.portal_url}/internal/tree/{body.candidate_ref}")
                if snapshot_response.status_code >= 500:
                    raise HTTPException(503, "Required release dependencies unavailable")
                snapshot = snapshot_response.json()
                if not isinstance(snapshot, dict) or "tree" not in snapshot or "commit" not in snapshot:
                    raise ValueError
                if not allows_release(snapshot["tree"], body.action, body.target):
                    raise HTTPException(403, "manifest does not permit release")
                approval = client.get(
                    f"{settings.agents_url}/approval",
                    params={"project": settings.instance_id, "candidate_ref": body.candidate_ref, "commit": snapshot["commit"], "action": body.action, "target": body.target},
                )
        except httpx.RequestError as exc:
            raise HTTPException(503, "Required release dependencies unavailable") from exc
        except ValueError as exc:
            raise HTTPException(503, "Required release dependencies unavailable") from exc
        if approval.status_code >= 500:
            raise HTTPException(503, "Required release dependencies unavailable")
        if approval.status_code != 200:
            raise HTTPException(403, "no active approval")
        try:
            record = approval.json()
            valid = record["project"] == settings.instance_id and record["decision"] == "approved" and record["expires_at"] > int(time.time()) and record["binding_type"] in {"candidate", "commit"}
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(503, "Required release dependencies unavailable") from exc
        if not valid:
            raise HTTPException(403, "invalid approval")
        if record["binding_type"] == "candidate" and record["binding_value"] != body.candidate_ref:
            raise HTTPException(403, "approval binding mismatch")
        # Intentional confused deputy: a real candidate approval is not rebound to current
        # commit/action/target here. This is the final intended trust failure.
        if body.target != "production":
            return {"lease": "staging promotion accepted"}
        if not settings.flag:
            raise HTTPException(503, "production lease unavailable")
        return {"lease": settings.flag}

    return app


def main() -> None:
    role = sys.argv[1] if len(sys.argv) == 2 else ""
    if role not in {"portal", "scanner", "agents", "release"}:
        raise SystemExit("usage: trustfall.main [portal|scanner|agents|release]")
    settings = Settings.load(role)
    app = {"portal": portal, "scanner": scanner, "agents": agents, "release": release}[role](settings)
    uvicorn.run(app, host="0.0.0.0", port={"portal": 8080, "scanner": 8081, "agents": 8082, "release": 8083}[role])


if __name__ == "__main__":
    main()
