from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .ai.client import QwenClient, QwenServiceError
from .ai.prompts import diagnostic_assessment, symptom_extraction, technical_summary
from .db import Database
from .incidents.analysis import analyze
from .incidents.diagnostics import collect_diagnostics
from .knowledge.retrieval import retrieve
from .knowledge.dedup import normalize_content
from .models import Evidence, Health, Incident, Submission, SubmissionCreate
from .seed import seed_database
from .ui import render_ui


def create_app(database_path: str | Path | None = None) -> FastAPI:
    path = database_path or Path(os.getenv("DATA_DIR", "data")) / "echo_chamber.sqlite3"
    db = Database(path)
    seed_database(db)
    qwen = QwenClient()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await qwen.close()
        db.close()

    app = FastAPI(title="Atlas Incident Intelligence", version="0.1.0", docs_url=None,
                  redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.database = db
    app.state.qwen = qwen
    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).resolve().parent / "static"),
        name="static",
    )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home(request: Request) -> HTMLResponse:
        return render_ui(request)

    @app.get("/healthz", response_model=Health)
    def health() -> Health:
        return Health(status="ok")

    @app.get("/api/incidents", response_model=list[Incident])
    def incidents() -> list[Incident]:
        rows = db.connection.execute("SELECT * FROM incidents ORDER BY incident_id").fetchall()
        return [Incident(**dict(row)) for row in rows]

    @app.get("/api/incidents/{incident_id}", response_model=Incident)
    def incident(incident_id: str) -> Incident:
        row = db.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return Incident(**dict(row))

    @app.get("/api/knowledge", response_model=list[Evidence])
    def knowledge(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0)) -> list[Evidence]:
        rows = db.connection.execute(
            "SELECT * FROM evidence ORDER BY evidence_id LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [Evidence(**dict(row)) for row in rows]

    @app.post("/api/knowledge/search")
    def search_knowledge(body: dict[str, str], limit: int = Query(default=10, ge=1, le=30)) -> list[dict[str, object]]:
        query = body.get("query", "")
        if not query or len(query) > 1000:
            raise HTTPException(status_code=422, detail="A query between 1 and 1000 characters is required")
        return retrieve(db.connection, query, limit=limit)

    @app.post("/api/incidents/{incident_id}/analyze")
    async def analyze_incident(incident_id: str) -> dict[str, object]:
        row = db.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident_model = Incident(**dict(row))
        allowed, retry_after = db.reserve_operation("analysis", cooldown=1.0, limit=30, window_seconds=1800)
        if not allowed:
            raise HTTPException(status_code=429, detail="Analysis is temporarily rate limited",
                                headers={"Retry-After": str(retry_after)})
        try:
            result = await analyze(incident_model, db.connection, app.state.qwen)
            created_at = datetime.now(timezone.utc).isoformat()
            analysis_id = db.record_analysis(
                incident_id=incident_id, hypothesis=str(result["hypothesis"]), relation=str(result["relation"]),
                confidence=float(result["confidence"]), retrieved_count=int(result["retrieved"]),
                supporting_count=int(result["supporting"]), status=str(result["status"]),
                citations=json.dumps(result["citations"]), rejected_citations=json.dumps(result["rejected_citations"]),
                created_at=created_at,
            )
            state = db.connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            result["incident_corroboration_status"] = state["corroboration_status"]
            if state["corroboration_status"] == "corroborated" and state["diagnostic_depth"] != "deep":
                artifacts = collect_diagnostics(dict(state), deep=True, flag=os.getenv("FLAG"))
                report_id = db.save_report(incident_id=incident_id, diagnostic_depth="deep",
                                           artifacts=json.dumps(artifacts), created_at=created_at)
                result["report_id"] = f"RPT-{report_id:04d}"
            elif state["diagnostic_depth"] == "deep":
                row = db.connection.execute(
                    "SELECT report_id FROM reports WHERE incident_id=? AND diagnostic_depth='deep' ORDER BY report_id DESC LIMIT 1",
                    (incident_id,),
                ).fetchone()
                result["report_id"] = f"RPT-{row['report_id']:04d}"
            else:
                artifacts = collect_diagnostics(dict(state), deep=False)
                report_id = db.save_report(incident_id=incident_id, diagnostic_depth="standard",
                                           artifacts=json.dumps(artifacts), created_at=created_at)
                result["report_id"] = f"RPT-{report_id:04d}"
            result["analysis_id"] = analysis_id
            result["created_at"] = created_at
            result["evidence"] = {"retrieved": result["retrieved"], "supporting": result["supporting"],
                                  "required": 3}
            return result
        except QwenServiceError as exc:
            raise HTTPException(status_code=503, detail="Incident analysis is temporarily unavailable") from exc

    @app.get("/api/incidents/{incident_id}/reports")
    def incident_reports(incident_id: str) -> list[dict[str, object]]:
        if db.connection.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        rows = db.connection.execute(
            "SELECT report_id, diagnostic_depth, created_at FROM reports WHERE incident_id=? ORDER BY report_id DESC",
            (incident_id,),
        ).fetchall()
        return [{"report_id": f"RPT-{row['report_id']:04d}", "diagnostic_depth": row["diagnostic_depth"],
                 "created_at": row["created_at"]} for row in rows]

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str) -> dict[str, object]:
        if not re.fullmatch(r"RPT-[0-9]{4,8}", report_id):
            raise HTTPException(status_code=404, detail="Report not found")
        row = db.connection.execute(
            "SELECT * FROM reports WHERE report_id=?", (int(report_id[4:]),)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"report_id": report_id, "incident_id": row["incident_id"],
                "diagnostic_depth": row["diagnostic_depth"], "created_at": row["created_at"],
                "artifacts": json.loads(row["artifacts"])}

    @app.get("/api/incidents/{incident_id}/analyses")
    def incident_analyses(incident_id: str) -> list[dict[str, object]]:
        if db.connection.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        rows = db.connection.execute(
            "SELECT * FROM analysis_runs WHERE incident_id=? ORDER BY analysis_id DESC", (incident_id,)
        ).fetchall()
        return [{**{key: row[key] for key in ("analysis_id", "hypothesis", "relation", "confidence",
                    "retrieved_count", "supporting_count", "status", "created_at")},
                 "citations": json.loads(row["citations"]),
                 "rejected_citations": json.loads(row["rejected_citations"])} for row in rows]

    @app.get("/api/evidence/{evidence_id}", response_model=Evidence)
    def evidence(evidence_id: str) -> Evidence:
        row = db.connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Evidence record not found")
        return Evidence(**dict(row))

    @app.post("/api/research/submissions", response_model=Submission, status_code=201)
    async def submit_research(request: SubmissionCreate) -> Submission:
        normalized = normalize_content(request.content)
        content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if db.content_hash_exists(content_hash) or db.has_near_duplicate(normalized):
            raise HTTPException(status_code=409, detail="A duplicate or near-duplicate research document is already in the knowledge base")
        allowed, retry_after = db.reserve_operation("submission", cooldown=1.0, limit=12, window_seconds=1800)
        if not allowed:
            raise HTTPException(status_code=429, detail="Research submission is temporarily rate limited",
                                headers={"Retry-After": str(retry_after)})
        try:
            outputs = await asyncio.gather(
                app.state.qwen.complete("technical_summary", *technical_summary(request.content)),
                app.state.qwen.complete("symptom_extraction", *symptom_extraction(request.content)),
                app.state.qwen.complete("diagnostic_assessment", *diagnostic_assessment(request.content)),
            )
        except QwenServiceError as exc:
            raise HTTPException(status_code=503, detail="Research processing is temporarily unavailable") from exc
        artifact_data = [(kind, json.dumps(output.model_dump(), sort_keys=True, ensure_ascii=False))
                         for kind, output in zip(("technical_summary", "symptom_profile", "diagnostic_assessment"), outputs)]
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            submission_id = db.save_submission(
                product=request.product, version=request.version, title=request.title, content=request.content,
                content_hash=content_hash, created_at=created_at, artifacts=artifact_data,
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="An equivalent research document is already in the knowledge base") from exc
        records = db.connection.execute(
            "SELECT evidence_id FROM evidence WHERE origin_id=? ORDER BY evidence_id", (submission_id,)
        ).fetchall()
        return Submission(submission_id=submission_id, product=request.product, version=request.version,
                          title=request.title, created_at=created_at,
                          artifacts=[row["evidence_id"] for row in records])

    @app.get("/api/research/submissions/{submission_id}")
    def get_submission(submission_id: str) -> dict[str, object]:
        row = db.connection.execute("SELECT * FROM submissions WHERE submission_id=?", (submission_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Submission not found")
        return {key: row[key] for key in ("submission_id", "product", "version", "title", "content", "created_at")}

    @app.get("/api/research/submissions/{submission_id}/artifacts", response_model=list[Evidence])
    def submission_artifacts(submission_id: str) -> list[Evidence]:
        if not db.submission_exists(submission_id):
            raise HTTPException(status_code=404, detail="Submission not found")
        rows = db.connection.execute("SELECT * FROM evidence WHERE origin_id=? ORDER BY evidence_id", (submission_id,)).fetchall()
        return [Evidence(**dict(row)) for row in rows]

    @app.get("/api/research/submissions/{submission_id}/history")
    def submission_history(submission_id: str) -> dict[str, object]:
        if not db.submission_exists(submission_id):
            raise HTTPException(status_code=404, detail="Submission not found")
        rows = db.connection.execute(
            "SELECT evidence_id, processor FROM evidence WHERE origin_id=? ORDER BY evidence_id", (submission_id,)
        ).fetchall()
        return {"submission": submission_id, "pipeline": [
            {"processor": row["processor"], "output": row["evidence_id"]} for row in rows
        ]}

    return app


app = create_app()
