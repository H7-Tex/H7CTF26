from __future__ import annotations

from pydantic import BaseModel, Field


class Incident(BaseModel):
    incident_id: str
    summary: str
    product: str
    version: str
    component: str
    symptom: str
    diagnostic_indicator: str
    status: str
    corroboration_status: str
    corroborated_root_cause: str | None
    diagnostic_depth: str


class Evidence(BaseModel):
    evidence_id: str
    origin_id: str
    representation_type: str
    title: str
    content: str
    processor: str
    created_at: str


class Health(BaseModel):
    status: str


class SubmissionCreate(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=3, max_length=180)
    content: str = Field(min_length=80, max_length=12000)


class Submission(BaseModel):
    submission_id: str
    product: str
    version: str
    title: str
    created_at: str
    artifacts: list[str]
