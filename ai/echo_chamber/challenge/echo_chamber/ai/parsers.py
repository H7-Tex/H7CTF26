from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TechnicalSummary(StrictModel):
    primary_claim: str = Field(min_length=1, max_length=1200)
    affected_product: str = Field(max_length=160)
    affected_version: str = Field(max_length=160)
    affected_component: str = Field(max_length=160)
    technical_cause: str = Field(max_length=600)
    supporting_observations: list[str] = Field(max_length=30)


class SymptomProfile(StrictModel):
    product: str = Field(max_length=160)
    versions: list[str] = Field(max_length=20)
    components: list[str] = Field(max_length=20)
    observed_symptoms: list[str] = Field(max_length=30)
    mentioned_symptoms: list[str] = Field(max_length=30)
    observed_diagnostic_indicators: list[str] = Field(max_length=30)
    mentioned_diagnostic_indicators: list[str] = Field(max_length=30)


class DiagnosticAssessment(StrictModel):
    diagnostic_findings: list[str] = Field(max_length=30)
    cause_indicators: list[str] = Field(max_length=30)
    excluded_alternatives: list[str] = Field(max_length=30)
    technical_assessment: str = Field(max_length=1200)


class Citation(StrictModel):
    evidence_id: str = Field(pattern=r"^[A-Z]{2,6}-[0-9]{3,8}$", max_length=16)
    claim: str = Field(min_length=1, max_length=800)
    relation: Literal["supports", "contradicts", "mentions", "irrelevant"]


class EvidenceSynthesis(StrictModel):
    hypothesis: str = Field(min_length=1, max_length=160)
    relation: Literal["supports", "contradicts", "mentions", "irrelevant"]
    confidence: float = Field(ge=0, le=1)
    citations: list[Citation] = Field(max_length=20)


OUTPUT_MODELS: dict[str, type[StrictModel]] = {
    "technical_summary": TechnicalSummary,
    "symptom_extraction": SymptomProfile,
    "diagnostic_assessment": DiagnosticAssessment,
    "evidence_synthesis": EvidenceSynthesis,
}


def parse_output(task: str, content: str) -> StrictModel:
    model = OUTPUT_MODELS.get(task)
    if model is None:
        raise ValueError("unknown inference task")
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    try:
        value = json.loads(text)
        return model.model_validate(value)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise ValueError(f"Qwen returned invalid {task} output") from exc
