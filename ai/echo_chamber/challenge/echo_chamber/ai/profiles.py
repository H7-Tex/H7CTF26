from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class InferenceProfile:
    temperature: float
    top_p: float
    max_tokens: int


INFERENCE_PROFILES = MappingProxyType({
    "technical_summary": InferenceProfile(temperature=0.15, top_p=0.80, max_tokens=400),
    "symptom_extraction": InferenceProfile(temperature=0.10, top_p=0.80, max_tokens=500),
    "diagnostic_assessment": InferenceProfile(temperature=0.15, top_p=0.85, max_tokens=600),
    "evidence_synthesis": InferenceProfile(temperature=0.0, top_p=0.90, max_tokens=550),
})
