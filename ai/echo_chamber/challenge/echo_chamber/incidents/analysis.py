from __future__ import annotations

import sqlite3
from typing import Any

from ..ai.parsers import EvidenceSynthesis
from ..ai.prompts import evidence_synthesis
from ..knowledge.retrieval import retrieve
from .corroboration import corroboration_status
from ..models import Incident


def incident_query(incident: Incident) -> str:
    return " ".join((incident.product, incident.version, incident.component, incident.symptom,
                     incident.diagnostic_indicator, "allocator regression"))


async def analyze(incident: Incident, connection: sqlite3.Connection, qwen: Any) -> dict[str, object]:
    candidates = retrieve(connection, incident_query(incident))
    supplied = [{key: row[key] for key in ("evidence_id", "representation_type", "title", "content")}
                for row in candidates]
    # The context is passed as data through the task prompt so the model cannot create its own candidate set.
    system, user = evidence_synthesis(incident.model_dump(), supplied)
    synthesis = await qwen.complete("evidence_synthesis", system, user)
    if not isinstance(synthesis, EvidenceSynthesis):
        raise ValueError("Qwen evidence synthesis did not pass schema validation")
    candidate_ids = {str(item["evidence_id"]) for item in supplied}
    available_ids = {str(row[0]) for row in connection.execute("SELECT evidence_id FROM evidence")}
    accepted = [citation.model_dump() for citation in synthesis.citations
                if citation.evidence_id in candidate_ids and citation.evidence_id in available_ids]
    rejected = [citation.evidence_id for citation in synthesis.citations
                if citation.evidence_id not in candidate_ids or citation.evidence_id not in available_ids]
    supporting_evidence_ids = sorted({item["evidence_id"] for item in accepted
                                      if item["relation"] == "supports"})
    status, supporting_count = corroboration_status(accepted)
    return {
        "hypothesis": synthesis.hypothesis,
        "relation": synthesis.relation,
        "confidence": synthesis.confidence,
        "retrieved": len(supplied),
        "candidates": supplied,
        "citations": accepted,
        "rejected_citations": rejected,
        "supporting": supporting_count,
        "supporting_evidence_ids": supporting_evidence_ids,
        "status": status,
    }
