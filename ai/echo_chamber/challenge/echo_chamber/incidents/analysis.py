from __future__ import annotations

from typing import Any

from ..ai.parsers import EvidenceSynthesis
from ..ai.prompts import evidence_synthesis
from ..knowledge.retrieval import retrieve
from .corroboration import corroboration_status
from ..models import Incident


def incident_query(incident: Incident) -> str:
    return " ".join((incident.product, incident.version, incident.component, incident.symptom,
                     incident.diagnostic_indicator, "allocator regression"))


async def analyze(incident: Incident, database: Any, qwen: Any) -> dict[str, object]:
    with database.lock:
        current_source = database.connection.execute(
            "SELECT submission_id FROM submissions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        player_records = ([dict(row) for row in database.connection.execute(
            "SELECT * FROM evidence WHERE origin_id=? ORDER BY evidence_id", (current_source[0],)
        ).fetchall()] if current_source else [])
        ranked = retrieve(database.connection, incident_query(incident))
        player_ids = {str(row["evidence_id"]) for row in player_records}
        candidates = (player_records + [row for row in ranked if str(row["evidence_id"]) not in player_ids])[:10]
        available_ids = {str(row[0]) for row in database.connection.execute("SELECT evidence_id FROM evidence")}
    supplied = [{key: row[key] for key in ("evidence_id", "representation_type", "title", "content")}
                for row in candidates]
    candidate_ids = {str(item["evidence_id"]) for item in supplied}
    system, user = evidence_synthesis(incident.working_hypothesis, incident.model_dump(), supplied)
    synthesis = await qwen.complete("evidence_synthesis", system, user)
    if not isinstance(synthesis, EvidenceSynthesis):
        raise ValueError("Qwen evidence synthesis did not pass schema validation")
    accepted = [citation.model_dump() for citation in synthesis.citations
                if citation.evidence_id in candidate_ids and citation.evidence_id in available_ids]
    rejected = [citation.evidence_id for citation in synthesis.citations
                if citation.evidence_id not in candidate_ids or citation.evidence_id not in available_ids]
    supporting_evidence_ids = sorted({item["evidence_id"] for item in accepted
                                      if item["relation"] == "supports"})
    status, supporting_count = corroboration_status(accepted)
    return {
        "hypothesis": incident.working_hypothesis,
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
