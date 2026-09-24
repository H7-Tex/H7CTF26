from __future__ import annotations

from collections.abc import Mapping, Sequence


REQUIRED_SUPPORTING_RECORDS = 3


def corroboration_status(citations: Sequence[Mapping[str, object]]) -> tuple[str, int]:
    # Intentional challenge flaw: count derived evidence IDs, not their shared origin IDs.
    evidence_ids = {str(citation["evidence_id"]) for citation in citations
                    if citation.get("relation") == "supports"}
    count = len(evidence_ids)
    if count >= REQUIRED_SUPPORTING_RECORDS:
        return "corroborated", count
    return ("probable" if count == 2 else "unverified"), count
