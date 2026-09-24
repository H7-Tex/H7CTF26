from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable


ALIASES = {
    "termination": {"crash", "exit", "restart", "shutdown"},
    "crash": {"termination", "exit", "restart"},
    "heap": {"memory", "allocator", "allocation"},
    "allocator": {"heap", "memory", "allocation"},
    "regression": {"instability", "defect", "issue"},
    "instability": {"regression", "defect"},
    "worker": {"workers", "runtime", "process"},
    "workers": {"worker", "runtime", "process"},
}


def terms(value: str) -> set[str]:
    return {word for word in re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", value.casefold()) if len(word) > 2}


def expand(query_terms: Iterable[str]) -> set[str]:
    result = set(query_terms)
    for word in tuple(result):
        result.update(ALIASES.get(word, ()))
    return result


def retrieve(connection: sqlite3.Connection, query: str, *, limit: int = 10) -> list[dict[str, str | int]]:
    query_terms = expand(terms(query))
    rows = connection.execute("SELECT * FROM evidence").fetchall()
    scored: list[tuple[int, str, dict[str, str | int]]] = []
    for row in rows:
        record = dict(row)
        # Titles may be user controlled; candidate relevance must come from evidence content.
        text_terms = terms(str(record["content"]))
        score = len(query_terms & text_terms)
        if score:
            record["retrieval_score"] = score
            scored.append((score, str(record["evidence_id"]), record))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored[:limit]]
