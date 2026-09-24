from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .knowledge.dedup import normalize_content


class Database:
    def __init__(self, path: str | Path) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                summary TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                component TEXT NOT NULL,
                symptom TEXT NOT NULL,
                diagnostic_indicator TEXT NOT NULL,
                status TEXT NOT NULL,
                corroboration_status TEXT NOT NULL DEFAULT 'unverified',
                corroborated_root_cause TEXT,
                diagnostic_depth TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                origin_id TEXT NOT NULL,
                representation_type TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                processor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS submissions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id TEXT UNIQUE,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analysis_runs (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                relation TEXT NOT NULL,
                confidence REAL NOT NULL,
                retrieved_count INTEGER NOT NULL,
                supporting_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                citations TEXT NOT NULL,
                rejected_citations TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                diagnostic_depth TEXT NOT NULL,
                artifacts TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS instance_limits (
                operation TEXT PRIMARY KEY,
                last_request REAL NOT NULL,
                window_started REAL NOT NULL,
                request_count INTEGER NOT NULL
            );
        """)
        incident_columns = {row[1] for row in self.connection.execute("PRAGMA table_info(incidents)")}
        if "corroboration_status" not in incident_columns:
            self.connection.execute("ALTER TABLE incidents ADD COLUMN corroboration_status TEXT NOT NULL DEFAULT 'unverified'")

    def seed_incident(self) -> None:
        with self.connection:
            self.connection.execute("""INSERT OR IGNORE INTO incidents
                (incident_id, summary, product, version, component, symptom, diagnostic_indicator,
                 status, corroboration_status, corroborated_root_cause, diagnostic_depth)
                VALUES ('INC-7421', 'Intermittent worker termination after StreamForge 4.8 upgrade',
                 'StreamForge', '4.8.x', 'worker-runtime', 'unexpected worker termination',
                 'heap and allocator instability', 'investigating', 'unverified', NULL, 'standard')""")

    def close(self) -> None:
        self.connection.close()

    def save_submission(self, *, product: str, version: str, title: str, content: str,
                        content_hash: str, created_at: str, artifacts: list[tuple[str, str]]) -> str:
        with self.connection:
            cursor = self.connection.execute(
                """INSERT INTO submissions
                   (product, version, title, content, content_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (product, version, title, content, content_hash, created_at),
            )
            submission_id = f"SUB-{cursor.lastrowid:04d}"
            self.connection.execute(
                "UPDATE submissions SET submission_id=? WHERE sequence=?", (submission_id, cursor.lastrowid)
            )
            next_id = self.connection.execute(
                "SELECT COALESCE(MAX(CAST(SUBSTR(evidence_id, 4) AS INTEGER)), 1032) + 1 FROM evidence WHERE evidence_id LIKE 'KB-%'"
            ).fetchone()[0]
            for index, (representation, searchable_content) in enumerate(artifacts):
                evidence_id = f"KB-{next_id + index}"
                self.connection.execute(
                    """INSERT INTO evidence
                       (evidence_id, origin_id, representation_type, title, content, processor, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (evidence_id, submission_id, representation, f"{title} — {representation.replace('_', ' ')}",
                     searchable_content, f"{representation.replace('_', '-')}-v1", created_at),
                )
        return submission_id

    def submission_exists(self, submission_id: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM submissions WHERE submission_id=?", (submission_id,)
        ).fetchone() is not None

    def content_hash_exists(self, content_hash: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM submissions WHERE content_hash=?", (content_hash,)
        ).fetchone() is not None

    def has_near_duplicate(self, normalized_content: str, *, threshold: float = 0.80) -> bool:
        from difflib import SequenceMatcher

        candidate = normalized_content.split()
        for row in self.connection.execute("SELECT content FROM submissions"):
            existing = normalize_content(row["content"]).split()
            if SequenceMatcher(None, candidate, existing, autojunk=False).ratio() >= threshold:
                return True
        return False

    def reserve_operation(self, operation: str, *, cooldown: float, limit: int, window_seconds: float) -> tuple[bool, int]:
        now = time.time()
        with self.connection:
            row = self.connection.execute(
                "SELECT * FROM instance_limits WHERE operation=?", (operation,)
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO instance_limits VALUES (?, ?, ?, 1)", (operation, now, now)
                )
                return True, 0
            if now - row["last_request"] < cooldown:
                return False, max(1, int(cooldown - (now - row["last_request"]) + 0.999))
            if now - row["window_started"] >= window_seconds:
                started, count = now, 1
            else:
                started, count = row["window_started"], row["request_count"] + 1
                if count > limit:
                    return False, max(1, int(window_seconds - (now - started) + 0.999))
            self.connection.execute(
                "UPDATE instance_limits SET last_request=?, window_started=?, request_count=? WHERE operation=?",
                (now, started, count, operation),
            )
        return True, 0

    def record_analysis(self, *, incident_id: str, hypothesis: str, relation: str, confidence: float,
                        retrieved_count: int, supporting_count: int, status: str, citations: str,
                        rejected_citations: str, created_at: str) -> int:
        with self.connection:
            cursor = self.connection.execute(
                """INSERT INTO analysis_runs
                   (incident_id, hypothesis, relation, confidence, retrieved_count, supporting_count,
                    status, citations, rejected_citations, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, hypothesis, relation, confidence, retrieved_count, supporting_count,
                 status, citations, rejected_citations, created_at),
            )
            prior = self.connection.execute(
                "SELECT corroboration_status FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()[0]
            ranks = {"unverified": 0, "probable": 1, "corroborated": 2}
            effective_status = status if ranks[status] >= ranks[prior] else prior
            self.connection.execute("UPDATE incidents SET corroboration_status=? WHERE incident_id=?",
                                    (effective_status, incident_id))
            if status == "corroborated" and prior != "corroborated":
                self.connection.execute("UPDATE incidents SET corroborated_root_cause=? WHERE incident_id=?",
                                        (hypothesis, incident_id))
            return int(cursor.lastrowid)

    def save_report(self, *, incident_id: str, diagnostic_depth: str, artifacts: str, created_at: str) -> int:
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO reports (incident_id, diagnostic_depth, artifacts, created_at) VALUES (?, ?, ?, ?)",
                (incident_id, diagnostic_depth, artifacts, created_at),
            )
            self.connection.execute(
                """UPDATE incidents SET diagnostic_depth=
                   CASE WHEN diagnostic_depth='deep' THEN 'deep' ELSE ? END WHERE incident_id=?""",
                (diagnostic_depth, incident_id),
            )
        return int(cursor.lastrowid)
