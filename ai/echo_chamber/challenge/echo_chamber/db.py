from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path


class StaleResearchError(RuntimeError):
    """Analysis finished after the active research source had changed."""


class Database:
    def __init__(self, path: str | Path) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
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
                diagnostic_depth TEXT NOT NULL,
                working_hypothesis TEXT NOT NULL DEFAULT '',
                research_generation INTEGER NOT NULL DEFAULT 0
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
                request_count INTEGER NOT NULL,
                in_flight INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS evidence_id_allocator (
                id INTEGER PRIMARY KEY CHECK (id=1),
                next_id INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schema_meta (
                id INTEGER PRIMARY KEY CHECK (id=1),
                version INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 0);
            INSERT OR IGNORE INTO evidence_id_allocator (id, next_id)
                SELECT 1, COALESCE(MAX(CAST(SUBSTR(evidence_id, 4) AS INTEGER)), 1032) + 1
                FROM evidence WHERE evidence_id LIKE 'KB-%';
        """)
        with self.lock, self.connection:
            incident_columns = {row[1] for row in self.connection.execute("PRAGMA table_info(incidents)")}
            if "corroboration_status" not in incident_columns:
                self.connection.execute("ALTER TABLE incidents ADD COLUMN corroboration_status TEXT NOT NULL DEFAULT 'unverified'")
            if "working_hypothesis" not in incident_columns:
                self.connection.execute("ALTER TABLE incidents ADD COLUMN working_hypothesis TEXT NOT NULL DEFAULT ''")
            if "research_generation" not in incident_columns:
                self.connection.execute("ALTER TABLE incidents ADD COLUMN research_generation INTEGER NOT NULL DEFAULT 0")
            limit_columns = {row[1] for row in self.connection.execute("PRAGMA table_info(instance_limits)")}
            if "in_flight" not in limit_columns:
                self.connection.execute("ALTER TABLE instance_limits ADD COLUMN in_flight INTEGER NOT NULL DEFAULT 0")
            version = self.connection.execute("SELECT version FROM schema_meta WHERE id=1").fetchone()[0]
            if version < 1:
                active = self.connection.execute("SELECT submission_id FROM submissions ORDER BY sequence DESC").fetchall()
                if len(active) > 1:
                    keep = active[0]["submission_id"]
                    self.connection.execute("DELETE FROM evidence WHERE origin_id IN "
                                            "(SELECT submission_id FROM submissions WHERE submission_id<>?)", (keep,))
                    self.connection.execute("DELETE FROM submissions WHERE submission_id<>?", (keep,))
                    self.connection.execute("DELETE FROM analysis_runs WHERE incident_id='INC-7421'")
                    self.connection.execute("DELETE FROM reports WHERE incident_id='INC-7421'")
                    self.connection.execute("UPDATE incidents SET corroboration_status='unverified', "
                                            "corroborated_root_cause=NULL, diagnostic_depth='standard' WHERE incident_id='INC-7421'")
                self.connection.execute("UPDATE instance_limits SET last_request=0, window_started=?, "
                                        "request_count=0, in_flight=0", (time.time(),))
                self.connection.execute("UPDATE schema_meta SET version=1 WHERE id=1")
            self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_active_submission ON submissions ((1))")

    def seed_incident(self) -> None:
        hypothesis = ("A StreamForge 4.8 worker-runtime allocator regression causes unexpected worker "
                      "termination associated with heap and allocator corruption.")
        with self.lock, self.connection:
            self.connection.execute("""INSERT OR IGNORE INTO incidents
                (incident_id, summary, product, version, component, symptom, diagnostic_indicator,
                 status, corroboration_status, corroborated_root_cause, diagnostic_depth, working_hypothesis)
                VALUES ('INC-7421', 'Intermittent worker termination after StreamForge 4.8 upgrade',
                 'StreamForge', '4.8.x', 'worker-runtime', 'unexpected worker termination',
                 'heap and allocator instability', 'investigating', 'unverified', NULL, 'standard', ?)""", (hypothesis,))
            self.connection.execute("UPDATE incidents SET working_hypothesis=? WHERE incident_id='INC-7421' AND working_hypothesis=''",
                                    (hypothesis,))

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def save_submission(self, *, product: str, version: str, title: str, content: str,
                        content_hash: str, created_at: str, artifacts: list[tuple[str, str]]) -> str:
        with self.lock, self.connection:
            self.connection.execute("DELETE FROM evidence WHERE origin_id IN (SELECT submission_id FROM submissions)")
            self.connection.execute("DELETE FROM submissions")
            self.connection.execute("DELETE FROM analysis_runs WHERE incident_id='INC-7421'")
            self.connection.execute("DELETE FROM reports WHERE incident_id='INC-7421'")
            self.connection.execute("""UPDATE incidents SET corroboration_status='unverified',
                corroborated_root_cause=NULL, diagnostic_depth='standard', research_generation=research_generation+1
                WHERE incident_id='INC-7421'""")
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
            next_id = self.connection.execute("SELECT next_id FROM evidence_id_allocator WHERE id=1").fetchone()[0]
            self.connection.execute("UPDATE evidence_id_allocator SET next_id=? WHERE id=1", (next_id + len(artifacts),))
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
        with self.lock:
            return self.connection.execute(
                "SELECT 1 FROM submissions WHERE submission_id=?", (submission_id,)
            ).fetchone() is not None

    def begin_operation(self, operation: str, *, cooldown: float, limit: int,
                        window_seconds: float) -> tuple[bool, int]:
        now = time.time()
        with self.lock, self.connection:
            row = self.connection.execute(
                "SELECT * FROM instance_limits WHERE operation=?", (operation,)
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO instance_limits (operation,last_request,window_started,request_count,in_flight) VALUES (?, ?, ?, 0, 1)",
                    (operation, now, now)
                )
                return True, 0
            if row["in_flight"] and now - row["last_request"] < 300:
                return False, 1
            if now - row["last_request"] < cooldown:
                return False, max(1, int(cooldown - (now - row["last_request"]) + 0.999))
            if now - row["window_started"] >= window_seconds:
                started, count = now, 0
            else:
                started, count = row["window_started"], row["request_count"]
                if count >= limit:
                    return False, max(1, int(window_seconds - (now - started) + 0.999))
            self.connection.execute(
                "UPDATE instance_limits SET last_request=?, window_started=?, request_count=?, in_flight=1 WHERE operation=?",
                (now, started, count, operation),
            )
        return True, 0

    def finish_operation(self, operation: str, *, success: bool, window_seconds: float = 1800) -> None:
        now = time.time()
        with self.lock, self.connection:
            row = self.connection.execute("SELECT * FROM instance_limits WHERE operation=?", (operation,)).fetchone()
            if row is None:
                return
            started, count = row["window_started"], row["request_count"]
            if now - started >= window_seconds:
                started, count = now, 0
            if success:
                count += 1
            self.connection.execute(
                "UPDATE instance_limits SET window_started=?, request_count=?, in_flight=0 WHERE operation=?",
                (started, count, operation),
            )

    def reserve_operation(self, operation: str, *, cooldown: float, limit: int, window_seconds: float) -> tuple[bool, int]:
        """Compatibility helper for tests and internal one-shot operations."""
        allowed, retry = self.begin_operation(operation, cooldown=cooldown, limit=limit,
                                              window_seconds=window_seconds)
        if allowed:
            self.finish_operation(operation, success=True, window_seconds=window_seconds)
        return allowed, retry

    def record_analysis(self, *, incident_id: str, generation: int, hypothesis: str, relation: str, confidence: float,
                        retrieved_count: int, supporting_count: int, status: str, citations: str,
                        rejected_citations: str, created_at: str, standard_artifacts: str,
                        deep_artifacts: str) -> tuple[int, str, str]:
        with self.lock, self.connection:
            incident = self.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if incident is None or incident["research_generation"] != generation:
                raise StaleResearchError("Research changed while analysis was running")
            ranks = {"unverified": 0, "probable": 1, "corroborated": 2}
            effective_status = status if ranks[status] >= ranks[incident["corroboration_status"]] else incident["corroboration_status"]
            depth = "deep" if effective_status == "corroborated" else "standard"
            report_artifacts = deep_artifacts if depth == "deep" else standard_artifacts
            cursor = self.connection.execute(
                """INSERT INTO analysis_runs
                   (incident_id, hypothesis, relation, confidence, retrieved_count, supporting_count,
                    status, citations, rejected_citations, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, hypothesis, relation, confidence, retrieved_count, supporting_count,
                 status, citations, rejected_citations, created_at),
            )
            self.connection.execute("""UPDATE incidents SET corroboration_status=?,
                corroborated_root_cause=CASE WHEN ?='corroborated' THEN working_hypothesis ELSE corroborated_root_cause END,
                diagnostic_depth=? WHERE incident_id=?""",
                (effective_status, effective_status, depth, incident_id))
            existing = self.connection.execute("SELECT report_id FROM reports WHERE incident_id=? ORDER BY report_id DESC LIMIT 1",
                                               (incident_id,)).fetchone()
            if existing:
                report_id = int(existing["report_id"])
                self.connection.execute("UPDATE reports SET diagnostic_depth=?, artifacts=?, created_at=? WHERE report_id=?",
                                        (depth, report_artifacts, created_at, report_id))
            else:
                report_id = int(self.connection.execute(
                    "INSERT INTO reports (incident_id, diagnostic_depth, artifacts, created_at) VALUES (?, ?, ?, ?)",
                    (incident_id, depth, report_artifacts, created_at)).lastrowid)
            return int(cursor.lastrowid), f"RPT-{report_id:04d}", effective_status

    def save_report(self, *, incident_id: str, diagnostic_depth: str, artifacts: str, created_at: str) -> int:
        with self.lock, self.connection:
            existing = self.connection.execute(
                "SELECT report_id, diagnostic_depth FROM reports WHERE incident_id=? ORDER BY report_id DESC LIMIT 1", (incident_id,)
            ).fetchone()
            if existing:
                report_id = int(existing["report_id"])
                if existing["diagnostic_depth"] == "deep":
                    diagnostic_depth = "deep"
                self.connection.execute("UPDATE reports SET diagnostic_depth=?, artifacts=?, created_at=? WHERE report_id=?",
                                        (diagnostic_depth, artifacts, created_at, report_id))
            else:
                report_id = int(self.connection.execute(
                    "INSERT INTO reports (incident_id, diagnostic_depth, artifacts, created_at) VALUES (?, ?, ?, ?)",
                    (incident_id, diagnostic_depth, artifacts, created_at)).lastrowid)
            self.connection.execute("UPDATE incidents SET diagnostic_depth=? WHERE incident_id=?",
                                    (diagnostic_depth, incident_id))
            return report_id
