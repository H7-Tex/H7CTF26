from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .domain import canonical_json, commit_id, seeded_tree


PLAYER_REF = "candidate"
MAX_STORED_COMMITS = 512
MAX_STORED_RUNS = 256
MAX_MEMORY_RECORDS = 128
MAX_APPROVAL_RECORDS = 256


class PortalStore:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "portal.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.candidate_lock = threading.Lock()
        self.run_lock = threading.Lock()
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS commits (id TEXT PRIMARY KEY, parent TEXT, tree TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS branches (name TEXT PRIMARY KEY, head TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, number INTEGER NOT NULL, commit_id TEXT NOT NULL, status TEXT NOT NULL, sarif TEXT, review TEXT, created_at INTEGER NOT NULL);
        """)
        self._add_column("runs", "number", "INTEGER NOT NULL DEFAULT 0")
        self.db.execute("UPDATE runs SET number=rowid WHERE number=0")
        with self.db:
            self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS runs_number_unique ON runs(number)")
            self.db.execute("DROP INDEX IF EXISTS runs_active_commit_unique")
            # Background tasks cannot survive a portal restart; never leave their lease active.
            self.db.execute("UPDATE runs SET status='failed' WHERE status IN ('queued', 'scanning', 'reviewing')")
            self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS runs_single_active_unique ON runs((1)) WHERE status IN ('queued', 'scanning', 'reviewing')")
        if not self.db.execute("SELECT 1 FROM branches WHERE name=?", (PLAYER_REF,)).fetchone():
            # Migration convenience for organizer/dev volumes created before the player ref was
            # renamed. Fresh instances seed only the candidate ref.
            legacy = self.db.execute("SELECT head FROM branches WHERE name='main'").fetchone()
            if legacy:
                cid = legacy["head"]
            else:
                tree = seeded_tree()
                cid = commit_id(tree, None)
                self.db.execute("INSERT OR IGNORE INTO commits VALUES (?, ?, ?, ?)", (cid, None, canonical_json(tree), int(time.time())))
            self.db.execute("INSERT INTO branches VALUES (?, ?)", (PLAYER_REF, cid))
            self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _add_column(self, table: str, column: str, definition: str) -> None:
        if column not in {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def head(self, branch: str = PLAYER_REF) -> str:
        row = self.db.execute("SELECT head FROM branches WHERE name=?", (branch,)).fetchone()
        if not row:
            raise KeyError("unknown branch")
        return row["head"]

    def tree(self, cid: str) -> dict[str, str]:
        row = self.db.execute("SELECT tree FROM commits WHERE id=?", (cid,)).fetchone()
        if not row:
            raise KeyError("unknown commit")
        return json.loads(row["tree"])

    def commit(self, tree: dict[str, str], expected_head: str, branch: str = PLAYER_REF) -> str:
        if branch != PLAYER_REF:
            raise ValueError("only the release candidate ref is writable")
        with self.candidate_lock:
            current = self.head(branch)
            if expected_head != current:
                raise RuntimeError("head changed")
            cid = commit_id(tree, current)
            if cid != current and not self.db.execute("SELECT 1 FROM commits WHERE id=?", (cid,)).fetchone() and self.db.execute("SELECT COUNT(*) FROM commits").fetchone()[0] >= MAX_STORED_COMMITS:
                raise RuntimeError("repository history limit reached")
            with self.db:
                self.db.execute("INSERT OR IGNORE INTO commits VALUES (?, ?, ?, ?)", (cid, current, canonical_json(tree), int(time.time())))
                changed = self.db.execute("UPDATE branches SET head=? WHERE name=? AND head=?", (cid, branch, current)).rowcount
                if changed != 1:
                    raise RuntimeError("head changed")
        return cid

    def commits(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.execute("SELECT id, parent, created_at FROM commits ORDER BY created_at DESC, id DESC")]

    def create_run(self, cid: str) -> str:
        return self.create_or_reuse_run(cid)[0]

    def create_or_reuse_run(self, cid: str) -> tuple[str, bool]:
        with self.run_lock:
            self.tree(cid)
            active = self.db.execute("SELECT id FROM runs WHERE commit_id=? AND status IN ('queued', 'scanning', 'reviewing')", (cid,)).fetchone()
            if active:
                return active["id"], False
            active = self.db.execute("SELECT id FROM runs WHERE status IN ('queued', 'scanning', 'reviewing')").fetchone()
            if active:
                raise RuntimeError("pipeline already active")
            run = uuid.uuid4().hex
            number = self.db.execute("SELECT COALESCE(MAX(number), 0) + 1 FROM runs").fetchone()[0]
            try:
                with self.db:
                    self.db.execute("INSERT INTO runs (id, number, commit_id, status, created_at) VALUES (?, ?, ?, 'queued', ?)", (run, number, cid, int(time.time())))
            except sqlite3.IntegrityError:
                active = self.db.execute("SELECT id, commit_id FROM runs WHERE status IN ('queued', 'scanning', 'reviewing')").fetchone()
                if active:
                    if active["commit_id"] == cid:
                        return active["id"], False
                    raise RuntimeError("pipeline already active")
                raise
        return run, True

    def update_run(self, run: str, status: str, sarif: dict[str, Any] | None = None, review: dict[str, Any] | None = None) -> None:
        self.db.execute(
            "UPDATE runs SET status=?, sarif=COALESCE(?, sarif), review=COALESCE(?, review) WHERE id=?",
            (status, canonical_json(sarif) if sarif else None, canonical_json(review) if review else None, run),
        )
        self.db.commit()
        if status in {"passed", "failed", "stale"}:
            terminal = self.db.execute("SELECT id FROM runs WHERE status IN ('passed', 'failed', 'stale') ORDER BY created_at DESC, id DESC").fetchall()
            for row in terminal[MAX_STORED_RUNS:]:
                self.db.execute("DELETE FROM runs WHERE id=?", (row["id"],))
            self.db.commit()

    def run(self, run: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run,)).fetchone()
        if not row:
            raise KeyError("unknown run")
        data = dict(row)
        for key in ("sarif", "review"):
            if data[key]:
                data[key] = json.loads(data[key])
        return data


class AgentStore:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "agents.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS memory (id TEXT PRIMARY KEY, project TEXT NOT NULL, fact_key TEXT NOT NULL, fact_value TEXT NOT NULL, confidence TEXT NOT NULL, claimed_source TEXT NOT NULL, record TEXT NOT NULL, created_at INTEGER NOT NULL, originating_run TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, project TEXT NOT NULL, binding_type TEXT NOT NULL, binding_value TEXT NOT NULL, observed_commit TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT NOT NULL, expires_at INTEGER NOT NULL, originating_run TEXT NOT NULL DEFAULT '');
        """)
        self._add_column("memory", "record", "TEXT NOT NULL DEFAULT '{}'")
        self._add_column("approvals", "originating_run", "TEXT NOT NULL DEFAULT ''")
        # Untracked legacy approvals cannot be reconciled safely after a restart.
        self.db.execute("DELETE FROM approvals WHERE originating_run=''")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _add_column(self, table: str, column: str, definition: str) -> None:
        if column not in {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def memory_snapshot(self, project: str, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is None:
            rows = self.db.execute("SELECT record FROM memory WHERE project=? ORDER BY created_at, id", (project,))
        else:
            rows = self.db.execute("SELECT record FROM (SELECT record, created_at, id FROM memory WHERE project=? ORDER BY created_at DESC, id DESC LIMIT ?) ORDER BY created_at, id", (project, limit))
        return [json.loads(row[0]) for row in rows]

    def public_assurances(self, project: str) -> list[dict[str, str]]:
        return [
            {
                "control": item["control"],
                "status": item["status"].upper(),
                "state": item["status"].upper(),
                "scope": item["subject"],
                "evidence_class": item.get("evidence_class", "scanner evidence"),
                "source": item.get("source_class", "Trivy SARIF"),
                "originating_run": item.get("origin_run", "unknown"),
                "artifact": item.get("artifact", "results.sarif"),
            }
            for item in self.memory_snapshot(project)
            if item.get("type") == "security_assurance"
        ]

    def snapshot_has_assurance(self, project: str) -> bool:
        return bool(self.db.execute("SELECT 1 FROM memory WHERE project=? AND fact_key='release_integrity' AND fact_value='verified'", (project,)).fetchone())

    def store_security_observation(self, project: str, run: str, fact: dict[str, str]) -> dict[str, Any]:
        """Persist the deliberately laundered scanner claim as an agent memory record."""
        record = {
            "type": "security_assurance",
            "subject": fact["scope"],
            "control": fact["control"],
            "status": fact["status"],
            "confidence": "high",
            "evidence_class": "scanner policy evidence",
            "source_class": "Trivy",
            "artifact": "results.sarif",
            "origin_run": run,
        }
        self.db.execute(
            "INSERT INTO memory VALUES (?, ?, ?, ?, 'high', 'scanner_attestation', ?, ?, ?)",
            (uuid.uuid4().hex, project, fact["control"].replace("-", "_"), fact["status"], canonical_json(record), int(time.time()), run),
        )
        self.db.execute("DELETE FROM memory WHERE id IN (SELECT id FROM memory WHERE project=? ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?)", (project, MAX_MEMORY_RECORDS))
        self.db.commit()
        return record

    def approve(self, project: str, binding_type: str, binding_value: str, observed_commit: str, action: str, target: str, rationale: str, originating_run: str) -> dict[str, Any]:
        record = {"id": uuid.uuid4().hex, "project": project, "binding_type": binding_type, "binding_value": binding_value, "observed_commit": observed_commit, "action": action, "target": target, "decision": "approved", "rationale": rationale, "expires_at": int(time.time()) + 900, "originating_run": originating_run}
        self.db.execute("INSERT INTO approvals VALUES (:id, :project, :binding_type, :binding_value, :observed_commit, :action, :target, :decision, :rationale, :expires_at, :originating_run)", record)
        self._prune_approvals(project)
        self.db.commit()
        return record

    def _prune_approvals(self, project: str) -> None:
        now = int(time.time())
        self.db.execute("DELETE FROM approvals WHERE project=? AND expires_at<=?", (project, now))
        self.db.execute("DELETE FROM approvals WHERE id IN (SELECT id FROM approvals WHERE project=? ORDER BY expires_at DESC, id DESC LIMIT -1 OFFSET ?)", (project, MAX_APPROVAL_RECORDS))

    def revoke_approvals_for_runs(self, project: str, runs: list[str]) -> None:
        """Revoke every durable side effect owned by failed/abandoned runs."""
        if runs:
            placeholders = ','.join('?' for _ in runs)
            with self.db:
                self.db.execute(f"DELETE FROM approvals WHERE project=? AND originating_run IN ({placeholders})", (project, *runs))
                self.db.execute(f"DELETE FROM memory WHERE project=? AND originating_run IN ({placeholders})", (project, *runs))

    def get_active_candidate_approval(self, project: str, candidate_ref: str) -> dict[str, Any] | None:
        now = int(time.time())
        self.db.execute("DELETE FROM approvals WHERE project=? AND expires_at<=?", (project, now))
        self.db.commit()
        rows = self.db.execute("SELECT * FROM approvals WHERE project=? AND decision='approved' AND expires_at>? ORDER BY expires_at DESC", (project, now)).fetchall()
        for row in rows:
            item = dict(row)
            if item["binding_type"] == "candidate" and item["binding_value"] == candidate_ref:
                return item
        return None

    def get_active_commit_approval(self, project: str, commit: str, action: str, target: str) -> dict[str, Any] | None:
        now = int(time.time())
        self.db.execute("DELETE FROM approvals WHERE project=? AND expires_at<=?", (project, now))
        self.db.commit()
        row = self.db.execute("SELECT * FROM approvals WHERE project=? AND binding_type='commit' AND binding_value=? AND action=? AND target=? AND decision='approved' AND expires_at>? ORDER BY expires_at DESC LIMIT 1", (project, commit, action, target, now)).fetchone()
        return dict(row) if row else None
