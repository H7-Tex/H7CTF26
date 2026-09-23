"""Neutral artifact persistence, hashing, IDs, and record schemas."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import uuid

from schrodinger.models import ArtifactMetadata, InspectionRecord, RuntimeJob


class ArtifactStore:
    def __init__(self, root: Path, readonly: bool = False):
        self.root = Path(root)
        self.blobs = self.root / "artifacts"
        self.database = self.root / "metadata.sqlite3"
        self.readonly = readonly
        if readonly:
            if not self.blobs.is_dir() or not self.database.is_file():
                raise FileNotFoundError("artifact store is not initialized")
            return
        self.blobs.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    package_name TEXT NOT NULL DEFAULT '',
                    version TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'upload'
                )"""
            )
            existing = {row[1] for row in db.execute("PRAGMA table_info(artifacts)")}
            for name, declaration in (
                ("package_name", "TEXT NOT NULL DEFAULT ''"),
                ("version", "TEXT NOT NULL DEFAULT ''"),
                ("source", "TEXT NOT NULL DEFAULT 'upload'"),
            ):
                if name not in existing:
                    db.execute(f"ALTER TABLE artifacts ADD COLUMN {name} {declaration}")
            db.execute(
                """CREATE TABLE IF NOT EXISTS inspections (
                    inspection_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    files_json TEXT NOT NULL,
                    parsed_metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )"""
            )
            inspection_columns = {row[1] for row in db.execute("PRAGMA table_info(inspections)")}
            if "parsed_metadata_json" not in inspection_columns:
                db.execute("ALTER TABLE inspections ADD COLUMN parsed_metadata_json TEXT NOT NULL DEFAULT '{}' ")
            db.execute(
                """CREATE TABLE IF NOT EXISTS runtime_jobs (
                    job_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    output_json TEXT NOT NULL
                )"""
            )

    def create(
        self,
        filename: str,
        content: bytes,
        *,
        package_name: str,
        version: str,
        source: str = "upload",
        created_at: datetime | None = None,
    ) -> ArtifactMetadata:
        self._require_writable()
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = uuid.uuid4().hex
        created_at = created_at or datetime.now(timezone.utc)
        blob = self.blobs / f"{artifact_id}.whl"

        with blob.open("xb") as stream:
            stream.write(content)
            stream.flush()

        try:
            with self._connect() as db:
                db.execute(
                    """INSERT INTO artifacts
                    (artifact_id, original_filename, package_name, version, sha256,
                     size, created_at, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        artifact_id,
                        Path(filename).name,
                        package_name,
                        version,
                        digest,
                        len(content),
                        created_at.isoformat(),
                        source,
                    ),
                )
        except Exception:
            blob.unlink(missing_ok=True)
            raise

        return ArtifactMetadata(
            artifact_id=artifact_id,
            original_filename=Path(filename).name,
            package_name=package_name,
            version=version,
            sha256=digest,
            size=len(content),
            created_at=created_at,
            source=source,
        )

    def get(self, artifact_id: str) -> ArtifactMetadata | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT artifact_id, original_filename, package_name, version, sha256, size, created_at, source "
                "FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        return ArtifactMetadata(**dict(zip(ArtifactMetadata.model_fields, row))) if row else None

    def list_artifacts(self, search: str = "", limit: int = 100, offset: int = 0) -> list[ArtifactMetadata]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT artifact_id, original_filename, package_name, version,
                   sha256, size, created_at, source FROM artifacts
                   WHERE package_name LIKE ? OR original_filename LIKE ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (f"%{search}%", f"%{search}%", limit, offset),
            ).fetchall()
        return [ArtifactMetadata(**dict(zip(ArtifactMetadata.model_fields, row))) for row in rows]

    def count_artifacts(self, search: str = "") -> int:
        with self._connect() as db:
            return db.execute(
                "SELECT COUNT(*) FROM artifacts WHERE package_name LIKE ? OR original_filename LIKE ?",
                (f"%{search}%", f"%{search}%"),
            ).fetchone()[0]

    def read_bytes(self, artifact_id: str) -> bytes:
        return (self.blobs / f"{artifact_id}.whl").read_bytes()

    def record_inspection(self, record: InspectionRecord) -> None:
        self._require_writable()
        with self._connect() as db:
            db.execute(
                """INSERT INTO inspections
                   (inspection_id, artifact_id, sha256, status, summary, findings_json,
                    files_json, parsed_metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.inspection_id,
                    record.artifact_id,
                    record.sha256,
                    record.status,
                    record.summary,
                    json.dumps([item.model_dump(mode="json") for item in record.findings]),
                    json.dumps([item.model_dump(mode="json") for item in record.files]),
                    json.dumps(record.parsed_metadata),
                    record.created_at.isoformat(),
                ),
            )

    def inspections(self, artifact_id: str | None = None, limit: int = 100) -> list[InspectionRecord]:
        query = """SELECT i.inspection_id, i.artifact_id, a.package_name, a.version,
                   i.sha256, i.status, i.summary, i.findings_json, i.files_json,
                   i.parsed_metadata_json, i.created_at
                   FROM inspections i JOIN artifacts a USING (artifact_id)"""
        params: tuple = ()
        if artifact_id is not None:
            query += " WHERE i.artifact_id = ?"
            params = (artifact_id,)
        query += " ORDER BY i.created_at DESC LIMIT ?"
        params += (limit,)
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [self._inspection_from_row(row) for row in rows]

    @staticmethod
    def _inspection_from_row(row) -> InspectionRecord:
        return InspectionRecord(
            inspection_id=row[0],
            artifact_id=row[1],
            package_name=row[2],
            version=row[3],
            sha256=row[4],
            status=row[5],
            summary=row[6],
            findings=json.loads(row[7]),
            files=json.loads(row[8]),
            parsed_metadata=json.loads(row[9]),
            created_at=row[10],
            file_count=len(json.loads(row[8])),
        )

    def record_runtime_job(self, job: RuntimeJob) -> None:
        self._require_writable()
        with self._connect() as db:
            db.execute(
                """INSERT INTO runtime_jobs
                   (job_id, artifact_id, sha256, status, created_at, duration_ms, output_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    job.job_id,
                    job.artifact_id,
                    job.sha256,
                    job.status,
                    job.created_at.isoformat(),
                    job.duration_ms,
                    json.dumps(job.output),
                ),
            )

    def seed_runtime_job(self, job: RuntimeJob) -> None:
        self._require_writable()
        with self._connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO runtime_jobs
                   (job_id, artifact_id, sha256, status, created_at, duration_ms, output_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    job.job_id,
                    job.artifact_id,
                    job.sha256,
                    job.status,
                    job.created_at.isoformat(),
                    job.duration_ms,
                    json.dumps(job.output),
                ),
            )

    def update_runtime_job_output(self, job_id: str, output: list[str]) -> None:
        """Update one persisted output record during Portal-owned migrations."""
        self._require_writable()
        with self._connect() as db:
            db.execute(
                "UPDATE runtime_jobs SET output_json = ? WHERE job_id = ?",
                (json.dumps(output), job_id),
            )

    def runtime_jobs(self, job_id: str | None = None) -> list[RuntimeJob]:
        query = """SELECT j.job_id, j.artifact_id, a.package_name, a.version,
                   j.sha256, j.status, j.created_at, j.duration_ms, j.output_json
                   FROM runtime_jobs j JOIN artifacts a USING (artifact_id)"""
        params: tuple = ()
        if job_id:
            query += " WHERE j.job_id = ?"
            params = (job_id,)
        query += " ORDER BY j.created_at DESC"
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [
            RuntimeJob(
                job_id=row[0], artifact_id=row[1], package_name=row[2], version=row[3],
                sha256=row[4], status=row[5], created_at=row[6], duration_ms=row[7],
                output=json.loads(row[8]),
            )
            for row in rows
        ]

    def _connect(self):
        if self.readonly:
            return sqlite3.connect(f"{self.database.resolve().as_uri()}?mode=ro", uri=True)
        return sqlite3.connect(self.database)

    def _require_writable(self) -> None:
        if self.readonly:
            raise PermissionError("artifact store is read-only")
