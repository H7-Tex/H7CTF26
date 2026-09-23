"""SQLite bootstrap, migrations, and small persistence primitives for ARGUS."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .domain import GrantedCapability, canonical_approval_claims


SQLITE_BUSY_TIMEOUT_MS = 5_000
SCHEMA_VERSION = 12

CANONICAL_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_CANONICAL_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_CANONICAL_TIMESTAMP_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z"


class SchemaVersionError(RuntimeError):
    """The database cannot be safely opened by this application version."""


MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE IF NOT EXISTS integrations (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            publisher_class TEXT NOT NULL,
            package_digest TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            status TEXT NOT NULL,
            approved_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tool_snapshots (
            instance_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            descriptor_hash TEXT NOT NULL,
            descriptor_json TEXT NOT NULL,
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, integration_id, descriptor_hash),
            FOREIGN KEY (instance_id, integration_id)
                REFERENCES integrations(instance_id, id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS incidents (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            telemetry_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tool_calls (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            server_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            arguments_hash TEXT NOT NULL,
            result_projection TEXT NOT NULL,
            call_order INTEGER NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id),
            FOREIGN KEY (instance_id, incident_id)
                REFERENCES incidents(instance_id, id) ON DELETE CASCADE,
            UNIQUE (instance_id, incident_id, call_order)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_cards (
            instance_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            owner_class TEXT NOT NULL,
            card_json TEXT NOT NULL,
            card_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, agent_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS a2a_tasks (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            caller_service TEXT NOT NULL,
            origin_subject TEXT NOT NULL,
            owner_class TEXT NOT NULL,
            skill_id TEXT NOT NULL,
            artifact_kind TEXT NOT NULL,
            artifact_json TEXT NOT NULL,
            normalized_tool TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_approvals (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            target TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consumed_at TEXT,
            PRIMARY KEY (instance_id, id),
            FOREIGN KEY (instance_id, task_id)
                REFERENCES a2a_tasks(instance_id, id) ON DELETE CASCADE
        )
        """,
        "CREATE INDEX IF NOT EXISTS tool_snapshots_instance_integration_idx ON tool_snapshots(instance_id, integration_id, observed_at)",
        "CREATE INDEX IF NOT EXISTS incidents_instance_created_idx ON incidents(instance_id, created_at, id)",
        "CREATE INDEX IF NOT EXISTS tool_calls_instance_incident_order_idx ON tool_calls(instance_id, incident_id, call_order)",
        "CREATE INDEX IF NOT EXISTS a2a_tasks_instance_status_idx ON a2a_tasks(instance_id, status, created_at)",
        "CREATE INDEX IF NOT EXISTS security_approvals_instance_expiry_idx ON security_approvals(instance_id, expires_at)",
    ),
    2: (
        """
        CREATE TABLE IF NOT EXISTS k8s_deployments (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            workload TEXT NOT NULL,
            profile TEXT NOT NULL,
            service_account TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            cleaned_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ready_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_status_idx ON k8s_deployments(instance_id, status, created_at)",
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_namespace_idx ON k8s_deployments(instance_id, namespace, workload)",
    ),
    3: (
        "ALTER TABLE integrations ADD COLUMN approved_descriptor_hash TEXT",
        "ALTER TABLE k8s_deployments RENAME TO k8s_deployments_v2",
        """
        CREATE TABLE k8s_deployments (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            approval_id TEXT,
            namespace TEXT NOT NULL,
            workload TEXT NOT NULL,
            profile TEXT NOT NULL,
            service_account TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            cleaned_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ready_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id),
            FOREIGN KEY (instance_id, approval_id)
                REFERENCES security_approvals(instance_id, id) ON DELETE RESTRICT
        )
        """,
        """
        INSERT INTO k8s_deployments
            (instance_id, id, namespace, workload, profile, service_account,
             manifest_hash, status, cleaned_at, created_at, ready_at, updated_at)
        SELECT instance_id, id, namespace, workload, profile, service_account,
               manifest_hash, status, cleaned_at, created_at, ready_at, updated_at
        FROM k8s_deployments_v2
        """,
        "DROP TABLE k8s_deployments_v2",
        "CREATE INDEX IF NOT EXISTS integrations_instance_approved_descriptor_idx ON integrations(instance_id, approved_descriptor_hash)",
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_status_idx ON k8s_deployments(instance_id, status, created_at)",
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_namespace_idx ON k8s_deployments(instance_id, namespace, workload)",
    ),
    4: (
        "ALTER TABLE k8s_deployments RENAME TO k8s_deployments_v3",
        """
        CREATE TABLE k8s_deployments (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            approval_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            workload TEXT NOT NULL,
            profile TEXT NOT NULL,
            service_account TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            cleaned_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ready_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id),
            FOREIGN KEY (instance_id, approval_id)
                REFERENCES security_approvals(instance_id, id) ON DELETE RESTRICT
        )
        """,
        """
        INSERT INTO k8s_deployments
            (instance_id, id, approval_id, namespace, workload, profile,
             service_account, manifest_hash, status, cleaned_at, created_at,
             ready_at, updated_at)
        SELECT instance_id, id, approval_id, namespace, workload, profile,
               service_account, manifest_hash, status, cleaned_at, created_at,
               ready_at, updated_at
        FROM k8s_deployments_v3
        """,
        "DROP TABLE k8s_deployments_v3",
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_status_idx ON k8s_deployments(instance_id, status, created_at)",
        "CREATE INDEX IF NOT EXISTS k8s_deployments_instance_namespace_idx ON k8s_deployments(instance_id, namespace, workload)",
        f"""
        CREATE TRIGGER security_approvals_canonical_insert
        BEFORE INSERT ON security_approvals
        WHEN NOT (
            NEW.expires_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
            AND length(NEW.expires_at) = 27
            AND NEW.created_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
            AND length(NEW.created_at) = 27
            AND (NEW.consumed_at IS NULL OR (
                NEW.consumed_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
                AND length(NEW.consumed_at) = 27
            ))
        )
        BEGIN
            SELECT RAISE(ABORT, 'approval timestamps must be canonical UTC');
        END
        """,
        f"""
        CREATE TRIGGER security_approvals_canonical_update
        BEFORE UPDATE OF expires_at, created_at, consumed_at ON security_approvals
        WHEN NOT (
            NEW.expires_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
            AND length(NEW.expires_at) = 27
            AND NEW.created_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
            AND length(NEW.created_at) = 27
            AND (NEW.consumed_at IS NULL OR (
                NEW.consumed_at GLOB '{_CANONICAL_TIMESTAMP_GLOB}'
                AND length(NEW.consumed_at) = 27
            ))
        )
        BEGIN
            SELECT RAISE(ABORT, 'approval timestamps must be canonical UTC');
        END
        """,
    ),
    5: (
        """
        ALTER TABLE security_approvals
        ADD COLUMN granted_capability TEXT NOT NULL
            DEFAULT 'standard-runtime'
            CHECK (granted_capability IN ('standard-runtime', 'protected-runtime'))
        """,
    ),
    6: (
        "ALTER TABLE integrations ADD COLUMN package_manifest_json TEXT NOT NULL DEFAULT '{}'",
        """
        CREATE TABLE IF NOT EXISTS community_mcp_state (
            instance_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            service_summary TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, integration_id),
            FOREIGN KEY (instance_id, integration_id)
                REFERENCES integrations(instance_id, id) ON DELETE CASCADE
        )
        """,
        "CREATE INDEX IF NOT EXISTS community_mcp_state_instance_updated_idx ON community_mcp_state(instance_id, updated_at, integration_id)",
    ),
    7: (
        """
        CREATE UNIQUE INDEX IF NOT EXISTS integrations_one_active_vendor_review_idx
        ON integrations(instance_id, endpoint)
        WHERE publisher_class = 'community'
          AND endpoint = 'community-review'
          AND status IN ('registered', 'pending', 'approved')
        """,
    ),
    8: (
        """
        CREATE TABLE IF NOT EXISTS incident_control_material (
            instance_id TEXT NOT NULL PRIMARY KEY,
            control_id TEXT NOT NULL,
            target TEXT NOT NULL,
            review_contract_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (instance_id, control_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS community_deliveries (
            instance_id TEXT NOT NULL,
            id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            received_context_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (instance_id, id),
            FOREIGN KEY (instance_id, incident_id)
                REFERENCES incidents(instance_id, id) ON DELETE CASCADE,
            FOREIGN KEY (instance_id, integration_id)
                REFERENCES integrations(instance_id, id) ON DELETE CASCADE
        )
        """,
        "CREATE INDEX IF NOT EXISTS community_deliveries_instance_integration_idx ON community_deliveries(instance_id, integration_id, created_at, id)",
    ),
    9: (
        """
        ALTER TABLE security_approvals
        ADD COLUMN key_id TEXT NOT NULL DEFAULT 'legacy'
            CHECK (length(key_id) BETWEEN 1 AND 128)
        """,
    ),
    10: (
        "ALTER TABLE a2a_tasks ADD COLUMN context_id TEXT NOT NULL DEFAULT 'legacy'",
    ),
    11: (
        """
        CREATE UNIQUE INDEX k8s_deployments_instance_approval_idx
        ON k8s_deployments(instance_id, approval_id)
        """,
        "ALTER TABLE k8s_deployments ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE k8s_deployments ADD COLUMN protected_objective TEXT",
    ),
    12: (
        "ALTER TABLE k8s_deployments RENAME COLUMN protected_objective TO verification_result",
    ),
}

# Compatibility export for callers that want the complete schema text. The
# initializer executes individual statements so migrations remain transactional.
SCHEMA = ";\n".join(
    statement.strip() for migration in MIGRATIONS.values() for statement in migration
) + ";"


def canonical_json(value: Any) -> str:
    """Serialize JSON fields deterministically for hashes and audit records."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def utc_now() -> datetime:
    return datetime.now(UTC)


def encode_timestamp(value: datetime | None = None) -> str:
    """Encode an aware instant as fixed-precision UTC RFC3339 text."""

    value = value or utc_now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include timezone information")
    return value.astimezone(UTC).strftime(CANONICAL_TIMESTAMP_FORMAT)


def parse_timestamp(value: str) -> datetime:
    """Parse only the canonical UTC timestamp representation."""

    if not isinstance(value, str) or not _CANONICAL_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be canonical UTC RFC3339 text")
    try:
        return datetime.strptime(value, CANONICAL_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("timestamp is not a valid UTC instant") from exc


def _timestamp_value(value: datetime | str) -> str:
    if isinstance(value, datetime):
        return encode_timestamp(value)
    parse_timestamp(value)
    return value


def _capability_value(value: GrantedCapability) -> str:
    if not isinstance(value, GrantedCapability):
        raise ValueError("granted_capability must be a known GrantedCapability")
    return value.value


def connect_database(path: str | Path) -> sqlite3.Connection:
    """Open one explicit SQLite file with local multi-process settings."""

    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        database_path,
        timeout=SQLITE_BUSY_TIMEOUT_MS / 1_000,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


@contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
    """Run a transaction and roll it back on any failure."""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Apply missing schema migrations sequentially and idempotently."""

    current = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"database schema version {current} is newer than supported version {SCHEMA_VERSION}"
        )
    for version in range(current + 1, SCHEMA_VERSION + 1):
        if version == 4:
            if connection.execute(
                "SELECT 1 FROM k8s_deployments WHERE approval_id IS NULL LIMIT 1"
            ).fetchone():
                raise SchemaVersionError(
                    "schema v4 requires every Kubernetes deployment to reference an approval"
                )
            for row in connection.execute(
                "SELECT created_at, expires_at, consumed_at FROM security_approvals"
            ):
                try:
                    parse_timestamp(row[0])
                    parse_timestamp(row[1])
                    if row[2] is not None:
                        parse_timestamp(row[2])
                except ValueError as exc:
                    raise SchemaVersionError(
                        "schema v4 requires canonical approval timestamps"
                    ) from exc
        with transaction(connection):
            try:
                for statement in MIGRATIONS[version]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {version}")
            except sqlite3.IntegrityError as exc:
                if version == 4:
                    raise SchemaVersionError("schema v4 migration found incompatible historical rows") from exc
                if version == 7:
                    raise SchemaVersionError(
                        "schema v7 requires historical duplicate active community integrations to be reset or reconciled"
                    ) from exc
                if version == 11:
                    raise SchemaVersionError(
                        "schema v11 requires historical duplicate deployments for one approval to be reset or reconciled"
                    ) from exc
                raise


@contextmanager
def open_database(database_path: str | Path, instance_id: str) -> Iterator[sqlite3.Connection]:
    """Open the configured database path and initialize its schema."""

    if not instance_id:
        raise ValueError("instance_id must not be empty")
    connection = connect_database(database_path)
    try:
        initialize_schema(connection)
        yield connection
    finally:
        connection.close()


def insert_security_approval(
    connection: sqlite3.Connection,
    *,
    instance_id: str,
    approval_id: str,
    task_id: str,
    control_id: str,
    target: str,
    granted_capability: GrantedCapability,
    expires_at: datetime | str,
    signature: str,
    key_id: str = "legacy",
    created_at: datetime | str | None = None,
) -> None:
    """Insert an approval only after canonicalizing all persisted timestamps."""

    created = _timestamp_value(created_at or utc_now())
    expires = _timestamp_value(expires_at)
    capability = _capability_value(granted_capability)
    if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128:
        raise ValueError("key_id is invalid")
    with transaction(connection):
        connection.execute(
            """
            INSERT INTO security_approvals
                (instance_id, id, task_id, control_id, target, granted_capability,
                 expires_at, key_id, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (instance_id, approval_id, task_id, control_id, target, capability, expires, key_id, signature, created),
        )


def claim_security_approval(
    connection: sqlite3.Connection,
    *,
    instance_id: str,
    approval_id: str,
    task_id: str,
    control_id: str,
    target: str,
    granted_capability: GrantedCapability,
    key_id: str,
    signature: str,
    now: datetime | str,
    consumed_at: datetime | str | None = None,
) -> bool:
    """Atomically claim one fully matching, unexpired approval for one instance."""

    now_value = _timestamp_value(now)
    consumed_value = _timestamp_value(consumed_at) if consumed_at is not None else now_value
    capability = _capability_value(granted_capability)
    with transaction(connection):
        changed = connection.execute(
            """
            UPDATE security_approvals
            SET consumed_at = ?
            WHERE instance_id = ?
              AND id = ?
              AND task_id = ?
              AND control_id = ?
              AND target = ?
              AND granted_capability = ?
              AND key_id = ?
              AND signature = ?
              AND consumed_at IS NULL
              AND expires_at > ?
            """,
            (
                consumed_value,
                instance_id,
                approval_id,
                task_id,
                control_id,
                target,
                capability,
                key_id,
                signature,
                now_value,
            ),
        ).rowcount
    return changed == 1


def claim_security_approval_and_insert_deployment(
    connection: sqlite3.Connection,
    *,
    instance_id: str,
    approval_id: str,
    task_id: str,
    control_id: str,
    target: str,
    granted_capability: GrantedCapability,
    key_id: str,
    signature: str,
    now: datetime | str,
    consumed_at: datetime | str | None = None,
    deployment_id: str,
    namespace: str,
    workload: str,
    profile: str,
    service_account: str,
    manifest_hash: str,
    status: str = "accepted",
) -> bool:
    """Claim an approval and record its derived deployment in one transaction."""

    now_value = _timestamp_value(now)
    consumed_value = _timestamp_value(consumed_at) if consumed_at is not None else now_value
    capability = _capability_value(granted_capability)
    with transaction(connection):
        changed = connection.execute(
            """
            UPDATE security_approvals
            SET consumed_at = ?
            WHERE instance_id = ?
              AND id = ?
              AND task_id = ?
              AND control_id = ?
              AND target = ?
              AND granted_capability = ?
              AND key_id = ?
              AND signature = ?
              AND consumed_at IS NULL
              AND expires_at > ?
            """,
            (
                consumed_value,
                instance_id,
                approval_id,
                task_id,
                control_id,
                target,
                capability,
                key_id,
                signature,
                now_value,
            ),
        ).rowcount
        if changed != 1:
            return False
        connection.execute(
            """
            INSERT INTO k8s_deployments
                (instance_id, id, approval_id, namespace, workload, profile,
                 service_account, manifest_hash, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                instance_id,
                deployment_id,
                approval_id,
                namespace,
                workload,
                profile,
                service_account,
                manifest_hash,
                status,
            ),
        )
    return True


def update_k8s_deployment(
    connection: sqlite3.Connection,
    *,
    instance_id: str,
    deployment_id: str,
    status: str,
    ready_at: datetime | str | None = None,
    cleaned_at: datetime | str | None = None,
    evidence_json: str = "{}",
    verification_result: str | None = None,
) -> None:
    """Persist bounded deployment state and evidence only."""

    ready_value = _timestamp_value(ready_at) if ready_at is not None else None
    cleaned_value = _timestamp_value(cleaned_at) if cleaned_at is not None else None
    if not isinstance(evidence_json, str) or len(evidence_json.encode("utf-8")) > 16_384:
        raise ValueError("deployment evidence is too large")
    if verification_result is not None and (
        not isinstance(verification_result, str)
        or len(verification_result.encode("utf-8")) > 4_096
    ):
        raise ValueError("deployment verification result is too large")
    with transaction(connection):
        connection.execute(
            """
            UPDATE k8s_deployments
            SET status = ?, ready_at = COALESCE(?, ready_at), cleaned_at = COALESCE(?, cleaned_at),
                evidence_json = ?, verification_result = ?, updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ? AND id = ?
            """,
            (
                status,
                ready_value,
                cleaned_value,
                evidence_json,
                verification_result,
                instance_id,
                deployment_id,
            ),
        )
