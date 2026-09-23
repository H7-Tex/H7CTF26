import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from argus.domain import GrantedCapability, canonical_approval_claims
from argus.store import (
    MIGRATIONS,
    SCHEMA_VERSION,
    SchemaVersionError,
    claim_security_approval,
    claim_security_approval_and_insert_deployment,
    connect_database,
    encode_timestamp,
    initialize_schema,
    insert_security_approval,
    open_database,
    parse_timestamp,
    transaction,
)


def _create_version_three_database(path):
    connection = connect_database(path)
    for version in (1, 2, 3):
        with transaction(connection):
            for statement in MIGRATIONS[version]:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version}")
    return connection


def _insert_task(connection, instance_id="instance-a", task_id="task"):
    connection.execute(
        """
        INSERT INTO a2a_tasks
            (instance_id,id,caller_service,origin_subject,owner_class,skill_id,
             artifact_kind,artifact_json,status)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (instance_id, task_id, "coordinator", "vendor", "external", "review", "recommendation", "{}", "completed"),
    )


def test_fresh_schema_and_repeated_startup(tmp_path):
    path = tmp_path / "configured.sqlite3"
    connection = connect_database(path)
    initialize_schema(connection)
    initialize_schema(connection)
    assert path.exists()
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 12
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {
        "integrations",
        "tool_snapshots",
        "incidents",
        "tool_calls",
        "agent_cards",
        "a2a_tasks",
        "security_approvals",
        "k8s_deployments",
        "community_mcp_state",
        "incident_control_material",
        "community_deliveries",
    } <= tables
    assert "approved_descriptor_hash" in {
        row[1] for row in connection.execute("PRAGMA table_info(integrations)")
    }
    deployment_columns = {
        row[1]: row for row in connection.execute("PRAGMA table_info(k8s_deployments)")
    }
    assert deployment_columns["approval_id"][3] == 1
    approval_columns = {
        row[1]: row for row in connection.execute("PRAGMA table_info(security_approvals)")
    }
    assert approval_columns["granted_capability"][3] == 1
    assert approval_columns["key_id"][3] == 1
    assert "package_manifest_json" in {
        row[1] for row in connection.execute("PRAGMA table_info(integrations)")
    }
    foreign_keys = list(connection.execute("PRAGMA foreign_key_list(k8s_deployments)"))
    assert any(row[2] == "security_approvals" and row[4] == "id" for row in foreign_keys)
    connection.close()


def test_upgrade_from_version_three_adds_required_approval_and_timestamp_guards(tmp_path):
    connection = _create_version_three_database(tmp_path / "upgrade.sqlite3")
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    initialize_schema(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO security_approvals
                (instance_id,id,task_id,control_id,target,expires_at,signature)
            VALUES (?,?,?,?,?,?,?)
            """,
            ("instance-a", "bad", "missing", "control", "target", "2030-01-01T00:00:00Z", "sig"),
        )
    connection.close()


def test_upgrade_from_real_version_four_defaults_historical_approvals_to_standard(tmp_path):
    connection = connect_database(tmp_path / "v4.sqlite3")
    for version in (1, 2, 3, 4):
        with transaction(connection):
            for statement in MIGRATIONS[version]:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version}")
    _insert_task(connection)
    connection.commit()
    connection.execute(
        """
        INSERT INTO security_approvals
            (instance_id,id,task_id,control_id,target,expires_at,signature,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            "instance-a",
            "historical",
            "task",
            "control",
            "team",
            "2030-01-01T00:00:00.000000Z",
            "sig",
            "2028-01-01T00:00:00.000000Z",
        ),
    )
    connection.commit()
    initialize_schema(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert connection.execute(
        "SELECT granted_capability FROM security_approvals WHERE id='historical'"
    ).fetchone()[0] == GrantedCapability.STANDARD_RUNTIME.value
    connection.close()


def test_upgrade_rejects_historical_null_deployment_approval(tmp_path):
    connection = _create_version_three_database(tmp_path / "null-approval.sqlite3")
    connection.execute(
        """
        INSERT INTO k8s_deployments
            (instance_id,id,approval_id,namespace,workload,profile,service_account,manifest_hash,status)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        ("instance-a", "deployment", None, "argus-team-a", "workload", "team-namespace", "argus-worker", "hash", "pending"),
    )
    connection.commit()
    with pytest.raises(SchemaVersionError, match="approval"):
        initialize_schema(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    connection.close()


def test_future_schema_version_is_rejected(tmp_path):
    connection = connect_database(tmp_path / "future.sqlite3")
    connection.execute("PRAGMA user_version = 99")
    with pytest.raises(SchemaVersionError, match="newer"):
        initialize_schema(connection)
    connection.close()


def test_explicit_database_path_and_instance_scoping(tmp_path):
    path = tmp_path / "exact" / "state.sqlite3"
    with open_database(path, "instance-a") as connection:
        connection.execute(
            "INSERT INTO integrations(instance_id,id,publisher_class,package_digest,endpoint,status,approved_descriptor_hash) VALUES (?,?,?,?,?,?,?)",
            ("instance-a", "integration", "community", "digest", "internal", "approved", "hash-a"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO tool_snapshots(instance_id,integration_id,descriptor_hash,descriptor_json) VALUES (?,?,?,?)",
                ("instance-b", "integration", "hash-b", "{}"),
            )
        assert path.exists()
        assert not (path.parent / "argus.sqlite3").exists()


def test_active_vendor_registration_is_unique_per_instance(tmp_path):
    with open_database(tmp_path / "registrations.sqlite3", "instance-a") as connection:
        row = ("instance-a", "one", "community", "digest", "community-review", "pending")
        connection.execute(
            "INSERT INTO integrations(instance_id,id,publisher_class,package_digest,endpoint,status) VALUES (?,?,?,?,?,?)",
            row,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO integrations(instance_id,id,publisher_class,package_digest,endpoint,status) VALUES (?,?,?,?,?,?)",
                ("instance-a", "two", "community", "digest", "community-review", "approved"),
            )
        connection.execute(
            "INSERT INTO integrations(instance_id,id,publisher_class,package_digest,endpoint,status) VALUES (?,?,?,?,?,?)",
            ("instance-b", "one", "community", "digest", "community-review", "pending"),
        )


def test_upgrade_rejects_historical_duplicate_active_community_integrations(tmp_path):
    connection = connect_database(tmp_path / "duplicate-registrations.sqlite3")
    for version in range(1, 7):
        with transaction(connection):
            for statement in MIGRATIONS[version]:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version}")
    connection.executemany(
        "INSERT INTO integrations(instance_id,id,publisher_class,package_digest,endpoint,status) VALUES (?,?,?,?,?,?)",
        (
            ("instance-a", "one", "community", "digest-1", "community-review", "pending"),
            ("instance-a", "two", "community", "digest-2", "community-review", "approved"),
        ),
    )
    connection.commit()
    with pytest.raises(SchemaVersionError, match="duplicate active community integrations"):
        initialize_schema(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
    connection.close()


def test_timestamp_helpers_accept_only_canonical_utc_values():
    instant = datetime(2029, 1, 1, tzinfo=UTC)
    encoded = encode_timestamp(instant)
    assert encoded == "2029-01-01T00:00:00.000000Z"
    assert parse_timestamp(encoded) == instant
    with pytest.raises(ValueError):
        parse_timestamp("2029-01-01T00:00:00Z")
    with pytest.raises(ValueError):
        parse_timestamp("2029-99-01T00:00:00.000000Z")


def test_canonical_approval_claims_include_only_authoritative_capability():
    payload = canonical_approval_claims(
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.PROTECTED_RUNTIME,
        expires_at="2030-01-01T00:00:00.000000Z",
        key_id="key-1",
    )
    assert '"granted_capability":"protected-runtime"' in payload
    assert '"key_id":"key-1"' in payload
    assert "display" not in payload
    with pytest.raises(ValueError):
        canonical_approval_claims(
            instance_id="instance-a",
            approval_id="approval",
            task_id="task",
            control_id="control",
            target="team",
            granted_capability="protected-runtime",
            expires_at="2030-01-01T00:00:00.000000Z",
            key_id="key-1",
        )


def test_atomic_approval_claim_and_deployment_relationship(tmp_path):
    connection = connect_database(tmp_path / "approval.sqlite3")
    initialize_schema(connection)
    _insert_task(connection)
    connection.commit()
    insert_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        expires_at="2030-01-01T00:00:00.000000Z",
        signature="sig",
        key_id="key-1",
        created_at="2028-01-01T00:00:00.000000Z",
    )
    connection.execute(
        """
        INSERT INTO k8s_deployments
            (instance_id,id,approval_id,namespace,workload,profile,service_account,manifest_hash,status)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        ("instance-a", "deployment", "approval", "argus-instance-a", "workload", "team-namespace", "argus-worker", "hash", "pending"),
    )
    connection.commit()
    assert connection.execute(
        "SELECT key_id FROM security_approvals WHERE id = 'approval'"
    ).fetchone()[0] == "key-1"
    now = "2029-01-01T00:00:00.000000Z"
    assert claim_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        key_id="key-1",
        signature="sig",
        now=now,
    )
    assert not claim_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        key_id="legacy",
        signature="sig",
        now=now,
    )
    assert connection.execute(
        "SELECT consumed_at FROM security_approvals WHERE instance_id=? AND id=?",
        ("instance-a", "approval"),
    ).fetchone()[0] == now
    connection.close()


def test_approval_claim_rejects_wrong_scope_and_expiry(tmp_path):
    connection = connect_database(tmp_path / "approval-scope.sqlite3")
    initialize_schema(connection)
    _insert_task(connection)
    connection.commit()
    insert_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        expires_at="2029-01-01T00:00:00.000000Z",
        signature="sig",
    )
    now = "2029-01-01T00:00:00.000000Z"
    common = {
        "task_id": "task",
        "key_id": "legacy",
        "signature": "sig",
        "now": "2028-01-01T00:00:00.000000Z",
    }
    assert not claim_security_approval(connection, instance_id="instance-a", approval_id="approval", control_id="wrong", target="team", granted_capability=GrantedCapability.STANDARD_RUNTIME, **common)
    assert not claim_security_approval(connection, instance_id="instance-a", approval_id="approval", control_id="control", target="team", granted_capability=GrantedCapability.PROTECTED_RUNTIME, **common)
    assert not claim_security_approval(connection, instance_id="instance-b", approval_id="approval", control_id="control", target="team", granted_capability=GrantedCapability.STANDARD_RUNTIME, **common)
    assert not claim_security_approval(connection, instance_id="instance-a", approval_id="approval", control_id="control", target="team", granted_capability=GrantedCapability.STANDARD_RUNTIME, task_id="task", key_id="legacy", signature="sig", now=now)
    connection.close()


def test_concurrent_full_claim_and_deployment_insert_has_one_winner(tmp_path):
    path = tmp_path / "concurrent-approval.sqlite3"
    connection = connect_database(path)
    initialize_schema(connection)
    _insert_task(connection)
    connection.commit()
    insert_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        expires_at="2030-01-01T00:00:00.000000Z",
        signature="sig",
        key_id="legacy",
    )
    connection.close()

    def attempt(deployment_id: str) -> bool:
        current = connect_database(path)
        try:
            return claim_security_approval_and_insert_deployment(
                current,
                instance_id="instance-a",
                approval_id="approval",
                task_id="task",
                control_id="control",
                target="team",
                granted_capability=GrantedCapability.STANDARD_RUNTIME,
                key_id="legacy",
                signature="sig",
                now="2029-01-01T00:00:00.000000Z",
                deployment_id=deployment_id,
                namespace="argus-instance-a",
                workload=f"workload-{deployment_id}",
                profile="team-namespace",
                service_account="argus-worker",
                manifest_hash="hash",
            )
        finally:
            current.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, ("deployment-a", "deployment-b")))
    assert results.count(True) == 1
    check = connect_database(path)
    assert check.execute("SELECT COUNT(*) FROM k8s_deployments").fetchone()[0] == 1
    assert check.execute("SELECT consumed_at FROM security_approvals WHERE id='approval'").fetchone()[0] == "2029-01-01T00:00:00.000000Z"
    check.close()


def test_upgrade_rejects_historical_duplicate_approval_deployments(tmp_path):
    connection = connect_database(tmp_path / "duplicate-deployments.sqlite3")
    for version in range(1, 11):
        with transaction(connection):
            for statement in MIGRATIONS[version]:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {version}")
    _insert_task(connection)
    connection.commit()
    insert_security_approval(
        connection,
        instance_id="instance-a",
        approval_id="approval",
        task_id="task",
        control_id="control",
        target="team",
        granted_capability=GrantedCapability.STANDARD_RUNTIME,
        expires_at="2030-01-01T00:00:00.000000Z",
        signature="sig",
    )
    for deployment_id in ("deployment-a", "deployment-b"):
        connection.execute(
            """
            INSERT INTO k8s_deployments
                (instance_id,id,approval_id,namespace,workload,profile,service_account,manifest_hash,status)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            ("instance-a", deployment_id, "approval", "argus-instance-a", deployment_id, "team-namespace", "argus-worker", "hash", "pending"),
        )
    connection.commit()
    with pytest.raises(SchemaVersionError, match="duplicate deployments"):
        initialize_schema(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
    connection.close()


def test_timestamp_trigger_rejects_noncanonical_raw_sql(tmp_path):
    connection = connect_database(tmp_path / "timestamps.sqlite3")
    initialize_schema(connection)
    _insert_task(connection)
    connection.commit()
    with pytest.raises(sqlite3.IntegrityError, match="canonical"):
        connection.execute(
            """
            INSERT INTO security_approvals
                (instance_id,id,task_id,control_id,target,expires_at,signature,created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            ("instance-a", "bad", "task", "control", "team", "2030-01-01T00:00:00Z", "sig", "2028-01-01T00:00:00Z"),
        )
    with pytest.raises(ValueError):
        insert_security_approval(
            connection,
            instance_id="instance-a",
            approval_id="bad-helper",
            task_id="task",
            control_id="control",
            target="team",
            granted_capability=GrantedCapability.STANDARD_RUNTIME,
            expires_at="2030-01-01T00:00:00Z",
            signature="sig",
        )
    connection.close()
