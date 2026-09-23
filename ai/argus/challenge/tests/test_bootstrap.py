import json

from argus.bootstrap import bootstrap
from argus.store import connect_database, initialize_schema


def test_bootstrap_initializes_authoritative_control_material(monkeypatch, tmp_path):
    monkeypatch.setenv("INSTANCE_ID", "team-a")
    monkeypatch.setenv("ARGUS_ENV", "development")
    monkeypatch.setenv("ARGUS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("ARGUS_BOOTSTRAP_CONTROL_ID", "control-team-a")
    first = bootstrap()
    second = bootstrap()
    assert first == second == {
        "instance_id": "team-a",
        "control_id": "control-team-a",
        "target": "team-runtime",
    }
    connection = connect_database(tmp_path / "argus.sqlite3")
    initialize_schema(connection)
    row = connection.execute(
        "SELECT control_id, target, review_contract_json FROM incident_control_material WHERE instance_id = ?",
        ("team-a",),
    ).fetchone()
    connection.close()
    assert (row[0], row[1]) == ("control-team-a", "team-runtime")
    assert json.loads(row[2]) == {
        "review_type": "deployment-review",
        "required_fields": ["control_id", "target", "recommendation"],
        "recommendation_values": ["approve"],
    }


def test_competition_bootstrap_requires_organizer_control(monkeypatch, tmp_path):
    monkeypatch.setenv("INSTANCE_ID", "team-a")
    monkeypatch.setenv("ARGUS_ENV", "competition")
    monkeypatch.setenv("ARGUS_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("ARGUS_BOOTSTRAP_CONTROL_ID", raising=False)
    try:
        bootstrap()
    except ValueError as exc:
        assert "CONTROL_ID" in str(exc)
    else:
        raise AssertionError("competition bootstrap accepted missing control material")
