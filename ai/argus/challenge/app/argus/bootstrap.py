"""Organizer-only instance bootstrap for ARGUS."""

from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path

from .store import canonical_json, connect_database, initialize_schema, transaction


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def bootstrap() -> dict[str, str]:
    instance_id = _required("INSTANCE_ID")
    if not _IDENTIFIER.fullmatch(instance_id):
        raise ValueError("INSTANCE_ID is invalid")
    environment = os.getenv("ARGUS_ENV", "development").strip().lower()
    if environment not in {"development", "competition"}:
        raise ValueError("ARGUS_ENV must be development or competition")
    data_dir = Path(os.getenv("ARGUS_STATE_DIR", "/tmp/argus").strip())
    database_path = Path(os.getenv("ARGUS_DATABASE_PATH", str(data_dir / "argus.sqlite3")))
    data_dir.mkdir(parents=True, exist_ok=True)

    connection = connect_database(database_path)
    try:
        initialize_schema(connection)
        existing = connection.execute(
            "SELECT control_id, target FROM incident_control_material WHERE instance_id = ?",
            (instance_id,),
        ).fetchone()
        if existing is not None:
            return {"instance_id": instance_id, "control_id": existing[0], "target": existing[1]}
        control_id = os.getenv("ARGUS_BOOTSTRAP_CONTROL_ID", "").strip()
        target = os.getenv("ARGUS_BOOTSTRAP_TARGET", "team-runtime").strip()
        if environment == "competition" and not control_id:
            raise ValueError("competition bootstrap requires ARGUS_BOOTSTRAP_CONTROL_ID")
        if not control_id:
            control_id = f"control-{secrets.token_hex(8)}"
        if not _IDENTIFIER.fullmatch(control_id) or not 1 <= len(target) <= 128:
            raise ValueError("bootstrap control material is invalid")
        contract = {
            "review_type": "deployment-review",
            "required_fields": ["control_id", "target", "recommendation"],
            "recommendation_values": ["approve"],
        }
        with transaction(connection):
            connection.execute(
                """
                INSERT INTO incident_control_material
                    (instance_id, control_id, target, review_contract_json)
                VALUES (?, ?, ?, ?)
                """,
                (instance_id, control_id, target, canonical_json(contract)),
            )
        return {"instance_id": instance_id, "control_id": control_id, "target": target}
    finally:
        connection.close()


def main() -> None:
    result = bootstrap()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
