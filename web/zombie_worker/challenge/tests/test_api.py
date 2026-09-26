from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from relay import main


@pytest.fixture
def client():
    main._sessions.clear(); main._operations.clear()
    main._exports.clear(); main._export_by_report.clear()
    main._diagnostic_record.clear()
    main._diagnostic_record.update(job_id=main.DIAGNOSTIC_JOB_ID, reading=main.DIAGNOSTIC_READING, published=False)
    main.jobs[main.DIAGNOSTIC_JOB_ID]["status"] = "Draft"
    main._report_preference.update(directive={"contract": "relay.report-package/v2", "scope": "summary"}, revision=0, processed_revision=0)
    main._dispatch_cycle = main._new_dispatch_cycle(time.time() - main._dispatch_collection_seconds - 1)
    main.CHECKPOINT_FLAG = "ZW-CHECKPOINT-test-receipt"
    yield TestClient(main.app)


def browser_headers():
    return {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def enroll_v1_worker(client: TestClient, profile: str = "complete"):
    client.get("/api/meta")
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    public = {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big"))}
    key_id = main.key_fingerprint(public)
    headers = {**browser_headers(), "Content-Type": "application/json"}
    registered = client.post("/api/sync/worker-key", headers=headers, json={"key_id": key_id, "public_key": public})
    assert registered.status_code == 201, registered.text
    current = client.get("/api/jobs/JOB-3887/report-preference")
    assert current.json()["report_package"]["contract"] == "relay.report-package/v1"
    saved = client.put("/api/jobs/JOB-3887/report-preference", headers={**headers, "If-Match": current.headers["etag"]},
        json={"contract": "relay.report-package/v1", "profile": profile})
    assert saved.status_code == 200, saved.text
    rolled = client.post("/api/runtime/ready", headers=browser_headers())
    assert rolled.status_code == 200, rolled.text
    return private, key_id


def test_public_session_starts_v1_and_cannot_advance_without_real_v1_prerequisites(client):
    assert client.get("/api/meta").json()["api_version"] == "1.0"
    assert 'content="2026.09.24.1"' in client.get("/").text
    assert client.post("/api/runtime/ready", headers=browser_headers()).status_code == 409
    assert client.post("/api/sync/worker-key", headers=browser_headers(), json={"key_id": "x", "public_key": {}}).status_code == 400


def test_v2_preference_rejects_legacy_profile_extension_and_preserves_scope(client):
    enroll_v1_worker(client)
    assert client.get("/api/meta").json()["api_version"] == "2.0"
    response = client.put("/api/jobs/JOB-3887/report-preference", json={
        "contract": "relay.report-package/v2", "scope": "record", "profile": "complete"})
    assert response.status_code == 422
    saved = client.put("/api/jobs/JOB-3887/report-preference", json={
        "contract": "relay.report-package/v2", "scope": "record"})
    assert saved.status_code == 200
    assert saved.json()["revision"] == 1
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"


def test_historical_v1_manifest_makes_package_semantics_discoverable(client):
    manifest = client.get("/__release/manifest/v1.json").json()
    path = "/assets/contracts/report-package-v1.json"
    assert path in manifest["assets"]
    artifact = client.get(path).json()
    assert artifact["contract"] == "relay.report-package/v1"
    assert "commissioning" in artifact["profiles"]["complete"]["material"]
    assert "commissioning" not in artifact["profiles"]["record"]["material"]
    assert not any(word in json.dumps(artifact).lower() for word in ("flag", "h7ctf", "exploit", "victim"))


def test_release_rollout_is_session_bound_and_v2_cannot_enroll_a_new_legacy_key(client):
    enroll_v1_worker(client, "record")
    assert client.get("/api/meta").json()["api_version"] == "2.0"
    key = {"key_id": "not-a-key", "public_key": {}}
    assert client.post("/api/sync/worker-key", headers=browser_headers(), json=key).status_code in {400, 403}
    fresh = TestClient(main.app)
    assert fresh.get("/api/meta").json()["api_version"] == "1.0"
    assert fresh.post("/api/runtime/ready", headers=browser_headers()).status_code == 409


def test_worker_key_cannot_cross_relay_sessions(client):
    _, first_key = enroll_v1_worker(client, "complete")
    other = TestClient(main.app)
    _, other_key = enroll_v1_worker(other, "record")
    assert first_key != other_key
    headers = {**browser_headers(), "Content-Type": "application/json"}
    response = other.post("/api/sync/replay", headers=headers,
        json={"key_id": first_key, "envelope": {}, "signature": "AA"})
    assert response.status_code == 401


def test_concurrent_preference_edit_is_etagged_and_deterministic(client):
    enroll_v1_worker(client, "summary")
    teammate = TestClient(main.app)
    enroll_v1_worker(teammate, "record")
    first = client.get("/api/jobs/JOB-3887/report-preference")
    second = teammate.get("/api/jobs/JOB-3887/report-preference")
    assert first.headers["etag"] == second.headers["etag"]
    stale_etag = first.headers["etag"]
    headers = {**browser_headers(), "Content-Type": "application/json", "If-Match": stale_etag}
    accepted = client.put("/api/jobs/JOB-3887/report-preference", headers=headers,
        json={"contract": "relay.report-package/v2", "scope": "record"})
    rejected = teammate.put("/api/jobs/JOB-3887/report-preference", headers=headers,
        json={"contract": "relay.report-package/v2", "scope": "summary"})
    assert accepted.status_code == 200 and accepted.json()["revision"] == 1
    assert rejected.status_code == 412
    state = client.get("/api/jobs/JOB-3887/report-preference").json()
    assert state["revision"] == 1 and state["report_package"]["scope"] == "record"


def test_dispatch_plan_remains_bound_to_one_immutable_snapshot(client):
    enroll_v1_worker(client, "complete")
    initial = client.get("/api/jobs/JOB-3887/report-preference")
    first = client.put("/api/jobs/JOB-3887/report-preference", headers={"If-Match": initial.headers["etag"]}, json={
        "contract": "relay.report-package/v2", "scope": "record"})
    assert first.status_code == 200
    with main._state_lock:
        main._dispatch_cycle = main._new_dispatch_cycle(time.time() + 20)
    client.get("/api/jobs/JOB-3887/report-preference")
    with main._state_lock:
        main._dispatch_cycle["snapshot_at"] = time.time() - 1
        main._advance_dispatch_locked()
        cycle_id = main._dispatch_cycle["cycle_id"]
    snapshot_revision = first.json()["revision"]
    snapshot = main._dispatch_cycle["snapshot"]
    assert snapshot["preference_revision"] == snapshot_revision
    later = client.put("/api/jobs/JOB-3887/report-preference", json={
        "contract": "relay.report-package/v2", "scope": "summary"})
    assert later.status_code == 200 and later.json()["revision"] == snapshot_revision + 1
    plan = client.post("/api/sync/plan", json={"cycle_id": cycle_id})
    assert plan.status_code == 200
    assert plan.json()["preference_revision"] == snapshot_revision
    assert plan.json()["report_package"] == snapshot["report_package"]
    assert client.post("/api/sync/plan", json={"cycle_id": cycle_id}).json() == plan.json()


def test_expired_plan_advances_cleanly_and_keeps_current_preference_for_next_cycle(client):
    enroll_v1_worker(client, "complete")
    saved = client.put("/api/jobs/JOB-3887/report-preference", json={
        "contract": "relay.report-package/v2", "scope": "record"})
    assert saved.status_code == 200
    with main._state_lock:
        main._dispatch_cycle = main._new_dispatch_cycle(time.time() - main._dispatch_collection_seconds - 1)
        main._advance_dispatch_locked()
        cycle_id = main._dispatch_cycle["cycle_id"]
    plan = client.post("/api/sync/plan", json={"cycle_id": cycle_id}).json()
    main._operations[plan["operation_id"]]["expires"] = time.monotonic() - 1
    expired = client.get("/api/jobs/JOB-3887/report-preference").json()["dispatch"]
    assert expired["state"] == "processed"
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
    with main._state_lock:
        main._dispatch_cycle["next_cycle_at"] = time.time() - 1
    future = client.get("/api/jobs/JOB-3887/report-preference").json()["dispatch"]
    assert future["cycle_id"] != cycle_id and future["state"] == "collecting"
    with main._state_lock:
        main._dispatch_cycle["snapshot_at"] = time.time() - 1
        main._advance_dispatch_locked()
        recovered = main._dispatch_cycle["snapshot"]
    assert recovered["preference_revision"] == saved.json()["revision"]
    assert recovered["report_package"] == {"contract": "relay.report-package/v2", "scope": "record"}


def test_v2_preview_and_export_cannot_publish_without_staged_legacy_replay(client):
    enroll_v1_worker(client)
    assert client.post("/api/jobs/JOB-3887/exports").status_code == 409
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
    assert client.get("/__release/manifest.json").json()["semantic_contract"] == "relay.sync-plan/v2"


def test_arbitrary_outbox_and_unsigned_replay_do_not_publish(client):
    enroll_v1_worker(client)
    headers = {**browser_headers(), "Content-Type": "application/json"}
    fabricated = {"schema_version": 1, "operation_id": "made-up", "report_package": {
        "contract": "relay.report-package/v1", "profile": "complete"}}
    staged = client.post("/api/sync/outbox", headers=headers, json={"envelope": fabricated})
    assert staged.status_code == 409
    replay = client.post("/api/sync/replay", headers=headers,
        json={"key_id": "unregistered", "envelope": fabricated, "signature": ""})
    assert replay.status_code == 401
    assert main._diagnostic_record["published"] is False
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"


def prepare_emulated_operation(client, profile: str = "complete"):
    private, key_id = enroll_v1_worker(client, profile)
    with main._state_lock:
        main._dispatch_cycle = main._new_dispatch_cycle(time.time() + 20)
    saved = client.put("/api/jobs/JOB-3887/report-preference", json={
        "contract": "relay.report-package/v2", "scope": "record"})
    assert saved.status_code == 200
    with main._state_lock:
        main._dispatch_cycle["snapshot_at"] = time.time() - 1
        main._advance_dispatch_locked()
        cycle_id = main._dispatch_cycle["cycle_id"]
    response = client.post("/api/sync/plan", json={"cycle_id": cycle_id})
    plan = response.json()
    operation = main._operations[plan["operation_id"]]
    # Independent reproduction of the public worker's v1 normalization.
    delivered = {**plan, **plan["delivery"]}
    envelope = {**delivered, "schema_version": 1, "state": "pending-sync",
        "sync_id": delivered.get("sync_id") or delivered["operation_id"],
        "persistence": delivered.get("persistence") or "outbox",
        "source_release": response.headers["x-release-id"],
        "source_contract": response.headers["x-semantic-contract"],
        "source_delivery": plan["delivery"], "source_plan": plan,
        "package_preference_revision": operation["legacy_profile_revision"],
        "report_package": {"contract": "relay.report-package/v1", "profile": profile}}
    return private, key_id, operation, plan, envelope, {**browser_headers(), "Content-Type": "application/json"}


def sign_replay(client, private, key_id, envelope, headers):
    staged = client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope})
    assert staged.status_code == 200, staged.text
    return staged


def replay_plan_with_legacy_profile(client, profile: str):
    private, key_id, operation, plan, envelope, headers = prepare_emulated_operation(client, profile)
    staged = sign_replay(client, private, key_id, envelope, headers)
    signed = {"key_id": key_id, "envelope": envelope}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    replay = client.post("/api/sync/replay", headers=headers,
        json={**signed, "signature": signature})
    assert replay.status_code == 200, replay.text
    return replay.json()


def test_full_signed_protocol_emulation_with_client_generated_key_is_possible(client):
    """Full protocol emulation is an intentional equivalent expert solve."""
    private, key_id, operation, plan, envelope, headers = prepare_emulated_operation(client)
    assert "ZW-CHECKPOINT-test-receipt" not in client.get("/api/meta").text
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
    assert client.post("/api/jobs/JOB-3887/exports").status_code == 409
    staged = client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope})
    assert staged.status_code == 200, staged.text
    assert staged.json()["reconciliation_receipt"] == "ZW-CHECKPOINT-test-receipt"
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
    assert client.post("/api/jobs/JOB-3887/exports").status_code == 409
    signed = {"key_id": key_id, "envelope": envelope}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    replay = client.post("/api/sync/replay", headers=headers, json={**signed, "signature": signature})
    assert replay.status_code == 200, replay.text
    assert replay.json()["report_status"] == "published"
    assert main._diagnostic_record["published"] is True


@pytest.mark.parametrize("mutation", [
    "snapshot_revision", "cycle", "source_plan", "semantic_contract", "transformed_package", "extra_field",
])
def test_incomplete_or_guessed_materialization_is_rejected(client, mutation):
    _, _, _, _, envelope, headers = prepare_emulated_operation(client)
    if mutation == "snapshot_revision":
        envelope["source_plan"]["preference_revision"] += 1
    elif mutation == "cycle":
        envelope["source_plan"]["dispatch_cycle_id"] = "another-cycle"
    elif mutation == "source_plan":
        envelope["source_plan"]["snapshot_digest"] = "0" * 64
    elif mutation == "semantic_contract":
        envelope["source_contract"] = "relay.sync-plan/v1"
    elif mutation == "transformed_package":
        envelope["report_package"]["profile"] = "record"
    else:
        envelope["made_up"] = True
    rejected = client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope})
    assert rejected.status_code == 409
    assert "reconciliation_receipt" not in rejected.json()
    assert main._diagnostic_record["published"] is False


def test_correct_signature_without_exact_prior_staging_fails(client):
    private, key_id, _, _, envelope, headers = prepare_emulated_operation(client)
    signed = {"key_id": key_id, "envelope": envelope}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    response = client.post("/api/sync/replay", headers=headers, json={
        **signed, "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))})
    assert response.status_code == 409
    assert main._diagnostic_record["published"] is False


def test_altered_envelope_after_staging_and_second_replay_fail(client):
    private, key_id, _, _, envelope, headers = prepare_emulated_operation(client)
    staged = client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope})
    assert staged.status_code == 200
    altered = {**envelope, "effects": ["draft:publish"]}
    signed = {"key_id": key_id, "envelope": altered}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    forged = client.post("/api/sync/replay", headers=headers, json={
        **signed, "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))})
    assert forged.status_code == 409
    assert main._diagnostic_record["published"] is False
    signed = {"key_id": key_id, "envelope": envelope}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    accepted = client.post("/api/sync/replay", headers=headers, json={**signed, "signature": signature})
    assert accepted.status_code == 200, accepted.text
    replayed = client.post("/api/sync/replay", headers=headers, json={**signed, "signature": signature})
    assert replayed.status_code == 409


def test_expired_staged_operation_is_rejected(client):
    private, key_id, operation, _, envelope, headers = prepare_emulated_operation(client)
    assert client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope}).status_code == 200
    operation["expires"] = time.monotonic() - 1
    assert client.post("/api/sync/outbox", headers=headers, json={"envelope": envelope}).status_code == 410
    signed = {"key_id": key_id, "envelope": envelope}
    der = private.sign(main.canonical_json(signed), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    replay = client.post("/api/sync/replay", headers=headers, json={
        **signed, "signature": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))})
    assert replay.status_code == 410
    assert main._diagnostic_record["published"] is False


def test_signing_key_registration_alone_does_not_publish_or_issue_receipt(client):
    enroll_v1_worker(client, "complete")
    assert main._diagnostic_record["published"] is False
    assert not any(op.get("legacy_outbox") for op in main._operations.values())
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"


@pytest.mark.parametrize("profile", ["summary", "record"])
def test_v1_summary_or_record_profile_never_publishes_or_exports_flag(client, profile):
    result = replay_plan_with_legacy_profile(client, profile)
    assert result["report_status"] == "not-published"
    assert main._diagnostic_record["published"] is False
    assert client.get("/api/jobs/JOB-3887").json()["job"]["status"] == "Draft"
    assert client.post("/api/jobs/JOB-3887/exports").status_code == 409


def test_relay_discards_flag_environment_variable(monkeypatch, caplog):
    import importlib
    monkeypatch.setenv("FLAG", "H7CTF{must-not-be-retained}")
    importlib.reload(main)
    assert "FLAG" not in main.os.environ
    assert "must-not-be-retained" not in caplog.text
    assert "must-not-be-retained" not in Path(main.__file__).read_text()
