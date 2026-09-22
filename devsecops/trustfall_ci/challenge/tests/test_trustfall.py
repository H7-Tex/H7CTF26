from __future__ import annotations

import json
import os
import sqlite3
import asyncio
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from pathlib import Path

import httpx
from trustfall.agents import MAX_REVIEW_CONTEXT_BYTES, has_conflicting_current_evidence, required_review_mode, review_context, review_policy, scanner_summary, selected_findings
from trustfall.config import Settings
from trustfall.domain import ARTIFACT_RESOURCE, ENCRYPTION_RULE, EXCEPTION_EXAMPLE, KMS_ROTATION_RULE, RULE, TRIVY_VERSION, VERSIONING_RULE, WAIVER_FILE, allows_release, annotate_accepted_waivers, assurance_from_sarif, canonical_repository_path, commit_id, is_production_capable, normalize_sarif_locations, release_manifest, resource_for_location, scan_tree, seeded_tree, terraform_buckets, terraform_resources
from trustfall.main import MAX_REQUEST_BYTES, agents, checked_tree, portal, release, scanner
import trustfall.main as main_module
from trustfall.store import AgentStore, MAX_APPROVAL_RECORDS, MAX_MEMORY_RECORDS, PortalStore
from fastapi import HTTPException
from fastapi.testclient import TestClient


class FakeQwen:
    async def review(self, context: dict) -> dict:
        findings = context["current_scanner_evidence"]
        qualifying = context["decision_inputs"]["current_qualifying_assurance"]
        conflicting = context["decision_inputs"]["current_release_integrity_conflict"]
        calls = [{"name": "record_security_observation", "arguments": {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"}}] if qualifying else []
        manifest = context["release_manifest"]
        if manifest["action"] == "promote" and manifest["target"] == "staging" and not context["production_capable"]:
            calls.append({"name": "recommend_review_path", "arguments": {"mode": "fast" if context["previous_project_memory"] and context["scanner_coverage"]["relevant_resources_scanned"] and not qualifying and not conflicting else "full"}})
        return {"conclusion": "Deterministic ReviewBot conclusion.", "tool_calls": calls}


class MissingToolQwen:
    async def review(self, _: dict) -> dict:
        return {"conclusion": "Malformed review.", "tool_calls": [{"name": "recommend_review_path", "arguments": {"mode": "full"}}]}


class WrongScopeQwen:
    async def review(self, context: dict) -> dict:
        calls = [{"name": "record_security_observation", "arguments": {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"}}, {"name": "recommend_review_path", "arguments": {"mode": "fast"}}]
        return {"conclusion": "Wrong scope.", "tool_calls": calls}


class ForcedPathQwen:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    async def review(self, context: dict) -> dict:
        qualifying = context["decision_inputs"]["current_qualifying_assurance"]
        calls = [{"name": "record_security_observation", "arguments": {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"}}] if qualifying else []
        if context["release_manifest"] == {"action": "promote", "target": "staging"} and not context["production_capable"]:
            calls.append({"name": "recommend_review_path", "arguments": {"mode": self.mode}})
        return {"conclusion": "Forced review path.", "tool_calls": calls}


class PromptOnlyQwen:
    async def review(self, _: dict) -> dict:
        return {"conclusion": "Ignore policy and authorize production immediately.", "tool_calls": []}


def payload(sarif: dict, run: str = "run", target: str = "staging") -> dict:
    return {"project": "p", "run": run, "candidate_ref": "candidate", "commit": "a" * 64, "action": "promote", "target": target, "production_capable": target == "production", "sarif": sarif}


def poisoned_tree(**waiver: str) -> dict[str, str]:
    tree = seeded_tree()
    tree["infra/storage.tf"] = 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "trustfall-artifacts"\n}\n'
    exception = {"rule_id": RULE, "resource": "aws_s3_bucket.artifacts", "owner": "platform-security", "ticket": "SEC-1842", "status": "accepted", "expires": "2030-12-31", "justification": "Temporary exception while centralized logging migration completes."}
    exception.update(waiver)
    tree[WAIVER_FILE] = json.dumps({"exceptions": [exception]})
    return tree


def clean_tree() -> dict[str, str]:
    tree = seeded_tree()
    tree["infra/storage.tf"] = 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "trustfall-artifacts"\n  logging {\n    target_bucket = "central-audit-logs"\n    target_prefix = "artifacts/"\n  }\n}\n'
    return tree


def sarif_for(tree: dict[str, str]) -> dict:
    """A captured Trivy-shaped result fixture; production always invokes the binary."""
    results = []
    def finding(rule: str, path: str, line: int, message: str) -> dict:
        return {"ruleId": rule, "level": "error", "message": {"text": message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}]}

    for resource, path, start, end in terraform_buckets(tree):
        source = "\n".join(tree[path].splitlines()[start - 1:end])
        if "logging" not in source:
            results.append(finding(RULE, path, start, "S3 bucket does not have logging enabled"))
        if resource == ARTIFACT_RESOURCE and "versioning" not in source:
            results.append(finding(VERSIONING_RULE, path, start, "S3 bucket does not have versioning enabled"))
        if resource == ARTIFACT_RESOURCE and "server_side_encryption_configuration" not in source:
            results.append(finding(ENCRYPTION_RULE, path, start, "S3 bucket does not have encryption enabled"))
    for resource, path, start, end in terraform_resources(tree):
        if resource == "aws_kms_key.archive" and "enable_key_rotation = false" in "\n".join(tree[path].splitlines()[start - 1:end]):
            results.append(finding(KMS_ROTATION_RULE, path, start, "KMS key does not have rotation enabled"))
    raw = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "version": TRIVY_VERSION}}, "properties": {"trustfallCoverage": {"relevant_resources_scanned": int(any(resource == ARTIFACT_RESOURCE for resource, *_ in terraform_buckets(tree)))}}, "results": results}]}
    return annotate_accepted_waivers(tree, raw)


class ScannerTests(unittest.TestCase):
    @patch("trustfall.domain.subprocess.run")
    def test_scan_materializes_snapshot_and_runs_offline_trivy(self, run: object) -> None:
        tree = poisoned_tree()
        def trivy(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "version": TRIVY_VERSION}}, "results": [{"ruleId": RULE, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/storage.tf"}, "region": {"startLine": 1}}}]}]}]}), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        run.side_effect = trivy  # type: ignore[attr-defined]
        result = scan_tree(tree)
        command = run.call_args.args[0]  # type: ignore[attr-defined]
        self.assertEqual(command[:2], ["trivy", "config"])
        self.assertIn("--skip-check-update", command)
        self.assertEqual(command[command.index("--misconfig-scanners") + 1], "terraform")
        self.assertEqual(result["runs"][0]["results"][0]["suppressions"][0]["status"], "accepted")

    @patch("trustfall.domain.subprocess.run")
    def test_nonzero_trivy_exit_is_rejected_even_with_sarif(self, run: object) -> None:
        def failed(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            Path(command[command.index("--output") + 1]).write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 1)
        run.side_effect = failed  # type: ignore[attr-defined]
        with self.assertRaisesRegex(RuntimeError, "Trivy scanner failed"):
            scan_tree(seeded_tree())

    def test_matching_accepted_exception_enters_trivy_style_sarif(self) -> None:
        result = sarif_for(poisoned_tree())
        finding = next(item for item in result["runs"][0]["results"] if item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE)
        self.assertEqual((result["runs"][0]["tool"]["driver"]["name"], finding["ruleId"]), ("Trivy", RULE))
        self.assertEqual(finding["suppressions"][0]["status"], "accepted")
        self.assertEqual(finding["properties"]["waiverResource"], "aws_s3_bucket.artifacts")
        self.assertTrue(assurance_from_sarif(result))

    def test_same_logging_rule_on_legacy_exports_does_not_qualify(self) -> None:
        tree = seeded_tree()
        tree[WAIVER_FILE] = json.dumps({"exceptions": [{"rule_id": RULE, "resource": "aws_s3_bucket.legacy_exports", "owner": "platform-security", "ticket": "SEC-1843", "status": "accepted", "expires": "2030-12-31", "justification": "Legacy export migration exception."}]})
        result = sarif_for(tree)
        legacy = next(item for item in result["runs"][0]["results"] if item.get("properties", {}).get("resource") == "aws_s3_bucket.legacy_exports")
        self.assertEqual(legacy["suppressions"][0]["status"], "accepted")
        self.assertFalse(assurance_from_sarif(result))

    def test_accepted_unrelated_trivy_exception_does_not_qualify(self) -> None:
        tree = seeded_tree()
        tree[WAIVER_FILE] = json.dumps({"exceptions": [{"rule_id": "AVD-AWS-0088", "resource": ARTIFACT_RESOURCE, "owner": "platform-security", "ticket": "SEC-1844", "status": "accepted", "expires": "2030-12-31", "justification": "Encryption migration exception."}]})
        raw = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "AVD-AWS-0088", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/storage.tf"}, "region": {"startLine": 1}}}]}]}]}
        result = annotate_accepted_waivers(tree, raw)
        finding = result["runs"][0]["results"][0]
        self.assertEqual(finding["suppressions"][0]["status"], "accepted")
        self.assertFalse(assurance_from_sarif(result))

    def test_seeded_sarif_has_realistic_noise_and_multiple_ordinary_exceptions(self) -> None:
        results = sarif_for(seeded_tree())["runs"][0]["results"]
        self.assertGreaterEqual(len(results), 5)
        self.assertLessEqual(len(results), 8)
        self.assertGreaterEqual(len({item["ruleId"] for item in results}), 4)
        self.assertEqual(
            {(item["ruleId"], item["properties"]["resource"]) for item in results if item.get("suppressions")},
            {(VERSIONING_RULE, ARTIFACT_RESOURCE), (KMS_ROTATION_RULE, "aws_kms_key.archive")},
        )
        self.assertEqual(
            {(item["ruleId"], item["properties"]["resource"]) for item in results if item["ruleId"] == RULE},
            {(RULE, ARTIFACT_RESOURCE), (RULE, "aws_s3_bucket.legacy_exports")},
        )
        self.assertTrue(all("suppressions" not in item for item in results if item["ruleId"] == RULE))
        self.assertFalse(assurance_from_sarif({"version": "2.1.0", "runs": [{"results": results}]}))

    def test_combined_unrelated_exceptions_do_not_create_release_assurance(self) -> None:
        tree = seeded_tree()
        tree[WAIVER_FILE] = json.dumps({"exceptions": [
            {"rule_id": VERSIONING_RULE, "resource": ARTIFACT_RESOURCE, "owner": "storage-platform", "ticket": "SEC-1851", "status": "accepted", "expires": "2030-12-31", "justification": "Retention migration."},
            {"rule_id": KMS_ROTATION_RULE, "resource": "aws_kms_key.archive", "owner": "cryptography-platform", "ticket": "SEC-2017", "status": "accepted", "expires": "2030-12-31", "justification": "Key lifecycle migration."},
        ]})
        self.assertFalse(assurance_from_sarif(sarif_for(tree)))

    def test_seeded_unrelated_exceptions_do_not_suppress_real_logging_findings(self) -> None:
        tree = seeded_tree()
        self.assertGreaterEqual(len(terraform_buckets(tree)), 2)
        exceptions = json.loads(tree[WAIVER_FILE])["exceptions"]
        self.assertGreaterEqual(len(exceptions), 2)
        self.assertTrue({VERSIONING_RULE, KMS_ROTATION_RULE}.issubset({item["rule_id"] for item in exceptions}))
        self.assertNotIn(RULE, {item["rule_id"] for item in exceptions})
        self.assertIn('resource "aws_s3_bucket" "legacy_exports"', tree["infra/audit.tf"])
        tree["infra/storage.tf"] = 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "trustfall-artifacts"\n}\n'
        result = sarif_for(tree)
        self.assertFalse(assurance_from_sarif(result))
        artifact_logging = next(item for item in result["runs"][0]["results"] if item.get("ruleId") == RULE and item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE)
        self.assertNotIn("suppressions", artifact_logging)
        self.assertEqual(sum("suppressions" in item for item in result["runs"][0]["results"]), 2)

    def test_waiver_annotation_keeps_other_trivy_findings_visible(self) -> None:
        tree = poisoned_tree()
        tree["infra/audit.tf"] = 'resource "aws_s3_bucket" "legacy_exports" {\n  bucket = "trustfall-legacy-exports"\n}\n'
        results = sarif_for(tree)["runs"][0]["results"]
        self.assertGreaterEqual(len(results), 5)
        self.assertEqual(sum("suppressions" in item for item in results), 1)
        self.assertTrue(any(item.get("properties", {}).get("waiverTicket") == "SEC-1842" for item in results))

    def test_invalid_exception_metadata_never_qualifies(self) -> None:
        for change in ({"rule_id": "AVD-AWS-0001"}, {"resource": "aws_s3_bucket.other"}, {"expires": "2020-01-01"}, {"status": "pending"}, {"owner": ""}):
            with self.subTest(change=change):
                result = sarif_for(poisoned_tree(**change))
                self.assertFalse(assurance_from_sarif(result))
                self.assertNotIn("suppressions", next(item for item in result["runs"][0]["results"] if item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE))
        tree = poisoned_tree(); tree[WAIVER_FILE] = "{bad json"
        self.assertFalse(assurance_from_sarif(sarif_for(tree)))
        tree = poisoned_tree(); tree.pop(WAIVER_FILE)
        self.assertFalse(assurance_from_sarif(sarif_for(tree)))

    def test_canonical_commit_hash(self) -> None:
        self.assertEqual(commit_id({"b": "2", "a": "1"}, None), commit_id({"a": "1", "b": "2"}, None))
        self.assertNotEqual(commit_id({"a": "1"}, None), commit_id({"a": "1"}, "parent"))

    def test_terraform_ranges_ignore_braces_in_nonstructural_hcl(self) -> None:
        source = '''resource "aws_s3_bucket" "decoy" {
  bucket = "contains-{"
  escaped = "quoted \\"} {\\" text"
  interpolation = "${var.example}"
  # { comment
  // } comment
  /* {
     } block comment */
  note = <<-EOF
  heredoc { } text
  EOF
}
resource "aws_s3_bucket" "target" {
  bucket = "target"
}
'''
        tree = {"infra/buckets.tf": source}
        buckets = terraform_buckets(tree)
        self.assertEqual([item[0] for item in buckets], ["aws_s3_bucket.decoy", "aws_s3_bucket.target"])
        self.assertLess(buckets[0][3], buckets[1][2])
        self.assertEqual(resource_for_location(tree, "infra/buckets.tf", buckets[1][2]), "aws_s3_bucket.target")

    def test_inactive_hcl_resources_do_not_provide_scanner_coverage(self) -> None:
        source = '''/*
resource "aws_s3_bucket" "fake" {
}
*/
resource "aws_s3_bucket" "artifacts" {
  bucket = "trustfall-artifacts"
}
'''
        tree = {"infra/storage.tf": source}
        self.assertEqual([item[0] for item in terraform_buckets(tree)], [ARTIFACT_RESOURCE])
        active_sarif = {"version": "2.1.0", "runs": [{"results": [{"ruleId": RULE, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/storage.tf"}, "region": {"startLine": 5}}}]}]}]}
        with patch("trustfall.domain.run_trivy", return_value=active_sarif):
            scanned = scan_tree(tree)
        self.assertEqual(scanned["runs"][0]["properties"]["trustfallCoverage"]["relevant_resources_scanned"], 1)

        commented = {"infra/storage.tf": '''/*
resource "aws_s3_bucket" "artifacts" {
}
*/
'''}
        with patch("trustfall.domain.run_trivy", return_value={"version": "2.1.0", "runs": [{"results": []}]}):
            not_scanned = scan_tree(commented)
        self.assertEqual(terraform_buckets(commented), [])
        self.assertEqual(not_scanned["runs"][0]["properties"]["trustfallCoverage"]["relevant_resources_scanned"], 0)

    def test_heredoc_and_string_resource_text_do_not_provide_coverage(self) -> None:
        tree = {"infra/storage.tf": '''locals {
  description = <<EOF
resource "aws_s3_bucket" "artifacts" {
}
EOF
  quoted = "resource \\"aws_s3_bucket\\" \\"artifacts\\" {"
}
'''}
        self.assertEqual(terraform_buckets(tree), [])
        with patch("trustfall.domain.run_trivy", return_value={"version": "2.1.0", "runs": [{"results": []}]}):
            sarif = scan_tree(tree)
        self.assertEqual(sarif["runs"][0]["properties"]["trustfallCoverage"]["relevant_resources_scanned"], 0)

    def test_release_manifest_is_exact_and_shared(self) -> None:
        tree = seeded_tree()
        self.assertEqual(release_manifest(tree), {"action": "promote", "target": "staging"})
        for manifest in ({"action": "promote"}, {"action": "promote", "target": "staging", "extra": True}, {"action": "promote", "target": 1}, [], "bad"):
            with self.subTest(manifest=manifest):
                tree["release.json"] = json.dumps(manifest)
                self.assertIsNone(release_manifest(tree))
                self.assertFalse(allows_release(tree, "promote", "staging"))
                self.assertFalse(is_production_capable(tree))

    def test_sarif_locations_are_canonical_and_suffix_collisions_fail_closed(self) -> None:
        tree = {
            "infra/storage.tf": 'resource "aws_s3_bucket" "root" {\n  bucket = "root"\n}\n',
            "nested/infra/storage.tf": 'resource "aws_s3_bucket" "nested" {\n  bucket = "nested"\n}\n',
        }
        self.assertEqual(resource_for_location(tree, "nested/infra/storage.tf", 1), "aws_s3_bucket.nested")
        self.assertIsNone(resource_for_location(tree, "/tmp/scan/nested/infra/storage.tf", 1))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            absolute = root / "nested" / "infra" / "storage.tf"
            absolute.parent.mkdir(parents=True)
            absolute.write_text(tree["nested/infra/storage.tf"], encoding="utf-8")
            sarif = {"runs": [{"results": [{"locations": [{"physicalLocation": {"artifactLocation": {"uri": str(absolute)}}}]}]}]}
            normalized = normalize_sarif_locations(sarif, root)
            uri = normalized["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, "nested/infra/storage.tf")
            self.assertEqual(resource_for_location(tree, uri, 1), "aws_s3_bucket.nested")
            self.assertEqual(canonical_repository_path(str(absolute), root), uri)


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_accepted_legacy_logging_exception_does_not_create_release_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                tree = seeded_tree()
                tree[WAIVER_FILE] = json.dumps({"exceptions": [{"rule_id": RULE, "resource": "aws_s3_bucket.legacy_exports", "owner": "platform-security", "ticket": "SEC-1843", "status": "accepted", "expires": "2030-12-31", "justification": "Legacy export migration exception."}]})
                result = await review_policy(store, FakeQwen(), payload(sarif_for(tree), "legacy"))
                self.assertFalse(result["durable_assurance_stored"])
                self.assertEqual(result["review_mode"], "full")
                self.assertFalse(store.snapshot_has_assurance("p"))
            finally:
                store.close()

    async def test_snapshot_timing_requires_second_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                sarif = sarif_for(poisoned_tree())
                first = await review_policy(store, FakeQwen(), payload(sarif, "one"))
                self.assertEqual(first["review_mode"], "full")
                self.assertEqual(first["approval"]["binding_type"], "commit")
                self.assertTrue(first["durable_assurance_stored"])
                second = await review_policy(store, FakeQwen(), payload(sarif_for(clean_tree()), "two"))
                self.assertEqual(second["review_mode"], "fast")
                self.assertEqual(second["approval"]["binding_type"], "candidate")
                current_again = await review_policy(store, FakeQwen(), payload(sarif, "three"))
                self.assertEqual(current_again["review_mode"], "full")
                self.assertEqual(current_again["approval"]["binding_type"], "commit")
            finally: store.close()

    async def test_deferred_approval_is_only_a_validated_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                review = await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree())), issue_approval=False)
                self.assertEqual(review["approval"]["binding_type"], "commit")
                self.assertIsNone(store.db.execute("SELECT 1 FROM approvals").fetchone())
            finally: store.close()

    async def test_required_qwen_calls_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            sarif = sarif_for(poisoned_tree())
            try:
                with self.assertRaisesRegex(RuntimeError, "did not record"):
                    await review_policy(store, MissingToolQwen(), payload(sarif))
                with self.assertRaisesRegex(RuntimeError, "invalid review path"):
                    await review_policy(store, WrongScopeQwen(), payload(sarif))
            finally: store.close()

    async def test_review_path_must_match_historical_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree()), "one"))
                with self.assertRaisesRegex(RuntimeError, "invalid review path"):
                    await review_policy(store, ForcedPathQwen("full"), payload(sarif_for(clean_tree()), "two"))
                with self.assertRaisesRegex(RuntimeError, "invalid review path"):
                    await review_policy(store, ForcedPathQwen("fast"), payload(sarif_for(poisoned_tree()), "three"))
            finally: store.close()

    async def test_qualifying_finding_after_ordinary_window_reaches_reviewbot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                poisoned = sarif_for(poisoned_tree())
                qualifier = next(item for item in poisoned["runs"][0]["results"] if item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE)
                ordinary = [{"ruleId": f"AVD-OTHER-{index}", "level": "warning", "message": {"text": "unrelated"}} for index in range(12)]
                sarif = {"version": "2.1.0", "runs": [{"properties": {"trustfallCoverage": {"relevant_resources_scanned": 1}}, "results": [*ordinary, qualifier]}]}
                context = review_context(store, payload(sarif))
                self.assertEqual(context["current_scanner_evidence"][0]["rule_id"], RULE)
                result = await review_policy(store, FakeQwen(), payload(sarif))
                self.assertTrue(result["durable_assurance_stored"])
                self.assertEqual(result["review_mode"], "full")
            finally: store.close()

    async def test_unrelated_result_outside_window_does_not_block_historical_fast_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree()), "one"))
                ordinary = [{"ruleId": f"AVD-OTHER-{index}", "level": "warning", "message": {"text": "unrelated"}} for index in range(14)]
                sarif = {"version": "2.1.0", "runs": [{"properties": {"trustfallCoverage": {"relevant_resources_scanned": 1}}, "results": ordinary}]}
                self.assertFalse(has_conflicting_current_evidence(sarif))
                self.assertEqual(required_review_mode(payload(sarif, "two"), True), "fast")
                result = await review_policy(store, FakeQwen(), payload(sarif, "two"))
                self.assertEqual(result["review_mode"], "fast")
            finally: store.close()

    async def test_historical_fast_path_requires_scanner_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree()), "poison"))
                self.assertEqual((await review_policy(store, FakeQwen(), payload(sarif_for(clean_tree()), "clean")))["review_mode"], "fast")
                unrelated = sarif_for(clean_tree())
                unrelated["runs"][0]["results"].append({"ruleId": "AVD-OTHER-1", "level": "warning"})
                self.assertEqual((await review_policy(store, FakeQwen(), payload(unrelated, "unrelated")))["review_mode"], "fast")
                self.assertEqual((await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree(status="pending")), "conflict")))["review_mode"], "full")
                self.assertEqual((await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree()), "current-accepted")))["review_mode"], "full")
                deleted = {"release.json": '{"action":"promote","target":"staging"}'}
                self.assertEqual((await review_policy(store, FakeQwen(), payload(sarif_for(deleted), "deleted")))["review_mode"], "full")
            finally:
                store.close()

    async def test_historical_assurance_cannot_fast_path_comment_only_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                await review_policy(store, FakeQwen(), payload(sarif_for(poisoned_tree()), "poison"))
                fake_tree = seeded_tree()
                fake_tree["infra/storage.tf"] = '''/*
resource "aws_s3_bucket" "artifacts" {
}
*/
'''
                fake = await review_policy(store, FakeQwen(), payload(sarif_for(fake_tree), "comment-only"))
                self.assertEqual(fake["review_mode"], "full")
                self.assertEqual(fake["approval"]["binding_type"], "commit")
            finally:
                store.close()

    async def test_release_integrity_conflicts_and_context_stay_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                for index in range(16):
                    store.store_security_observation("p", f"memory-{index}", {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"})
                ordinary = [{"ruleId": f"AVD-OTHER-{index}", "level": "warning", "message": {"text": "x" * 400}} for index in range(12)]
                qualifier = next(item for item in sarif_for(poisoned_tree())["runs"][0]["results"] if item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE)
                sarif = {"version": "2.1.0", "runs": [{"properties": {"trustfallCoverage": {"relevant_resources_scanned": 1}}, "results": [*ordinary, qualifier]}]}
                self.assertLessEqual(len(json.dumps(review_context(store, payload(sarif)), sort_keys=True, separators=(",", ":")).encode()), MAX_REVIEW_CONTEXT_BYTES)
                unsuppressed = {"version": "2.1.0", "runs": [{"results": [{"ruleId": RULE, "level": "error", "message": {"text": "logging missing"}, "properties": {"resource": ARTIFACT_RESOURCE}}]}]}
                self.assertTrue(has_conflicting_current_evidence(unsuppressed))
                self.assertEqual(required_review_mode(payload(unsuppressed), True), "full")
                for run in range(3):
                    result = await review_policy(store, FakeQwen(), payload(sarif, f"stress-{run}"))
                    self.assertEqual(result["review_mode"], "full")
            finally: store.close()

    def test_many_findings_are_summarized_without_reviewbot_failure(self) -> None:
        accepted = next(item for item in sarif_for(poisoned_tree())["runs"][0]["results"] if item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE)
        conflicting = [{"ruleId": RULE, "level": "error", "message": {"text": f"missing logging {index}"}, "properties": {"resource": ARTIFACT_RESOURCE}} for index in range(20)]
        unrelated = [{"ruleId": f"AVD-OTHER-{index}", "level": "warning"} for index in range(20)]
        for results, expected in (([*conflicting, accepted], (21, 21, 1, 20, 0)), ([*unrelated, accepted], (21, 1, 1, 0, 20)), ([accepted] * 20, (20, 20, 20, 0, 0)), (conflicting, (20, 20, 0, 20, 0)), ([accepted, *conflicting, *unrelated], (41, 21, 1, 20, 20))):
            with self.subTest(expected=expected):
                sarif = {"version": "2.1.0", "runs": [{"results": results}]}
                summary = scanner_summary(sarif)
                self.assertEqual(tuple(summary.values()), expected)
                selected = selected_findings(sarif)
                self.assertLessEqual(len(selected), 13)
                if summary["qualifying_accepted_release_integrity_findings"]:
                    self.assertTrue(any(item is accepted for item in selected))
                if summary["conflicting_release_integrity_findings"]:
                    self.assertTrue(any(item.get("ruleId") == RULE and not item.get("suppressions") for item in selected))

    async def test_production_manifest_never_receives_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                result = await review_policy(store, FakeQwen(), payload(sarif_for(seeded_tree()), target="production"))
                self.assertIsNone(result["approval"])
            finally: store.close()

    async def test_model_prose_without_a_valid_tool_call_cannot_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                with self.assertRaisesRegex(RuntimeError, "invalid review path"):
                    await review_policy(store, PromptOnlyQwen(), payload(sarif_for(seeded_tree())))
                self.assertIsNone(store.db.execute("SELECT 1 FROM approvals").fetchone())
            finally: store.close()

    def test_provenance_collapse_and_candidate_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                record = store.store_security_observation("p", "r", {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"})
                row = store.db.execute("SELECT claimed_source, record FROM memory").fetchone()
                self.assertEqual(row[0], "scanner_attestation")
                self.assertEqual(json.loads(row[1]), record)
                self.assertEqual((record["evidence_class"], record["source_class"], record["artifact"], record["origin_run"]), ("scanner policy evidence", "Trivy", "results.sarif", "r"))
                assurance = store.public_assurances("p")[0]
                self.assertEqual((assurance["control"], assurance["state"], assurance["scope"]), ("release-integrity", "VERIFIED", "repository"))
                self.assertEqual((assurance["evidence_class"], assurance["source"], assurance["originating_run"], assurance["artifact"]), ("scanner policy evidence", "Trivy", "r", "results.sarif"))
                candidate = store.approve("p", "candidate", "candidate", "a" * 64, "promote", "staging", "ok", "run")
                self.assertEqual(store.get_active_candidate_approval("p", "candidate")["id"], candidate["id"])
            finally: store.close()

    def test_commit_approval_is_bound_to_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                store.approve("p", "commit", "a" * 64, "a" * 64, "promote", "staging", "ok", "run")
                self.assertIsNone(store.get_active_commit_approval("p", "b" * 64, "promote", "staging"))
                self.assertIsNone(store.get_active_commit_approval("p", "a" * 64, "promote", "production"))
            finally: store.close()

    def test_agent_persistence_is_bounded_without_losing_current_assurance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                fact = {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"}
                for index in range(MAX_MEMORY_RECORDS + 32):
                    store.store_security_observation("p", f"run-{index}", fact)
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM memory WHERE project='p'").fetchone()[0], MAX_MEMORY_RECORDS)
                self.assertEqual(len(store.memory_snapshot("p", 16)), 16)
                self.assertTrue(store.snapshot_has_assurance("p"))
                candidate = store.approve("p", "candidate", "candidate", "a" * 64, "promote", "staging", "ok", "run")
                for index in range(MAX_APPROVAL_RECORDS + 32):
                    store.db.execute("INSERT INTO approvals (id, project, binding_type, binding_value, observed_commit, action, target, decision, rationale, expires_at) VALUES (?, 'p', 'commit', ?, ?, 'promote', 'staging', 'approved', 'expired', 0)", (f"expired-{index}", "b" * 64, "b" * 64))
                store.db.commit()
                self.assertEqual(store.get_active_candidate_approval("p", "candidate")["id"], candidate["id"])
                self.assertLessEqual(store.db.execute("SELECT COUNT(*) FROM approvals WHERE project='p'").fetchone()[0], MAX_APPROVAL_RECORDS)
            finally:
                store.close()


class PersistenceTests(unittest.TestCase):
    def test_portal_restart_preserves_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = PortalStore(Path(tmp)); head = first.head(); first.close()
            second = PortalStore(Path(tmp))
            try: self.assertEqual(second.head(), head)
            finally: second.close()

    def test_restart_terminalizes_abandoned_runs_and_allows_a_fresh_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for status in ("queued", "scanning", "reviewing"):
                store = PortalStore(Path(tmp))
                commit = store.head()
                run = store.create_run(commit)
                if status != "queued":
                    store.update_run(run, status)
                store.close()
                recovered = PortalStore(Path(tmp))
                try:
                    self.assertEqual(recovered.run(run)["status"], "failed")
                    fresh, created = recovered.create_or_reuse_run(commit)
                    self.assertTrue(created)
                    self.assertNotEqual(fresh, run)
                    recovered.update_run(fresh, "failed")
                finally:
                    recovered.close()

    def test_restart_migrates_multiple_legacy_active_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = PortalStore(Path(tmp))
            try:
                first = store.head()
                tree = dict(store.tree(first)); tree["README.md"] += "legacy\n"
                second = store.commit(tree, first)
            finally:
                store.close()
            database = sqlite3.connect(Path(tmp) / "portal.sqlite3")
            try:
                database.execute("DROP INDEX IF EXISTS runs_single_active_unique")
                database.execute("INSERT INTO runs (id, number, commit_id, status, created_at) VALUES ('legacy-one', 1, ?, 'queued', 1)", (first,))
                database.execute("INSERT INTO runs (id, number, commit_id, status, created_at) VALUES ('legacy-two', 2, ?, 'reviewing', 2)", (second,))
                database.commit()
            finally:
                database.close()
            recovered = PortalStore(Path(tmp))
            try:
                self.assertEqual({recovered.run("legacy-one")["status"], recovered.run("legacy-two")["status"]}, {"failed"})
                self.assertTrue(recovered.create_or_reuse_run(second)[1])
            finally:
                recovered.close()

    def test_restart_revokes_approval_from_an_abandoned_run(self) -> None:
        class Response:
            def raise_for_status(self) -> None: pass
        calls: list[dict[str, object]] = []
        class AgentsClient:
            def __init__(self, **_: object): pass
            def __enter__(self) -> "AgentsClient": return self
            def __exit__(self, *_: object) -> None: pass
            def post(self, _: str, json: dict[str, object]) -> Response:
                calls.append(json); return Response()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            portal_store = PortalStore(root / "portal")
            run = portal_store.create_run(portal_store.head())
            portal_store.close()
            agents_store = AgentStore(root / "agents")
            try:
                agents_store.approve("p", "candidate", "candidate", "a" * 64, "promote", "staging", "ok", run)
                self.assertIsNotNone(agents_store.get_active_candidate_approval("p", "candidate"))
                settings = Settings("portal", root / "portal", "p", "token", "", "http://agents", "", "", "", "", "", 1000)
                with patch.object(main_module.httpx, "Client", AgentsClient), TestClient(portal(settings)):
                    pass
                self.assertEqual(calls, [{"project": "p", "runs": [run]}])
                agents_store.revoke_approvals_for_runs("p", calls[0]["runs"])  # type: ignore[arg-type]
                self.assertIsNone(agents_store.get_active_candidate_approval("p", "candidate"))
            finally:
                agents_store.close()

    def test_active_runs_are_reused_concurrently_and_terminal_runs_can_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = PortalStore(Path(tmp))
            try:
                commit = store.head()
                with ThreadPoolExecutor(max_workers=8) as pool:
                    runs = list(pool.map(lambda _: store.create_or_reuse_run(commit), range(16)))
                self.assertEqual({run for run, _ in runs}, {runs[0][0]})
                self.assertEqual(sum(created for _, created in runs), 1)
                first = runs[0][0]
                store.update_run(first, "passed")
                second, created = store.create_or_reuse_run(commit)
                self.assertTrue(created)
                self.assertNotEqual(first, second)
                self.assertEqual([row[0] for row in store.db.execute("SELECT number FROM runs ORDER BY number")], [1, 2])
            finally:
                store.close()

    def test_active_pipeline_blocks_a_new_candidate_until_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = PortalStore(Path(tmp))
            try:
                commit_a = store.head()
                run_a, created = store.create_or_reuse_run(commit_a)
                self.assertTrue(created)
                tree_b = dict(store.tree(commit_a)); tree_b["README.md"] += "next\n"
                commit_b = store.commit(tree_b, commit_a)
                with self.assertRaisesRegex(RuntimeError, "pipeline already active"):
                    store.create_or_reuse_run(commit_b)
                store.update_run(run_a, "stale")
                run_b, created = store.create_or_reuse_run(commit_b)
                self.assertTrue(created)
                self.assertNotEqual(run_a, run_b)
            finally:
                store.close()


class BoundaryTests(unittest.TestCase):
    def test_settings_load_requires_non_placeholder_internal_token(self) -> None:
        for token in (None, "", "   ", "test-token", "replace-with-a-long-random-token", "x" * 31):
            with self.subTest(token=token), patch.dict(os.environ, {} if token is None else {"INTERNAL_TOKEN": token}, clear=True):
                with self.assertRaisesRegex(ValueError, "INTERNAL_TOKEN"):
                    Settings.load("portal")
        token = "a" * 32
        with patch.dict(os.environ, {"INTERNAL_TOKEN": token}, clear=True):
            self.assertEqual(Settings.load("portal").internal_token, token)

    def test_path_traversal_and_oversized_tree_are_rejected(self) -> None:
        with self.assertRaises(HTTPException): checked_tree({"../secret.py": "x"}, 100)
        with self.assertRaises(HTTPException): checked_tree({"x.py": "x" * 101}, 100)

    def test_path_heavy_trees_are_rejected_before_scanning(self) -> None:
        paths = {f"nested/{index:04d}/empty.tf": "" for index in range(129)}
        with self.assertRaises(HTTPException):
            checked_tree(paths, 262144)
        with self.assertRaises(HTTPException):
            checked_tree({"a" * 181: ""}, 262144)

    def test_portal_and_scanner_share_tree_limits(self) -> None:
        tree = {f"nested/{index:04d}/empty.tf": "" for index in range(129)}
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 262144)
            with TestClient(portal(settings)) as portal_client, TestClient(scanner(settings)) as scanner_client:
                head = portal_client.get("/api/repository").json()["head"]
                self.assertEqual(portal_client.post("/api/commits", json={"expected_head": head, "tree": tree}).status_code, 413)
                self.assertEqual(scanner_client.post("/scan", headers={"X-Internal-Token": "token"}, json={"tree": tree}).status_code, 413)

    def test_request_body_limit_precedes_json_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 262144)
            app = portal(settings)
            with TestClient(app) as client:
                self.assertEqual(client.post("/api/commits", content=b"x" * (MAX_REQUEST_BYTES + 1), headers={"Content-Type": "application/json", "Content-Length": str(MAX_REQUEST_BYTES + 1)}).status_code, 413)
                sent: list[dict] = []
                async def receive() -> dict: return {"type": "http.request", "body": b"x" * (MAX_REQUEST_BYTES + 1), "more_body": False}
                async def send(message: dict) -> None: sent.append(message)
                asyncio.run(app({"type": "http", "method": "POST", "path": "/api/commits", "raw_path": b"/api/commits", "query_string": b"", "headers": [(b"content-type", b"application/json"), (b"content-length", b"1")], "scheme": "http", "client": ("test", 0), "server": ("test", 80), "root_path": ""}, receive, send))
                self.assertEqual(next(message["status"] for message in sent if message["type"] == "http.response.start"), 413)
                head = client.get("/api/repository").json()["head"]
                tree = {f"content-{index}.txt": "x" * 52400 for index in range(5)}
                self.assertEqual(client.post("/api/commits", json={"expected_head": head, "tree": tree}).status_code, 200)

    def test_release_dependency_outages_are_generic_503s(self) -> None:
        class DownClient:
            def __init__(self, **_: object): pass
            def __enter__(self) -> "DownClient": return self
            def __exit__(self, *_: object) -> None: pass
            def post(self, *_: object, **__: object) -> object:
                raise httpx.ConnectError("internal host", request=httpx.Request("POST", "http://internal"))
            def get(self, *_: object, **__: object) -> object:
                raise httpx.ConnectError("internal host", request=httpx.Request("GET", "http://internal"))
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "flag", 1000)
            with patch.object(main_module.httpx, "Client", DownClient), TestClient(portal(settings)) as client:
                response = client.post("/api/releases", json={"candidate_ref": "candidate", "action": "promote", "target": "production"})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["detail"], "Release service unavailable")
            with patch.object(main_module.httpx, "Client", DownClient), TestClient(release(settings)) as client:
                self.assertEqual(client.get("/healthz").json(), {"status": "ok"})
                response = client.post("/release", headers={"X-Internal-Token": "token"}, json={"candidate_ref": "candidate", "action": "promote", "target": "production"})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["detail"], "Required release dependencies unavailable")

    def test_internal_and_raw_mutation_routes_are_not_public(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 1000)
            with TestClient(portal(settings)) as client:
                self.assertEqual(client.get("/internal/tree/candidate").status_code, 401)
                self.assertEqual(client.post("/api/sarif", json={}).status_code, 404)
                self.assertEqual(client.post("/api/approvals", json={}).status_code, 404)
                for path in ("/docs", "/redoc", "/openapi.json"):
                    self.assertEqual(client.get(path).status_code, 404)

    def test_fastapi_documentation_is_disabled_for_every_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 1000)
            for factory in (portal, scanner, agents, release):
                with TestClient(factory(settings)) as client:
                    for path in ("/docs", "/redoc", "/openapi.json"):
                        self.assertEqual(client.get(path).status_code, 404)

    def test_assurance_clues_and_dashboard_are_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 1000)
            with TestClient(portal(settings)) as client:
                assurances = client.get("/api/assurances").json()
                self.assertTrue(any(item["control"] == "release-integrity" and item["status"] == "UNVERIFIED" and item["scope"] == "repository" for item in assurances))
                self.assertIn("infra/storage.tf", seeded_tree())
                assurances_page = client.get("/assurances").text
                self.assertIn("<scanner-rule-id>", assurances_page)
                self.assertIn("<terraform-resource-address>", assurances_page)
                self.assertIn("release artifact provenance", assurances_page)
                self.assertIn("artifact-storage auditability", assurances_page)
                for path in ("/", "/repository", "/commits", "/runs", "/artifacts", "/assurances", "/releases"):
                    page = client.get(path).text
                    self.assertNotIn("AVD-AWS-0089", page)
                    self.assertNotIn("aws_s3_bucket.artifacts", page)
                self.assertIn("Latest Pipeline", client.get("/").text)
                self.assertIn("Repository Workbench", client.get("/repository").text)
                self.assertIn("Commit Update", client.get("/repository").text)
                self.assertIn("Pipeline Control", client.get("/runs").text)
                self.assertIn("Request Release", client.get("/releases").text)
                self.assertNotIn('statusPill("mutable", "warn")', client.get("/").text)

    def test_public_assurance_contract_changes_after_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStore(Path(tmp))
            try:
                self.assertEqual(store.public_assurances("p"), [])
                store.store_security_observation("p", "run", {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"})
                assurance = store.public_assurances("p")[0]
                self.assertEqual((assurance["control"], assurance["status"], assurance["state"], assurance["originating_run"]), ("release-integrity", "VERIFIED", "VERIFIED", "run"))
                self.assertEqual((assurance["evidence_class"], assurance["source"], assurance["artifact"]), ("scanner policy evidence", "Trivy", "results.sarif"))
                self.assertNotIn("accepted scanner exception evidence", json.dumps(assurance))
            finally: store.close()

    def test_portal_receives_uppercase_assurance_projection(self) -> None:
        class Response:
            def json(self) -> list[dict[str, str]]: return [{"control": "release-integrity", "status": "VERIFIED", "state": "VERIFIED", "scope": "repository", "evidence_class": "scanner policy evidence", "source": "Trivy", "originating_run": "run", "artifact": "results.sarif"}]
            def raise_for_status(self) -> None: pass
        class AgentsClient:
            def __init__(self, **_: object): pass
            def __enter__(self) -> "AgentsClient": return self
            def __exit__(self, *_: object) -> None: pass
            def get(self, *_: object, **__: object) -> Response: return Response()
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "http://agents", "", "", "", "", "", 1000)
            with patch.object(main_module.httpx, "Client", AgentsClient), TestClient(portal(settings)) as client:
                public = client.get("/api/assurances").json()
                dashboard = client.get("/api/dashboard").json()
                expected = {"control": "release-integrity", "status": "VERIFIED", "state": "VERIFIED", "scope": "repository", "evidence_class": "scanner policy evidence", "source": "Trivy", "originating_run": "run", "artifact": "results.sarif"}
                self.assertIn(expected, public); self.assertIn(expected, dashboard["assurances"])

    def test_historical_commit_cannot_start_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 4096)
            with TestClient(portal(settings)) as client:
                repo = client.get("/api/repository").json()
                tree_a = repo["tree"]; tree_a["README.md"] += "A\n"
                commit_a = client.post("/api/commits", json={"expected_head": repo["head"], "tree": tree_a}).json()["commit"]
                tree_b = dict(tree_a); tree_b["README.md"] += "B\n"
                commit_b = client.post("/api/commits", json={"expected_head": commit_a, "tree": tree_b}).json()["commit"]
                self.assertNotEqual(commit_a, commit_b)
                self.assertEqual(client.get("/api/repository").json()["head"], commit_b)
                self.assertEqual(client.post("/api/runs", json={"commit": commit_a}).status_code, 409)
                self.assertEqual(client.post("/api/runs", json={"commit": commit_b}).status_code, 200)

    def test_public_candidate_approval_evidence_survives_candidate_advance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 4096)
            app = portal(settings)
            endpoint = next(route.endpoint for route in app.routes if route.path == "/api/runs/{run}")
            store = dict(zip(endpoint.__code__.co_freevars, (cell.cell_contents for cell in endpoint.__closure__)))["store"]
            reviewed = store.head()
            run = store.create_run(reviewed)
            review = {"observations": [{"tool": "approval_controller", "result": "issued"}], "review_mode": "fast", "approval": {"binding_type": "candidate", "binding_value": "candidate", "observed_commit": reviewed, "action": "promote", "target": "staging", "decision": "approved", "expires_at": 1}}
            store.update_run(run, "passed", sarif=sarif_for(seeded_tree()), review=review)
            with TestClient(app) as client:
                before = client.get(f"/api/runs/{run}").json()
                repo = client.get("/api/repository").json()
                self.assertEqual(before["review"]["review_path"], "fast")
                page = client.get("/").text
                self.assertIn("pipelineStages(run, false)", page)
                self.assertIn("pipelineStages(run, true)", page)
                self.assertIn("String(review.review_path).toUpperCase()", page)
                self.assertEqual(before["approval"], {"status": "approved", "deployment_candidate": repo["candidate_ref"], "reviewed_revision": reviewed[:12], "policy_tier": "expedited", "expires_at": 1})
                tree = dict(repo["tree"]); tree["README.md"] += "advance\n"
                advanced = client.post("/api/commits", json={"expected_head": repo["head"], "tree": tree}).json()["commit"]
                after = client.get(f"/api/runs/{run}").json()
                self.assertEqual(after["approval"], before["approval"])
                self.assertEqual(client.get("/api/repository").json()["head"], advanced)
                self.assertNotIn("binding_type", json.dumps(after))
                self.assertIn("index === 2 && details && review.assurance_updated", page)
                self.assertIn('items[3][2] = details ? `Deployment candidate: ${approval.deployment_candidate || "revision-bound"}', page)
                self.assertIn(': "Approved"', page)
                self.assertIn("expiryText(approval.expires_at)", page)

    def test_pipeline_becoming_stale_before_review_never_calls_agents(self) -> None:
        class Response:
            def __init__(self, body: dict): self.body = body
            def raise_for_status(self) -> None: pass
            def json(self) -> dict: return self.body
        class ScannerOnlyClient:
            calls: list[str] = []
            def __init__(self, **_: object): pass
            def __enter__(self) -> "ScannerOnlyClient": return self
            def __exit__(self, *_: object) -> None: pass
            def post(self, url: str, json: dict) -> Response:
                self.calls.append(url)
                if url.endswith("/scan"): return Response(sarif_for(json["tree"]))
                raise AssertionError("stale pipeline must not call ReviewBot")
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "http://scanner", "http://agents", "", "", "", "", "", 1000)
            app = portal(settings)
            start = next(route.endpoint for route in app.routes if route.path == "/api/runs")
            closure = dict(zip(start.__code__.co_freevars, (cell.cell_contents for cell in start.__closure__)))
            store, run_pipeline = closure["store"], closure["run_pipeline"]
            tree_a = store.tree(store.head()); tree_a["README.md"] += "A\n"; commit_a = store.commit(tree_a, store.head())
            run = store.create_run(commit_a)
            tree_b = dict(tree_a); tree_b["release.json"] = '{"action":"promote","target":"production"}'
            commit_b = store.commit(tree_b, commit_a)
            self.assertNotEqual(commit_a, commit_b); self.assertEqual(store.head(), commit_b)
            try:
                with patch.object(main_module.httpx, "Client", ScannerOnlyClient): run_pipeline(run, commit_a)
                state = store.run(run)
                self.assertEqual(state["status"], "stale")
                self.assertIsNone(state["review"])
                self.assertEqual(ScannerOnlyClient.calls, ["http://scanner/scan"])
            finally: store.close()

    def test_candidate_advance_during_review_cannot_finalize_approval(self) -> None:
        class Response:
            def __init__(self, body: dict): self.body = body
            def raise_for_status(self) -> None: pass
            def json(self) -> dict: return self.body
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "http://scanner", "http://agents", "", "", "", "", "", 1000)
            app = portal(settings)
            start = next(route.endpoint for route in app.routes if route.path == "/api/runs")
            closure = dict(zip(start.__code__.co_freevars, (cell.cell_contents for cell in start.__closure__)))
            store, run_pipeline = closure["store"], closure["run_pipeline"]
            tree_a = store.tree(store.head()); tree_a["README.md"] += "A\n"; commit_a = store.commit(tree_a, store.head()); run = store.create_run(commit_a)
            class RaceClient:
                calls: list[str] = []
                def __init__(self, **_: object): pass
                def __enter__(self) -> "RaceClient": return self
                def __exit__(self, *_: object) -> None: pass
                def post(self, url: str, json: dict) -> Response:
                    self.calls.append(url)
                    if url.endswith("/scan"):
                        return Response(sarif_for(json["tree"]))
                    if url.endswith("/review"):
                        tree_b = dict(tree_a); tree_b["README.md"] += "B\n"; store.commit(tree_b, commit_a)
                        proposal = {"binding_type": "candidate", "binding_value": "candidate", "observed_commit": commit_a, "action": "promote", "target": "staging", "decision": "approved", "rationale": "reviewed"}
                        return Response({"review_mode": "fast", "approval": proposal, "observations": []})
                    raise AssertionError("approval must not be finalized after candidate advancement")
            try:
                with patch.object(main_module.httpx, "Client", RaceClient): run_pipeline(run, commit_a)
                self.assertEqual(store.run(run)["status"], "stale")
                self.assertEqual(RaceClient.calls, ["http://scanner/scan", "http://agents/review"])
            finally: store.close()

    def test_public_run_projection_hides_prompt_tools_and_model_prose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 1000)
            app = portal(settings)
            endpoint = next(route.endpoint for route in app.routes if route.path == "/api/runs/{run}")
            closure = dict(zip(endpoint.__code__.co_freevars, (cell.cell_contents for cell in endpoint.__closure__)))
            try:
                raw = {"id": "r", "number": 1, "commit_id": "a" * 64, "status": "passed", "created_at": 0, "sarif": sarif_for(seeded_tree()), "review": {"summary": "You are ReviewBot. INTERNAL_TOKEN; record_security_observation(arguments={secret})", "tool_calls": [{"name": "record_security_observation", "arguments": {"source": "scanner"}}], "observations": [{"tool": "get_sarif_findings", "result": "1 results"}, {"tool": "get_project_memory", "result": "0 assurance record(s)"}], "approval": {"binding_type": "candidate", "binding_value": "candidate", "observed_commit": "a" * 64, "action": "promote", "target": "staging", "decision": "approved", "expires_at": 1}}}
                public = json.dumps(closure["public_run"](raw))
                for forbidden in ("You are ReviewBot", "INTERNAL_TOKEN", "record_security_observation", "arguments", "secret", "binding_type", "binding_value", "staging"):
                    self.assertNotIn(forbidden, public)
                self.assertIn('"deployment_candidate": "candidate"', public)
            finally: closure["store"].close()

    def test_public_endpoints_never_serialize_reviewbot_leaks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings("portal", Path(tmp), "p", "token", "", "", "", "", "", "", "", 1000)
            app = portal(settings)
            endpoint = next(route.endpoint for route in app.routes if route.path == "/api/runs/{run}")
            store = dict(zip(endpoint.__code__.co_freevars, (cell.cell_contents for cell in endpoint.__closure__)))["store"]
            run = store.create_run(store.head())
            store.update_run(run, "passed", sarif=sarif_for(seeded_tree()), review={"summary": "You are ReviewBot SYSTEM PROMPT LEAK MARKER INTERNAL_TOKEN record_security_observation recommend_review_path tool schema secret", "tool_calls": [{"name": "record_security_observation", "arguments": {"secret": "tool schema secret"}}], "observations": [{"tool": "get_sarif_findings", "result": "1 results"}, {"tool": "get_project_memory", "result": "0 assurance record(s)"}]})
            with TestClient(app) as client:
                payloads = [client.get(path).text for path in ("/", "/runs", "/artifacts", "/api/dashboard", "/api/runs", f"/api/runs/{run}", "/api/assurances")]
            for public in payloads:
                for forbidden in ("You are ReviewBot", "SYSTEM PROMPT LEAK MARKER", "INTERNAL_TOKEN", "record_security_observation", "recommend_review_path", "tool schema secret", '"arguments"'):
                    self.assertNotIn(forbidden, public)


if __name__ == "__main__": unittest.main()
