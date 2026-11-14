from __future__ import annotations

import concurrent.futures
import json
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from echo_chamber.ai.client import QwenOutputError, QwenServiceError, QwenTimeoutError
from echo_chamber.ai.parsers import parse_output
from echo_chamber.db import Database
from echo_chamber.main import create_app


REPORT_A = (
    "A StreamForge 4.8 worker-runtime field report records unexpected exits during normal work. "
    "Preserved cores show inconsistent heap allocator metadata after the upgrade. Host memory was "
    "below its limit and the kernel recorded no OOM event. The same workload on 4.7 left the heap intact."
)
REPORT_B = REPORT_A.replace("field report", "customer investigation").replace("records", "documents")
REPORT_C = REPORT_A.replace("field report", "vendor assessment").replace("inconsistent", "damaged")
UNRELATED = (
    "A storage team completed a routine object-store migration. Replication lag cleared after a route "
    "repair. The note contains no StreamForge worker-runtime incident or allocator observations."
)
CONTRADICTORY = (
    "Investigation of StreamForge 4.8 worker-runtime exits found no heap damage or allocator defect. "
    "Core metadata was consistent, restart events followed a host reboot, and the allocator performed "
    "normally. These observations contradict an allocator-regression explanation."
)


class ControllableQwen:
    def __init__(self, supports: int = 0) -> None:
        self.supports = supports
        self.citation_relation = "supports"
        self.fail_task: str | None = None
        self.failure: Exception = QwenServiceError("offline")
        self.prompts: list[str] = []

    async def complete(self, task: str, system: str, user: str):
        self.prompts.extend((system, user))
        if task == self.fail_task:
            raise self.failure
        if task == "technical_summary":
            if "object-store migration" in user:
                value = {"primary_claim": "Storage migration completed", "affected_product": "Object store",
                         "affected_version": "current", "affected_component": "replication",
                         "technical_cause": "route repair", "supporting_observations": ["replication lag cleared"]}
            else:
                value = {"primary_claim": "Worker exits with heap damage", "affected_product": "StreamForge",
                         "affected_version": "4.8", "affected_component": "worker-runtime",
                         "technical_cause": "allocator state corruption",
                         "supporting_observations": ["core shows damaged heap metadata"]}
        elif task == "symptom_extraction":
            if "object-store migration" in user:
                value = {"product": "Object store", "versions": [], "components": ["replication"],
                         "observed_symptoms": ["replication lag"], "mentioned_symptoms": [],
                         "observed_diagnostic_indicators": [], "mentioned_diagnostic_indicators": []}
            else:
                value = {"product": "StreamForge", "versions": ["4.8"], "components": ["worker-runtime"],
                         "observed_symptoms": ["worker exits"], "mentioned_symptoms": [],
                         "observed_diagnostic_indicators": ["heap metadata damage"],
                         "mentioned_diagnostic_indicators": []}
        elif task == "diagnostic_assessment":
            if "object-store migration" in user:
                value = {"diagnostic_findings": ["replication lag cleared after route repair"],
                         "cause_indicators": ["route repair"], "excluded_alternatives": [],
                         "technical_assessment": "Storage migration findings."}
            else:
                value = {"diagnostic_findings": ["core shows heap metadata damage"],
                         "cause_indicators": ["damage follows upgrade"], "excluded_alternatives": ["no OOM"],
                         "technical_assessment": "Findings are consistent with allocator corruption."}
        else:
            context = json.loads(user.split("<context>\n", 1)[1].split("\n</context>", 1)[0])
            derived = [item for item in context["evidence"] if item["representation_type"] != "source"]
            citations = [{"evidence_id": item["evidence_id"], "claim": "Record reports heap corruption.",
                          "relation": self.citation_relation} for item in derived[:self.supports]]
            value = {"relation": "mentions", "confidence": 0.7, "citations": citations}
        return parse_output(task, json.dumps(value))


class HardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.qwen = ControllableQwen()
        self.app.state.qwen = self.qwen
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.state.database.close()

    def submit(self, content: str = REPORT_A):
        return self.client.post("/api/research/submissions", json={
            "product": "StreamForge", "version": "4.8", "title": "Field incident report", "content": content,
        })

    def active_artifacts(self):
        return [item for item in self.client.get("/api/knowledge?limit=100").json()
                if item["representation_type"] != "source"]

    def test_replacement_resets_prior_corroboration_analyses_and_report(self) -> None:
        self.qwen.supports = 3
        first = self.submit().json()
        first_analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
        self.assertEqual(first_analysis["status"], "corroborated")
        self.assertEqual(self.client.get(f"/api/reports/{first_analysis['report_id']}").json()["diagnostic_depth"], "deep")

        now = time.time() + 10
        with patch("echo_chamber.db.time.time", return_value=now):
            replacement = self.submit(REPORT_B)
        self.assertEqual(replacement.status_code, 201, replacement.text)
        current = replacement.json()
        incident = self.client.get("/api/incidents/INC-7421").json()
        self.assertEqual(incident["corroboration_status"], "unverified")
        self.assertIsNone(incident["corroborated_root_cause"])
        self.assertEqual(incident["diagnostic_depth"], "standard")
        self.assertEqual(self.client.get("/api/incidents/INC-7421/analyses").json(), [])
        self.assertEqual(self.client.get("/api/incidents/INC-7421/reports").json(), [])
        self.assertEqual(self.client.get(f"/api/research/submissions/{first['submission_id']}").status_code, 404)
        self.assertEqual({item["origin_id"] for item in self.active_artifacts()}, {current["submission_id"]})
        self.assertEqual(self.client.get(f"/api/reports/{first_analysis['report_id']}").status_code, 404)
        self.qwen.supports = 2
        now = time.time() + 5
        with patch("echo_chamber.db.time.time", return_value=now):
            next_analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
        self.assertEqual(next_analysis["status"], "probable")
        self.assertEqual(next_analysis["supporting"], 2)
        self.assertEqual(len(self.client.get("/api/incidents/INC-7421/analyses").json()), 1)

    def test_bad_valid_source_can_be_replaced_and_retried_without_restart(self) -> None:
        self.qwen.supports = 2
        original = self.submit().json()
        first_analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
        self.assertEqual(first_analysis["incident_corroboration_status"], "probable")
        self.assertEqual(self.client.get("/api/incidents/INC-7421/reports").json()[0]["diagnostic_depth"], "standard")

        self.qwen.fail_task = "diagnostic_assessment"
        now = time.time() + 10
        with patch("echo_chamber.db.time.time", return_value=now):
            failed = self.submit(REPORT_B)
        self.assertEqual(failed.status_code, 503)
        self.assertEqual(self.client.get(f"/api/research/submissions/{original['submission_id']}").status_code, 200)
        self.assertEqual(self.client.get("/api/incidents/INC-7421").json()["corroboration_status"], "probable")
        self.assertEqual(len(self.client.get("/api/incidents/INC-7421/analyses").json()), 1)
        self.assertEqual(len(self.active_artifacts()), 3)
        with self.app.state.database.lock:
            quota = self.app.state.database.connection.execute(
                "SELECT request_count FROM instance_limits WHERE operation='submission'").fetchone()[0]
        self.assertEqual(quota, 1)

        self.qwen.fail_task = None
        now = time.time() + 15
        with patch("echo_chamber.db.time.time", return_value=now):
            replacement = self.submit(REPORT_C)
        self.assertEqual(replacement.status_code, 201, replacement.text)
        self.assertEqual(self.client.get("/api/incidents/INC-7421").json()["corroboration_status"], "unverified")
        self.assertEqual(self.client.get("/api/incidents/INC-7421/analyses").json(), [])
        self.assertEqual(self.client.get("/api/incidents/INC-7421/reports").json(), [])
        self.assertEqual({item["origin_id"] for item in self.active_artifacts()}, {replacement.json()["submission_id"]})
        self.qwen.supports = 2
        now = time.time() + 15
        with patch("echo_chamber.db.time.time", return_value=now):
            usable = self.client.post("/api/incidents/INC-7421/analyze").json()
        self.assertEqual(usable["status"], "probable")

    def test_unrelated_or_contradictory_replacement_has_no_stale_player_evidence(self) -> None:
        prior = self.submit().json()
        now = time.time() + 10
        with patch("echo_chamber.db.time.time", return_value=now):
            replacement = self.submit(UNRELATED).json()
        self.assertEqual(self.client.get(f"/api/research/submissions/{prior['submission_id']}").status_code, 404)
        records = self.active_artifacts()
        self.assertEqual(len(records), 3)
        self.assertEqual({item["origin_id"] for item in records}, {replacement["submission_id"]})
        retrieved = self.client.post("/api/knowledge/search", json={
            "query": "StreamForge 4.8 worker runtime allocator heap termination",
        }).json()
        self.assertFalse({item["evidence_id"] for item in records} &
                         {item["evidence_id"] for item in retrieved})

        self.qwen.citation_relation = "contradicts"
        now = time.time() + 15
        with patch("echo_chamber.db.time.time", return_value=now):
            contradictory = self.submit(CONTRADICTORY).json()
        analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
        self.assertEqual(analysis["status"], "unverified")
        self.assertEqual(analysis["supporting_evidence_ids"], [])
        self.assertTrue(all(item["relation"] == "contradicts" for item in analysis["citations"]))
        self.assertEqual({item["origin_id"] for item in self.active_artifacts()}, {contradictory["submission_id"]})

    def test_unusable_transform_output_returns_502_without_replacing_active_source(self) -> None:
        prior = self.submit().json()
        self.qwen.fail_task = "technical_summary"
        self.qwen.failure = QwenOutputError("bad shape")
        now = time.time() + 10
        with patch("echo_chamber.db.time.time", return_value=now):
            response = self.submit(REPORT_B)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(self.client.get(f"/api/research/submissions/{prior['submission_id']}").status_code, 200)
        self.assertEqual({item["origin_id"] for item in self.active_artifacts()}, {prior["submission_id"]})
        with self.app.state.database.lock:
            count = self.app.state.database.connection.execute(
                "SELECT request_count FROM instance_limits WHERE operation='submission'").fetchone()[0]
        self.assertEqual(count, 1)

    def test_analysis_timeout_does_not_consume_quota_and_retry_succeeds(self) -> None:
        self.qwen.fail_task = "evidence_synthesis"
        self.qwen.failure = QwenTimeoutError("slow")
        failed = self.client.post("/api/incidents/INC-7421/analyze")
        self.assertEqual(failed.status_code, 504)
        with self.app.state.database.lock:
            quota = self.app.state.database.connection.execute(
                "SELECT request_count FROM instance_limits WHERE operation='analysis'").fetchone()[0]
        self.assertEqual(quota, 0)

        self.qwen.fail_task = None
        now = time.time() + 5
        with patch("echo_chamber.db.time.time", return_value=now):
            retried = self.client.post("/api/incidents/INC-7421/analyze")
        self.assertEqual(retried.status_code, 200, retried.text)
        with self.app.state.database.lock:
            quota = self.app.state.database.connection.execute(
                "SELECT request_count FROM instance_limits WHERE operation='analysis'").fetchone()[0]
        self.assertEqual(quota, 1)

    def test_model_cannot_replace_application_hypothesis(self) -> None:
        self.qwen.supports = 3
        submitted = self.submit().json()
        analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
        hypothesis = self.client.get("/api/incidents/INC-7421").json()["working_hypothesis"]
        self.assertEqual(analysis["hypothesis"], hypothesis)
        self.assertEqual(self.client.get("/api/incidents/INC-7421/analyses").json()[0]["hypothesis"], hypothesis)
        self.assertEqual(self.client.get("/api/incidents/INC-7421").json()["corroborated_root_cause"], hypothesis)
        self.assertIn(submitted["submission_id"], {item["origin_id"] for item in self.active_artifacts()})
        self.assertIn(hypothesis, "".join(self.qwen.prompts))
        self.assertNotIn('"hypothesis": "', self.qwen.prompts[-1])

    def test_submission_limit_is_4000_and_invalid_request_uses_no_quota(self) -> None:
        invalid = self.submit("x" * 4001)
        self.assertEqual(invalid.status_code, 422)
        with self.app.state.database.lock:
            row = self.app.state.database.connection.execute(
                "SELECT request_count FROM instance_limits WHERE operation='submission'").fetchone()
        self.assertIsNone(row)

    def test_concurrent_operation_guard_is_serialized(self) -> None:
        db = Database(":memory:")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: db.begin_operation(
                    "analysis", cooldown=0, limit=10, window_seconds=100), range(8)))
            self.assertEqual(sum(allowed for allowed, _ in results), 1)
            db.finish_operation("analysis", success=False, window_seconds=100)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
