from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from echo_chamber.ai.parsers import parse_output
from echo_chamber.main import create_app


class FakeQwen:
    async def complete(self, task: str, system: str, user: str):
        values = {
            "technical_summary": {"primary_claim": "Worker termination", "affected_product": "StreamForge",
                "affected_version": "4.8", "affected_component": "worker-runtime", "technical_cause": "allocator instability",
                "supporting_observations": ["worker exits were observed", "heap metadata was inconsistent"]},
            "symptom_extraction": {"product": "StreamForge", "versions": ["4.8"], "components": ["worker-runtime"],
                "observed_symptoms": ["worker termination"], "mentioned_symptoms": [],
                "observed_diagnostic_indicators": ["heap metadata was inconsistent"],
                "mentioned_diagnostic_indicators": []},
            "diagnostic_assessment": {"diagnostic_findings": ["heap metadata is inconsistent"],
                "cause_indicators": ["failure followed the 4.8 upgrade"],
                "excluded_alternatives": ["no queue-pressure evidence"],
                "technical_assessment": "Observed heap damage is consistent with allocator instability."},
        }
        return parse_output(task, json.dumps(values[task]))


class PhaseThreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.app.state.qwen = FakeQwen()
        self.client = TestClient(self.app)
        self.content = (
            "A customer running StreamForge 4.8 on Linux reports intermittent worker-runtime exits. "
            "The failure appears after upgrade and heap metadata is inconsistent in allocator diagnostics. "
            "Collect worker logs and runtime metrics, verify native extensions against the 4.8 ABI, "
            "and compare allocator behavior with the previous release before rolling back."
        )

    def tearDown(self) -> None:
        self.app.state.database.close()

    def submit(self, content: str | None = None):
        return self.client.post("/api/research/submissions", json={
            "product": "StreamForge", "version": "4.8", "title": "Customer compatibility report",
            "content": content or self.content,
        })

    def test_one_source_creates_three_lineage_linked_artifacts(self) -> None:
        response = self.submit()
        self.assertEqual(response.status_code, 201, response.text)
        submission = response.json()
        self.assertEqual(len(submission["artifacts"]), 3)
        artifacts = self.client.get(f"/api/research/submissions/{submission['submission_id']}/artifacts").json()
        self.assertEqual({item["origin_id"] for item in artifacts}, {submission["submission_id"]})
        self.assertEqual({item["representation_type"] for item in artifacts}, {
            "technical_summary", "symptom_profile", "diagnostic_assessment"
        })
        history = self.client.get(f"/api/research/submissions/{submission['submission_id']}/history").json()
        self.assertEqual(len(history["pipeline"]), 3)
        assessment = next(item for item in artifacts if item["representation_type"] == "diagnostic_assessment")
        self.assertIn("heap metadata", json.loads(assessment["content"])["diagnostic_findings"][0])
        summary = json.loads(next(item for item in artifacts if item["representation_type"] == "technical_summary")["content"])
        symptoms = json.loads(next(item for item in artifacts if item["representation_type"] == "symptom_profile")["content"])
        self.assertEqual(summary["supporting_observations"], ["worker exits were observed", "heap metadata was inconsistent"])
        self.assertEqual(symptoms["observed_diagnostic_indicators"], ["heap metadata was inconsistent"])
        self.assertEqual(symptoms["mentioned_diagnostic_indicators"], [])
        self.assertEqual(set(json.loads(assessment["content"])), {
            "diagnostic_findings", "cause_indicators", "excluded_alternatives", "technical_assessment"
        })

    def test_punctuation_only_duplicate_is_collapsed(self) -> None:
        self.assertEqual(self.submit().status_code, 201)
        self.assertEqual(self.submit(self.content.replace(".", "!" )).status_code, 409)

    def test_near_duplicate_paraphrase_is_collapsed(self) -> None:
        self.assertEqual(self.submit().status_code, 201)
        paraphrase = self.content.replace("reports", "observes").replace("appears", "occurs").replace(
            "Collect worker logs", "Gather worker logs"
        )
        self.assertEqual(self.submit(paraphrase).status_code, 409)

    def test_artifact_has_canonical_validated_json(self) -> None:
        submission = self.submit().json()
        artifact = self.client.get(f"/api/research/submissions/{submission['submission_id']}/artifacts").json()[0]
        self.assertEqual(json.loads(artifact["content"])["affected_product"], "StreamForge")


if __name__ == "__main__":
    unittest.main()
