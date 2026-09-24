from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from echo_chamber.ai.parsers import parse_output
from echo_chamber.main import create_app


class Analyst:
    def __init__(self, citation_count: int) -> None:
        self.citation_count = citation_count
        self.prompts: list[str] = []

    async def complete(self, task: str, system: str, user: str):
        self.prompts.extend((system, user))
        evidence = json.loads(user.split("<context>\n", 1)[1].split("\n</context>", 1)[0])["evidence"]
        citations = [{"evidence_id": row["evidence_id"], "claim": "Record contains a relevant diagnostic observation.", "relation": "supports"}
                     for row in evidence[:self.citation_count]]
        return parse_output("evidence_synthesis", json.dumps({"hypothesis": "allocator regression",
            "relation": "supports", "confidence": 0.84, "citations": citations}))


class PhaseSixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.state.database.close()

    def test_flag_only_enters_deep_report_after_corroboration(self) -> None:
        secret = "H7CTF{phase_six_report_secret}"
        analyst = Analyst(3)
        self.app.state.qwen = analyst
        with patch.dict(os.environ, {"FLAG": secret}):
            pre_corroboration = [
                self.client.get("/api/incidents/INC-7421").json(),
                self.client.get("/api/incidents/INC-7421/reports").json(),
                self.client.get("/api/knowledge").json(),
            ]
            self.assertNotIn(secret, json.dumps(pre_corroboration))
            analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
            report = self.client.get(f"/api/reports/{analysis['report_id']}").json()
        self.assertEqual(analysis["status"], "corroborated")
        self.assertEqual(report["diagnostic_depth"], "deep")
        self.assertEqual(set(report["artifacts"]), {
            "application.log", "worker.log", "metrics.json", "process-environment.txt",
            "allocator-diagnostics.txt", "heap-core-metadata.json", "historical-support-metadata.txt",
        })
        self.assertIn(secret, report["artifacts"]["process-environment.txt"])
        self.assertNotIn(secret, "".join(analyst.prompts))
        self.assertEqual(self.client.get("/api/incidents/INC-7421").json()["diagnostic_depth"], "deep")

    def test_probable_analysis_gets_only_standard_diagnostics(self) -> None:
        secret = "H7CTF{not_yet_available}"
        self.app.state.qwen = Analyst(2)
        with patch.dict(os.environ, {"FLAG": secret}):
            analysis = self.client.post("/api/incidents/INC-7421/analyze").json()
            report = self.client.get(f"/api/reports/{analysis['report_id']}").json()
        self.assertEqual(analysis["status"], "probable")
        self.assertEqual(report["diagnostic_depth"], "standard")
        self.assertEqual(set(report["artifacts"]), {"application.log", "worker.log", "metrics.json"})
        self.assertNotIn(secret, json.dumps(report))
        self.assertIsNone(self.client.get("/api/incidents/INC-7421").json()["corroborated_root_cause"])

    def test_later_weak_analysis_does_not_erase_confirmed_incident_state(self) -> None:
        self.app.state.qwen = Analyst(3)
        with patch("echo_chamber.db.Database.reserve_operation", return_value=(True, 0)):
            first = self.client.post("/api/incidents/INC-7421/analyze").json()
            after_first = self.client.get("/api/incidents/INC-7421").json()
            self.app.state.qwen = Analyst(1)
            later = self.client.post("/api/incidents/INC-7421/analyze").json()
            after_weak = self.client.get("/api/incidents/INC-7421").json()
            self.app.state.qwen = Analyst(3)
            repeated = self.client.post("/api/incidents/INC-7421/analyze").json()
            after_repeated = self.client.get("/api/incidents/INC-7421").json()
        self.assertEqual(first["status"], "corroborated")
        self.assertEqual(after_first["diagnostic_depth"], "deep")
        self.assertEqual(later["status"], "unverified")
        self.assertEqual(later["incident_corroboration_status"], "corroborated")
        self.assertEqual(after_weak["diagnostic_depth"], "deep")
        self.assertEqual(repeated["report_id"], first["report_id"])
        self.assertEqual(after_repeated["diagnostic_depth"], "deep")
        self.assertEqual(after_repeated["corroborated_root_cause"], "allocator regression")
        reports = self.client.get("/api/incidents/INC-7421/reports").json()
        self.assertEqual([item["diagnostic_depth"] for item in reports], ["deep"])
        self.assertEqual(self.client.get(f"/api/reports/{first['report_id']}").status_code, 200)


if __name__ == "__main__":
    unittest.main()
