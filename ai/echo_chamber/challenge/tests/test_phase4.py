from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from echo_chamber.ai.parsers import parse_output
from echo_chamber.incidents.analysis import incident_query
from echo_chamber.knowledge.retrieval import retrieve
from echo_chamber.main import create_app
from echo_chamber.models import Incident


class Analyst:
    async def complete(self, task: str, system: str, user: str):
        context = json.loads(user.split("<context>\n", 1)[1].split("\n</context>", 1)[0])
        candidates = context["evidence"]
        assert all("origin_id" not in row for row in candidates)
        citations = [{"evidence_id": row["evidence_id"], "claim": "This record reports an observed incident fact.", "relation": "supports"}
                     for row in candidates[:3]]
        citations += [
            {"evidence_id": "KB-1009", "claim": "A known but unrelated record was not retrieved.", "relation": "mentions"},
            {"evidence_id": "KB-9999", "claim": "An unknown record was not supplied.", "relation": "supports"},
        ]
        return parse_output("evidence_synthesis", json.dumps({"hypothesis": "allocator regression",
            "relation": "mentions", "confidence": 0.82, "citations": citations}))


class PhaseFourTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.state.database.close()

    def test_incident_query_and_search_rank_relevant_records(self) -> None:
        incident = Incident(**self.client.get("/api/incidents/INC-7421").json())
        results = retrieve(self.app.state.database.connection, incident_query(incident))
        self.assertGreaterEqual(len(results), 2)
        self.assertGreaterEqual(results[0]["retrieval_score"], results[-1]["retrieval_score"])
        response = self.client.post("/api/knowledge/search", json={"query": "StreamForge 4.8 worker heap allocator crash"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("StreamForge" in row["title"] for row in response.json()))

    def test_title_terms_alone_do_not_make_a_record_retrievable(self) -> None:
        with self.app.state.database.connection:
            self.app.state.database.connection.execute(
                """INSERT INTO evidence VALUES
                   ('KB-9998', 'SUB-9998', 'diagnostic_assessment',
                    'StreamForge 4.8 worker allocator termination', 'A storage index completed normally.',
                    'diagnostic-assessment-v1', 'now')"""
            )
        incident = Incident(**self.client.get("/api/incidents/INC-7421").json())
        results = retrieve(self.app.state.database.connection, incident_query(incident))
        self.assertNotIn("KB-9998", {item["evidence_id"] for item in results})

    def test_analysis_only_accepts_citations_from_retrieved_set(self) -> None:
        self.app.state.qwen = Analyst()
        response = self.client.post("/api/incidents/INC-7421/analyze")
        self.assertEqual(response.status_code, 200, response.text)
        analysis = response.json()
        self.assertEqual(analysis["relation"], "mentions")
        self.assertEqual(analysis["status"], "corroborated")
        self.assertEqual(len(analysis["citations"]), 3)
        self.assertNotIn("KB-9999", {item["evidence_id"] for item in analysis["citations"]})
        self.assertEqual(set(analysis["rejected_citations"]), {"KB-1009", "KB-9999"})
        self.assertEqual(analysis["supporting"], 3)
        self.assertEqual(set(analysis["supporting_evidence_ids"]), {item["evidence_id"] for item in analysis["citations"]})
        self.assertEqual(analysis["evidence"]["required"], 3)
        incident = self.client.get("/api/incidents/INC-7421").json()
        self.assertEqual(incident["corroboration_status"], "corroborated")
        self.assertEqual(len(self.client.get("/api/incidents/INC-7421/analyses").json()), 1)

    def test_qwen_outage_is_a_clean_service_error(self) -> None:
        class Offline:
            async def complete(self, *_):
                from echo_chamber.ai.client import QwenServiceError
                raise QwenServiceError("offline")

        self.app.state.qwen = Offline()
        response = self.client.post("/api/incidents/INC-7421/analyze")
        self.assertEqual(response.status_code, 503)
        self.assertIn("temporarily unavailable", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
