from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from echo_chamber.main import create_app
from echo_chamber.seed import CORPUS


def tearDownModule() -> None:
    from echo_chamber.main import app
    app.state.database.close()


class PhaseOneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.state.database.close()

    def test_health_and_seeded_incident(self) -> None:
        self.assertEqual(self.client.get("/healthz").json(), {"status": "ok"})
        response = self.client.get("/api/incidents/INC-7421")
        self.assertEqual(response.status_code, 200)
        incident = response.json()
        self.assertEqual(incident["status"], "investigating")
        self.assertIsNone(incident["corroborated_root_cause"])
        self.assertEqual(incident["diagnostic_depth"], "standard")

    def test_seeded_corpus_is_browsable_and_lineage_ready(self) -> None:
        response = self.client.get("/api/knowledge")
        self.assertEqual(response.status_code, 200)
        records = response.json()
        self.assertEqual(len(records), len(CORPUS))
        self.assertEqual(records[0]["representation_type"], "source")
        self.assertTrue(records[0]["origin_id"].startswith("SRC-"))
        self.assertEqual(self.client.get(f"/api/evidence/{records[0]['evidence_id']}").status_code, 200)

    def test_unknown_incident_is_404(self) -> None:
        self.assertEqual(self.client.get("/api/incidents/INC-0000").status_code, 404)

    def test_research_routes_are_available(self) -> None:
        self.assertEqual(self.client.get("/api/research/submissions/SUB-0001").status_code, 404)


if __name__ == "__main__":
    unittest.main()
