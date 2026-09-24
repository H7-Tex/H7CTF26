from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from echo_chamber.main import create_app


class PhaseSevenTests(unittest.TestCase):
    def test_player_workspace_surfaces_operational_sections(self) -> None:
        app = create_app(":memory:")
        try:
            response = TestClient(app).get("/")
            self.assertEqual(response.status_code, 200)
            for label in ("Knowledge archive", "Research intake", "Evidence record", "Reports", "Run analysis"):
                self.assertIn(label, response.text)
            self.assertNotIn("RAG poisoning", response.text)
            self.assertNotIn("exploit successful", response.text.lower())
            self.assertNotIn("Required for corroboration", response.text)
            self.assertNotIn("source lineage", response.text.lower())
            self.assertNotIn("Origin ${item.origin_id}", response.text)
        finally:
            app.state.database.close()

    def test_fastapi_documentation_is_disabled(self) -> None:
        app = create_app(":memory:")
        try:
            client = TestClient(app)
            for route in ("/docs", "/redoc", "/openapi.json"):
                self.assertEqual(client.get(route).status_code, 404)
            self.assertEqual(client.get("/api/incidents/INC-7421").status_code, 200)
        finally:
            app.state.database.close()


if __name__ == "__main__":
    unittest.main()
