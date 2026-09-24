from __future__ import annotations

import re
import unittest

from fastapi.testclient import TestClient

from echo_chamber.main import create_app


class FrontendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(":memory:")
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.app.state.database.close()

    def test_root_template_and_static_assets_are_served(self) -> None:
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn('id="view-incident"', page.text)
        self.assertIn('id="research-form"', page.text)
        self.assertIn('id="evidence-form"', page.text)
        self.assertRegex(page.text, r'<script type="module" src="https?://[^/]+/static/js/workspace\.js"></script>')
        self.assertEqual(
            len(re.findall(r"<script\b", page.text)),
            len(re.findall(r"<script\b[^>]*\bsrc=", page.text)),
            "Every application script must be an external asset.",
        )
        for asset in (
            "/static/css/tokens.css",
            "/static/css/layout.css",
            "/static/css/components.css",
            "/static/js/workspace.js",
            "/static/js/research.js",
            "/static/js/evidence.js",
            "/static/js/reports.js",
        ):
            with self.subTest(asset=asset):
                self.assertEqual(self.client.get(asset).status_code, 200)

    def test_static_modules_use_existing_api_routes(self) -> None:
        scripts = "\n".join(
            self.client.get(f"/static/js/{name}").text
            for name in ("workspace.js", "research.js", "evidence.js", "reports.js")
        )
        for route in (
            "/api/incidents/INC-7421",
            "/api/incidents/INC-7421/analyses",
            "/api/incidents/INC-7421/reports",
            "/api/knowledge",
            "/api/evidence/",
            "/api/research/submissions",
            "/api/reports/",
        ):
            with self.subTest(route=route):
                self.assertIn(route, scripts)

    def test_template_has_unique_ids_and_no_lineage_hint(self) -> None:
        markup = self.client.get("/").text
        ids = re.findall(r'\bid="([^"]+)"', markup)
        duplicates = sorted(value for value in set(ids) if ids.count(value) > 1)
        self.assertFalse(duplicates, f"Duplicate IDs: {duplicates}")
        self.assertNotIn("origin_id", markup)
        self.assertNotIn("shared provenance", markup.lower())


if __name__ == "__main__":
    unittest.main()
