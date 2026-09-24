from __future__ import annotations

import asyncio
import json
import unittest

import httpx
from fastapi.testclient import TestClient

from echo_chamber.ai.client import QwenClient
from echo_chamber.ai.config import QwenSettings
from echo_chamber.ai.parsers import parse_output
from echo_chamber.db import Database
from echo_chamber.main import create_app


class FakeQwen:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, task: str, system: str, user: str):
        self.calls += 1
        if task == "technical_summary":
            value = {"primary_claim": "Operational note", "affected_product": "StreamForge",
                "affected_version": "4.8", "affected_component": "worker-runtime", "technical_cause": "unknown",
                "supporting_observations": []}
        elif task == "symptom_extraction":
            value = {"product": "StreamForge", "versions": [], "components": [], "observed_symptoms": [],
                "mentioned_symptoms": [], "observed_diagnostic_indicators": [], "mentioned_diagnostic_indicators": []}
        elif task == "diagnostic_assessment":
            value = {"diagnostic_findings": [], "cause_indicators": [], "excluded_alternatives": [], "technical_assessment": "No findings."}
        else:
            evidence = json.loads(user.split("<context>\n", 1)[1].split("\n</context>", 1)[0])["evidence"]
            value = {"hypothesis": "allocator regression", "relation": "mentions", "confidence": 0.5, "citations": []}
        return parse_output(task, json.dumps(value))


class PhaseEightTests(unittest.TestCase):
    def test_submission_and_analysis_cooldowns_return_429(self) -> None:
        app = create_app(":memory:")
        fake = FakeQwen()
        app.state.qwen = fake
        client = TestClient(app)
        content = "The storage gateway reconciles regional replicas after a routine maintenance window. " * 2
        first = client.post("/api/research/submissions", json={"product": "Archive", "version": "3.2",
            "title": "Storage replication note", "content": content})
        second = client.post("/api/research/submissions", json={"product": "QueueCore", "version": "2.0",
            "title": "Queue maintenance note", "content": "A broker deployment rotates queue credentials during maintenance. " * 3})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 429)
        self.assertIn("Retry-After", second.headers)
        self.assertEqual(fake.calls, 3)

        first_analysis = client.post("/api/incidents/INC-7421/analyze")
        second_analysis = client.post("/api/incidents/INC-7421/analyze")
        self.assertEqual(first_analysis.status_code, 200)
        self.assertEqual(second_analysis.status_code, 429)
        self.assertIn("Retry-After", second_analysis.headers)
        app.state.database.close()

    def test_instance_window_has_a_hard_request_cap(self) -> None:
        db = Database(":memory:")
        self.assertEqual(db.reserve_operation("probe", cooldown=0, limit=1, window_seconds=10000), (True, 0))
        allowed, retry = db.reserve_operation("probe", cooldown=0, limit=1, window_seconds=10000)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        db.close()

    def test_rate_limits_are_scoped_to_each_instance_database(self) -> None:
        first, second = Database(":memory:"), Database(":memory:")
        self.assertTrue(first.reserve_operation("analysis", cooldown=0, limit=1, window_seconds=10000)[0])
        self.assertFalse(first.reserve_operation("analysis", cooldown=0, limit=1, window_seconds=10000)[0])
        self.assertTrue(second.reserve_operation("analysis", cooldown=0, limit=1, window_seconds=10000)[0])
        first.close()
        second.close()

    def test_report_depth_cannot_regress_to_standard(self) -> None:
        db = Database(":memory:")
        db.seed_incident()
        deep_id = db.save_report(incident_id="INC-7421", diagnostic_depth="deep", artifacts="{}", created_at="now")
        db.save_report(incident_id="INC-7421", diagnostic_depth="standard", artifacts="{}", created_at="later")
        incident = db.connection.execute("SELECT diagnostic_depth FROM incidents WHERE incident_id='INC-7421'").fetchone()
        deep = db.connection.execute("SELECT diagnostic_depth FROM reports WHERE report_id=?", (deep_id,)).fetchone()
        self.assertEqual(incident["diagnostic_depth"], "deep")
        self.assertEqual(deep["diagnostic_depth"], "deep")
        db.close()

    def test_qwen_client_bounds_parallel_requests(self) -> None:
        active = maximum = 0

        async def handler(_: httpx.Request) -> httpx.Response:
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.03)
            active -= 1
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
                "primary_claim": "Worker issue", "affected_product": "StreamForge", "affected_version": "4.8",
                "affected_component": "worker-runtime", "technical_cause": "allocator instability",
                "supporting_observations": [],
            })}}]})

        async def run() -> None:
            transport = httpx.MockTransport(handler)
            http = httpx.AsyncClient(base_url="http://ollama.local", transport=transport)
            client = QwenClient(QwenSettings("http://127.0.0.1:11434", "qwen2.5-coder:7b"), client=http)
            await asyncio.gather(*(client.complete("technical_summary", "system", "user") for _ in range(6)))
            await http.aclose()

        asyncio.run(run())
        self.assertEqual(maximum, 2)


if __name__ == "__main__":
    unittest.main()
