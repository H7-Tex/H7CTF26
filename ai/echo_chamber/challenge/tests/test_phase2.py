from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

import httpx

from echo_chamber.ai.client import QwenClient, QwenServiceError
from echo_chamber.ai.config import QwenSettings, REQUIRED_MODEL
from echo_chamber.ai.parsers import EvidenceSynthesis, parse_output
from echo_chamber.ai.profiles import INFERENCE_PROFILES
from echo_chamber.ai.prompts import evidence_synthesis, symptom_extraction, technical_summary


class PhaseTwoTests(unittest.TestCase):
    def test_profiles_are_task_specific_and_bounded(self) -> None:
        self.assertEqual(set(INFERENCE_PROFILES), {
            "technical_summary", "symptom_extraction", "diagnostic_assessment", "evidence_synthesis"
        })
        self.assertTrue(all(0 <= profile.temperature <= 1 and 0 < profile.top_p <= 1 for profile in INFERENCE_PROFILES.values()))
        self.assertEqual(INFERENCE_PROFILES["evidence_synthesis"].temperature, 0.0)

    def test_local_ollama_model_override_is_development_only(self) -> None:
        with patch.dict("os.environ", {
            "QWEN_BASE_URL": "http://127.0.0.1:11434", "QWEN_MODEL": "qwen2.5-coder:7b"
        }):
            self.assertEqual(QwenSettings.from_env(), QwenSettings("http://127.0.0.1:11434", "qwen2.5-coder:7b"))
        with patch.dict("os.environ", {
            "QWEN_BASE_URL": "https://qwen.h7tex.com", "QWEN_MODEL": "qwen2.5-coder:7b"
        }):
            with self.assertRaises(ValueError):
                QwenSettings.from_env()

    def test_parser_validates_schema_and_allows_fenced_json(self) -> None:
        value = parse_output("evidence_synthesis", '```json\n{"hypothesis":"allocator regression","relation":"supports","confidence":0.8,"citations":[]}\n```')
        self.assertIsInstance(value, EvidenceSynthesis)
        with self.assertRaises(ValueError):
            parse_output("evidence_synthesis", '{"hypothesis":"x","relation":"approve","confidence":2,"citations":[],"flag":"secret"}')

    def test_per_citation_relation_is_required_and_validated(self) -> None:
        valid = '{"hypothesis":"allocator regression","relation":"mentions","confidence":0.5,"citations":[{"evidence_id":"KB-1001","claim":"Observed heap damage","relation":"supports"}]}'
        parsed = parse_output("evidence_synthesis", valid)
        self.assertEqual(parsed.citations[0].relation, "supports")
        with self.assertRaises(ValueError):
            parse_output("evidence_synthesis", valid.replace('"supports"}]', '"approve"}]'))

    def test_transform_prompt_treats_source_as_data(self) -> None:
        system, user = technical_summary("A worker was restarted after an upgrade.")
        self.assertIn("untrusted data", system)
        self.assertIn("<document>", user)
        _, symptom_prompt = symptom_extraction("A report mentions an unobserved worker failure.")
        self.assertIn("mentioned_symptoms", symptom_prompt)
        self.assertIn("Never put a merely mentioned", symptom_prompt)

    def test_analysis_prompt_requires_numeric_confidence_and_allowlisted_ids(self) -> None:
        system, user = evidence_synthesis({"incident_id": "INC-7421"}, [
            {"evidence_id": "KB-1001", "content": "A worker exited unexpectedly."},
        ])
        self.assertIn("JSON number", system)
        self.assertIn("not a descriptive label", user)
        self.assertIn("untrusted data", system)
        self.assertIn("corroborating evidence", system)
        self.assertIn("General release notes", system)
        self.assertIn("vendor bulletin", system)
        self.assertIn("incident titles and reporter", system)
        self.assertIn("three-gate test", system)
        self.assertIn("need not originate from this exact incident", system)
        self.assertIn('["KB-1001"]', user)

    def test_transform_schemas_keep_observations_distinct(self) -> None:
        _, summary_prompt = technical_summary("A worker restarted; diagnostics showed heap damage.")
        self.assertIn("supporting_observations", summary_prompt)
        _, symptom_prompt = symptom_extraction("A worker restarted; heap damage was mentioned as an example.")
        self.assertIn("observed_diagnostic_indicators", symptom_prompt)
        self.assertIn("mentioned_diagnostic_indicators", symptom_prompt)
        self.assertIn("Do not invent observations", symptom_prompt)

    def test_synthesis_does_not_receive_origin_metadata(self) -> None:
        _, user = evidence_synthesis({"incident_id": "INC-1"}, [{
            "evidence_id": "KB-1001", "origin_id": "SUB-0001", "representation_type": "technical_summary",
            "title": "Technical note", "content": "Observed failure.",
        }])
        self.assertNotIn("origin_id", user)

    def test_client_uses_required_model_profile_and_openai_endpoint(self) -> None:
        seen: dict[str, object] = {}

        def respond(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.path
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
                "primary_claim": "Worker runtime issue", "affected_product": "StreamForge",
                "affected_version": "4.8", "affected_component": "worker-runtime",
                "technical_cause": "allocator instability",
                "supporting_observations": ["worker exits were observed"],
            })}}]})

        async def run() -> None:
            transport = httpx.MockTransport(respond)
            http = httpx.AsyncClient(base_url="https://qwen.h7tex.com", transport=transport)
            client = QwenClient(QwenSettings(), client=http)
            result = await client.complete("technical_summary", "system", "user")
            self.assertEqual(result.affected_product, "StreamForge")
            await http.aclose()

        asyncio.run(run())
        body = seen["body"]
        self.assertEqual(seen["path"], "/v1/chat/completions")
        self.assertEqual(body["model"], REQUIRED_MODEL)
        self.assertEqual(body["temperature"], INFERENCE_PROFILES["technical_summary"].temperature)

    def test_service_errors_do_not_substitute_fake_inference(self) -> None:
        async def fail(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")

        async def run() -> None:
            http = httpx.AsyncClient(base_url="https://qwen.h7tex.com", transport=httpx.MockTransport(fail))
            client = QwenClient(QwenSettings(), client=http)
            with self.assertRaises(QwenServiceError):
                await client.complete("technical_summary", "system", "user")
            await http.aclose()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
