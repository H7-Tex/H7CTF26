from __future__ import annotations

import unittest

from scripts.local_qwen_smoke import semantic_observations, smoke_summary


class LocalSmokePolicyTests(unittest.TestCase):
    def test_semantic_failures_do_not_fail_integration_smoke(self) -> None:
        observations = semantic_observations(
            {
                "status": "corroborated",
                "supporting_evidence_ids": ["KB-1004", "KB-1005", "KB-1008"],
                "citations": [{"evidence_id": "KB-1004", "relation": "supports"}],
            },
            {
                "status": "probable",
                "supporting_evidence_ids": ["SUB-0001-1"],
                "citations": [{"evidence_id": "SUB-0001-1", "relation": "supports"}],
            },
        )

        summary = smoke_summary([], observations, "qwen-local")

        self.assertTrue(summary["integration_passed"])
        self.assertEqual(summary["integration_failures"], [])
        self.assertTrue(summary["semantic_observations"]["seeded_baseline_false_corroboration"])
        self.assertEqual(
            summary["semantic_observations"]["seeded_baseline_unexpected_supporting_evidence_ids"],
            ["KB-1004", "KB-1005", "KB-1008"],
        )
        self.assertTrue(summary["semantic_observations"]["vendor_bulletin_failed_to_corroborate"])

    def test_structural_failures_fail_integration_smoke(self) -> None:
        summary = smoke_summary(["analysis endpoint returned HTTP 500"], {}, "qwen-local")

        self.assertFalse(summary["integration_passed"])
        self.assertEqual(summary["integration_failures"], ["analysis endpoint returned HTTP 500"])

    def test_invalid_citation_rows_are_structural_failures(self) -> None:
        from scripts.local_qwen_smoke import has_invalid_citations

        self.assertFalse(has_invalid_citations([{"relation": "supports"}]))
        self.assertTrue(has_invalid_citations([{"relation": "asserts_support"}]))
        self.assertTrue(has_invalid_citations(["not a citation object"]))
        self.assertTrue(has_invalid_citations(None))


if __name__ == "__main__":
    unittest.main()
