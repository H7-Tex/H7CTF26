from __future__ import annotations

import unittest

from echo_chamber.incidents.corroboration import corroboration_status


class PhaseFiveTests(unittest.TestCase):
    def test_only_supporting_citation_relations_count(self) -> None:
        citations = [
            {"evidence_id": "KB-1", "origin_id": "SRC-1", "relation": "supports"},
            {"evidence_id": "KB-2", "origin_id": "SRC-2", "relation": "supports"},
            {"evidence_id": "KB-3", "origin_id": "SRC-3", "relation": "contradicts"},
            {"evidence_id": "KB-4", "origin_id": "SRC-4", "relation": "mentions"},
            {"evidence_id": "KB-5", "origin_id": "SRC-5", "relation": "irrelevant"},
        ]
        self.assertEqual(corroboration_status(citations), ("probable", 2))
        self.assertEqual(corroboration_status(citations[2:]), ("unverified", 0))

    def test_three_supporting_ids_from_one_origin_still_corroborate(self) -> None:
        citations = [
            {"evidence_id": f"KB-{index}", "origin_id": "SUB-0042", "relation": "supports"}
            for index in range(1, 4)
        ]
        self.assertEqual(len({row["origin_id"] for row in citations}), 1)
        self.assertEqual(corroboration_status(citations), ("corroborated", 3))

    def test_three_supporting_ids_from_three_origins_corroborate(self) -> None:
        citations = [
            {"evidence_id": f"KB-{index}", "origin_id": f"SRC-{index}", "relation": "supports"}
            for index in range(1, 4)
        ]
        self.assertEqual(corroboration_status(citations), ("corroborated", 3))

    def test_duplicate_supporting_id_counts_once(self) -> None:
        citations = [
            {"evidence_id": "KB-1", "relation": "supports"},
            {"evidence_id": "KB-1", "relation": "supports"},
            {"evidence_id": "KB-2", "relation": "supports"},
        ]
        self.assertEqual(corroboration_status(citations), ("probable", 2))


if __name__ == "__main__":
    unittest.main()
