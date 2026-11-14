from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
PACKAGE = ROOT.parent


class PackagingTests(unittest.TestCase):
    def test_h7_layout_exists(self) -> None:
        for path in (
            PACKAGE / "challenge.yml",
            PACKAGE / "README.md",
            ROOT / "Dockerfile",
            ROOT / "docker-compose.yml",
            ROOT / ".dockerignore",
            ROOT / ".env.example",
            ROOT / "pyproject.toml",
            ROOT / "trustfall",
            ROOT / "tests",
            PACKAGE / "solution" / "solve.py",
            PACKAGE / "solution" / "README.md",
            PACKAGE / "writeup" / "README.md",
            PACKAGE / "writeup" / "img",
            PACKAGE / "handout",
        ):
            self.assertTrue(path.exists(), path)

    def test_metadata_contract(self) -> None:
        metadata = (PACKAGE / "challenge.yml").read_text()
        for value in (
            "name: Trustfall CI",
            "category: ai",
            "difficulty: hard",
            "type: dynamic",
            'dynamic_flag_prefix: "H7CTF{"',
            "resource_type: docker",
            "image: h7ctf26/trustfall_ci",
            'cpu_limit: "1.0"',
            "memory_limit: 512Mi",
            "port: 8080",
        ):
            self.assertIn(value, metadata)
        for unsupported in ("is_regex", "network_mode"):
            self.assertNotIn(unsupported, metadata)

    def test_runtime_flag_contract_and_image_boundary(self) -> None:
        config = (ROOT / "trustfall" / "config.py").read_text()
        dockerignore = (ROOT / ".dockerignore").read_text()
        self.assertIn('flag=os.getenv("FLAG", "")', config)
        self.assertIn("solution", dockerignore)
        self.assertIn("writeup", dockerignore)
        self.assertIn("handout", dockerignore)
        contents = "\n".join(
            path.read_text(errors="ignore")
            for path in PACKAGE.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path != Path(__file__)
        )
        self.assertNotIn("H7" + "Tex{", contents)


if __name__ == "__main__":
    unittest.main()
