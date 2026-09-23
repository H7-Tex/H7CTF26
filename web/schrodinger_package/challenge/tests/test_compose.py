from pathlib import Path
import re

import yaml


def test_only_portal_is_published():
    compose_file = Path(__file__).parents[1] / "docker-compose.yml"
    compose = yaml.safe_load(compose_file.read_text(encoding="utf-8"))

    assert set(compose["services"]) == {"portal", "inspector", "runtime"}
    assert compose["services"]["portal"]["ports"] == ["8080:8080"]
    assert compose["services"]["portal"]["environment"]["FLAG"] == "${FLAG:-}"
    assert "./flag.txt:/run/secrets/challenge_flag:ro" in compose["services"]["portal"]["volumes"]
    assert "ports" not in compose["services"]["inspector"]
    assert "ports" not in compose["services"]["runtime"]
    assert compose["services"]["portal"]["build"] == "."
    assert compose["services"]["inspector"]["image"] == compose["services"]["portal"]["image"]
    assert compose["services"]["runtime"]["image"] == compose["services"]["portal"]["image"]
    assert compose["services"]["inspector"]["environment"]["ARTIFACT_DATA_DIR"] == "/var/lib/schrodinger"
    assert compose["services"]["runtime"]["environment"]["ARTIFACT_DATA_DIR"] == "/var/lib/schrodinger"
    assert "FLAG" not in compose["services"]["runtime"]["environment"]
    assert "./flag.txt:/run/secrets/challenge_flag:ro" not in compose["services"]["runtime"]["volumes"]
    assert compose["services"]["portal"]["networks"] == ["portal_edge", "portal_inspector", "portal_runtime"]
    assert compose["services"]["inspector"]["networks"] == ["portal_inspector"]
    assert compose["services"]["runtime"]["networks"] == ["portal_runtime"]
    assert compose["networks"]["portal_inspector"]["internal"] is True
    assert compose["networks"]["portal_runtime"]["internal"] is True
    assert compose["services"]["runtime"]["volumes"] == ["artifacts:/var/lib/schrodinger:ro"]
    assert compose["services"]["runtime"]["read_only"] is True
    assert compose["services"]["runtime"]["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in compose["services"]["runtime"]["security_opt"]
    assert compose["services"]["runtime"]["pids_limit"] <= 64
    assert compose["services"]["runtime"]["mem_limit"] == "768m"
    assert compose["services"]["runtime"]["cpus"] == 1.0
    assert "tmpfs" in compose["services"]["runtime"]


def test_phase_one_has_independent_parser_modules():
    challenge = Path(__file__).parents[1]
    assert (challenge / "schrodinger/inspector/parser.py").is_file()
    assert (challenge / "schrodinger/runtime/parser.py").is_file()
    assert not list((challenge / "schrodinger/shared").glob("*parser*"))


def test_runtime_docker_boundary_has_no_secret_inputs_and_documents_procfs():
    challenge = Path(__file__).parents[1]
    compose = yaml.safe_load((challenge / "docker-compose.yml").read_text(encoding="utf-8"))
    runtime = compose["services"]["runtime"]
    dockerfile = (challenge / "Dockerfile").read_text(encoding="utf-8").lower()
    isolation = (challenge / "ISOLATION.md").read_text(encoding="utf-8").lower()

    assert set(runtime["environment"]) == {"SCHRODINGER_ROLE", "ARTIFACT_DATA_DIR"}
    assert runtime["volumes"] == ["artifacts:/var/lib/schrodinger:ro"]
    assert "copy schrodinger ./schrodinger" in dockerfile
    assert "copy flag" not in dockerfile and "h7ctf{" not in dockerfile
    assert "attacker-controlled after package import" in isolation
    assert "popen(env=...)" in isolation
    assert "/proc" in isolation and "does not itself hide" in isolation
    assert "portal exclusively owns the real challenge flag" in isolation
    assert "release it only through the intentionally designed" in isolation
    assert "flag_triggered" not in (challenge / "schrodinger/runtime/app.py").read_text(encoding="utf-8")
    assert "SCHRODINGER_PACKAGE_RUNTIME_FLAG_REQUEST" not in (challenge / "schrodinger/runtime/parser.py").read_text(encoding="utf-8")


def test_image_build_context_excludes_secrets_and_pins_duplicate_member_behavior():
    challenge = Path(__file__).parents[1]
    dockerfile = (challenge / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (challenge / ".dockerignore").read_text(encoding="utf-8")
    base = next(line for line in dockerfile.splitlines() if line.startswith("FROM "))
    assert "python:3.12-slim@sha256:" in base
    assert len(base.rsplit("sha256:", 1)[1]) == 64
    assert "pip==25.0.1" in dockerfile
    assert "flag.txt" in dockerignore
    assert ".env" in dockerignore


def test_player_facing_files_contain_only_dummy_flags():
    root = Path(__file__).parents[2]
    pattern = re.compile(r"H7CTF\{[^}\r\n]+\}")
    for directory in ("handout", "solution", "writeup"):
        for path in (root / directory).rglob("*"):
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="ignore")
                assert all(match == "H7CTF{dummy}" for match in pattern.findall(content)), path
