import os

import pytest


@pytest.fixture
def clean_argus_env(monkeypatch, tmp_path):
    """Start each configuration test without leaked ARGUS/Ollama settings."""

    for name in list(os.environ):
        if name.startswith(("ARGUS_", "OLLAMA_")) or name in {
            "FLAG",
            "ROLE",
            "INSTANCE_ID",
            "DATA_DIR",
            "STATE_DIR",
        }:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARGUS_ROLE", "portal")
    monkeypatch.setenv("INSTANCE_ID", "team-a")
    monkeypatch.setenv("ARGUS_STATE_DIR", str(tmp_path))
    return tmp_path
