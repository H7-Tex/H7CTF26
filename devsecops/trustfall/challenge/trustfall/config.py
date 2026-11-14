from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    role: str
    data_dir: Path
    instance_id: str
    internal_token: str
    scanner_url: str
    agents_url: str
    portal_url: str
    ollama_url: str
    ollama_model: str
    ollama_digest: str
    flag: str
    max_input_bytes: int
    max_tracked_files: int = 128
    max_path_bytes: int = 16384
    max_file_bytes: int = 65536

    @classmethod
    def load(cls, role: str) -> "Settings":
        internal_token = os.getenv("INTERNAL_TOKEN")
        if not internal_token or len(internal_token.strip()) < 32 or internal_token.strip() in {"test-token", "replace-with-a-long-random-token"}:
            raise ValueError("INTERNAL_TOKEN must be explicitly set to a non-placeholder value")
        return cls(
            role=role,
            data_dir=Path(os.getenv("DATA_DIR", "/tmp/trustfall")),
            instance_id=os.getenv("INSTANCE_ID", "test-instance"),
            internal_token=internal_token,
            scanner_url=os.getenv("SCANNER_URL", "http://scanner:8081"),
            agents_url=os.getenv("AGENTS_URL", "http://agents:8082"),
            portal_url=os.getenv("PORTAL_URL", "http://portal:8080"),
            ollama_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"),
            ollama_digest=os.getenv("OLLAMA_MODEL_DIGEST", "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"),
            flag=os.getenv("FLAG", ""),
            max_input_bytes=int(os.getenv("MAX_INPUT_BYTES", "262144")),
            max_tracked_files=int(os.getenv("MAX_TRACKED_FILES", "128")),
            max_path_bytes=int(os.getenv("MAX_PATH_BYTES", "16384")),
            max_file_bytes=int(os.getenv("MAX_FILE_BYTES", "65536")),
        )
