from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


REQUIRED_MODEL = "Qwen2.5-Coder-7B-Instruct"


@dataclass(frozen=True)
class QwenSettings:
    base_url: str = "https://qwen.h7tex.com"
    model: str = REQUIRED_MODEL

    @classmethod
    def from_env(cls) -> QwenSettings:
        base_url = os.getenv("QWEN_BASE_URL", "https://qwen.h7tex.com").strip().rstrip("/")
        model = os.getenv("QWEN_MODEL", REQUIRED_MODEL).strip()
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("QWEN_BASE_URL must be an http(s) URL without embedded credentials")
        local_endpoint = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if not model or (model != REQUIRED_MODEL and not local_endpoint):
            raise ValueError(f"QWEN_MODEL must be {REQUIRED_MODEL} outside local development")
        return cls(base_url=base_url, model=model)
