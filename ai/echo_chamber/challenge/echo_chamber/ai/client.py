from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from .config import QwenSettings
from .parsers import StrictModel, parse_output
from .profiles import INFERENCE_PROFILES


class QwenServiceError(RuntimeError):
    """The upstream inference service could not complete the request."""


class QwenTimeoutError(QwenServiceError):
    """The upstream inference request timed out."""


class QwenOutputError(RuntimeError):
    """The model returned output that cannot be used by the application."""


class QwenClient:
    MAX_CONCURRENT_INFERENCE = 2

    def __init__(self, settings: QwenSettings | None = None, *, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings or QwenSettings.from_env()
        timeout = float(os.getenv("QWEN_TIMEOUT_SECONDS", "60"))
        self._client = client or httpx.AsyncClient(base_url=self.settings.base_url, timeout=timeout)
        self._owns_client = client is None
        self._inference_slots = asyncio.Semaphore(self.MAX_CONCURRENT_INFERENCE)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def complete(self, task: str, system: str, user: str) -> StrictModel:
        profile = INFERENCE_PROFILES.get(task)
        if profile is None:
            raise ValueError("unknown inference task")
        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": profile.temperature,
            "top_p": profile.top_p,
            "max_tokens": profile.max_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            async with self._inference_slots:
                response = await self._client.post("/v1/chat/completions", json=body)
        except httpx.TimeoutException as exc:
            raise QwenTimeoutError("Qwen inference timed out") from exc
        except httpx.TransportError as exc:
            raise QwenServiceError("Qwen inference service is unavailable") from exc
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise QwenServiceError("Qwen inference service returned an error") from exc
        try:
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("response content is not text")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise QwenOutputError("Qwen returned unusable output") from exc
        try:
            return parse_output(task, content)
        except ValueError as exc:
            raise QwenOutputError("Qwen returned schema-invalid output") from exc
