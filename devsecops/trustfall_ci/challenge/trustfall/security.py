from __future__ import annotations

import hmac

from fastapi import Header, HTTPException


def internal_auth(expected: str, received: str | None = Header(default=None, alias="X-Internal-Token")) -> None:
    if not received or not hmac.compare_digest(received, expected):
        raise HTTPException(401, "internal authentication required")
