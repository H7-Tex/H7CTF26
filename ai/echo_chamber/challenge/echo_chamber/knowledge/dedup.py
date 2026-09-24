from __future__ import annotations

import re
import unicodedata


def normalize_content(content: str) -> str:
    normalized = unicodedata.normalize("NFKC", content).casefold()
    return " ".join(re.sub(r"[^\w]+", " ", normalized).split())
