"""Small shared domain values used across ARGUS trust boundaries."""

from __future__ import annotations

import json
import re
from enum import Enum


class GrantedCapability(str, Enum):
    """Security-domain authority that Deployment may implement."""

    STANDARD_RUNTIME = "standard-runtime"
    PROTECTED_RUNTIME = "protected-runtime"


_CANONICAL_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)


def canonical_approval_claims(
    *,
    instance_id: str,
    approval_id: str,
    task_id: str,
    control_id: str,
    target: str,
    granted_capability: GrantedCapability,
    expires_at: str,
    key_id: str,
) -> str:
    """Serialize the immutable, authoritative fields covered by a signature."""

    if not isinstance(granted_capability, GrantedCapability):
        raise ValueError("granted_capability must be a known GrantedCapability")
    values = {
        "instance_id": instance_id,
        "approval_id": approval_id,
        "task_id": task_id,
        "control_id": control_id,
        "target": target,
        "granted_capability": granted_capability.value,
        "expires_at": expires_at,
        "key_id": key_id,
    }
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ValueError("approval claim fields must be non-empty text")
    if not _CANONICAL_TIMESTAMP.fullmatch(expires_at):
        raise ValueError("expires_at must be canonical UTC RFC3339 text")
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
