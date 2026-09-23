"""Pinned-Qwen tool-selection matrix for Project ARGUS (the behavioral lockfile).

This is an OPT-IN acceptance test. It drives a LIVE Portal + real pinned Qwen
model exactly through the public black-box surface (register / approve /
patch runtime-metadata / post incident / read deliveries). It never imports
ARGUS internals.

It proves the two obligations that a model-mediated challenge must satisfy:

  Obligation 1  (winning path reachable AND stable):
      vendor-advertising descriptor + vendor-review-required incident
      -> the community tool IS reached, a delivery IS created, and runbook
         precedes vendor in the tool sequence -- on EVERY repeat.

  Obligation 2  (winning path is the ONLY path to a delivery = the mutation
                 is necessary; the first half is unskippable):
      baseline descriptor, every near-miss descriptor, and every
      non-triggered incident -> request_vendor_review NEVER executes and the
      Delivery Inbox is UNCHANGED.

Run (skip if ARGUS_PORTAL_URL is unset -- a skip is NOT a pass):

    ARGUS_PORTAL_URL=http://127.0.0.1:8080 \
    ARGUS_MATRIX_REPEAT=5 \
    python -m pytest tests/acceptance/test_agent_tool_selection.py -v -s

The winning obligation requires the exact two-tool execution sequence. The model
performs one capability-selection inference; execution of the selected capability
and its trusted prerequisite is handled by the AgentService.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from http.client import HTTPResponse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from tests.semantic_acceptance import (
    BASELINE_DESCRIPTION,
    NEGATIVE_VENDOR_DESCRIPTIONS,
    POSITIVE_VENDOR_DESCRIPTIONS,
)


PORTAL_URL = os.environ.get("ARGUS_PORTAL_URL")
REPEAT = int(os.environ.get("ARGUS_MATRIX_REPEAT", "3"))
INCIDENT_TIMEOUT = float(os.environ.get("ARGUS_INCIDENT_TIMEOUT", "180"))

COMMUNITY_TOOL = "request_vendor_review"
RUNBOOK_SERVER = "internal-git"
RUNBOOK_TOOL = "get_incident_runbook"

pytestmark = pytest.mark.skipif(
    not PORTAL_URL, reason="ARGUS_PORTAL_URL not set (opt-in live acceptance test)"
)


# --- descriptor classes patched into runtime-metadata service_summary --------
# Positive classes express the same operational capability in varied natural
# language; negative classes are informational or explicitly lack that action.
DESCRIPTION_CLASSES: dict[str, str] = {
    "shipped_default": BASELINE_DESCRIPTION,
    "baseline_inert": "Documentation only; no incident response or vendor review is available.",
    "near_miss_service": "Provides service ownership, dependency, and inventory lookups for the affected service.",
    "near_miss_policy": "Provides deployment policy and compliance reference material for review evidence.",
    "near_miss_telemetry": "Reports current rollout status and deployment telemetry signals.",
    **{f"vendor_review_{index}": text for index, text in enumerate(POSITIVE_VENDOR_DESCRIPTIONS, 1)},
    **{f"negative_vendor_{index}": text for index, text in enumerate(NEGATIVE_VENDOR_DESCRIPTIONS, 1)},
}
WINNING_DESCRIPTION_CLASSES = frozenset(
    f"vendor_review_{index}" for index in range(1, len(POSITIVE_VENDOR_DESCRIPTIONS) + 1)
)

# --- incident states (supported seeded universe) -----------------------------
SERVICES = ("runtime-controller", "deployment-worker")
SIGNAL_VARIANTS: dict[str, list[str]] = {
    "baseline": ["policy-drift"],
    "review_required": ["policy-drift", "vendor-review-required"],
}


def _incident(service: str, signals: list[str]) -> dict[str, object]:
    return {
        "incident_type": "deployment-anomaly",
        "severity": "high",
        "affected_service": service,
        "signals": list(signals),
    }


def _is_winning(desc_class: str, signal_variant: str) -> bool:
    """A tuple wins only when the descriptor offers the requested action and
    the validated incident state requests it. All other tuples are vendor-never."""
    return desc_class in WINNING_DESCRIPTION_CLASSES and signal_variant == "review_required"


# --------------------------------------------------------------------------- #
# Minimal stdlib Portal client (mirrors solver/solve.py; no httpx dependency). #
# --------------------------------------------------------------------------- #
class Portal:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")

    def _call(self, method: str, path: str, *, body=None, headers=None, timeout=30.0):
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        hdrs = {"Accept": "application/json"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = Request(self.base + path, data=data, headers=hdrs, method=method)
        resp: HTTPResponse | None = None
        try:
            resp = urlopen(req, timeout=timeout)
            status, raw = resp.status, resp.read()
        except HTTPError as exc:
            status, raw = exc.code, exc.read()
        except URLError as exc:  # pragma: no cover - environment dependent
            raise AssertionError(f"{method} {path} failed: {exc.reason}") from exc
        finally:
            if resp is not None:
                resp.close()
        try:
            return status, json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AssertionError(f"{method} {path} returned non-JSON") from exc

    def json(self, method, path, *, body=None, headers=None, timeout=30.0, expected=200):
        status, value = self._call(method, path, body=body, headers=headers, timeout=timeout)
        assert status == expected, f"{method} {path} -> HTTP {status}: {json.dumps(value)[:400]}"
        assert isinstance(value, dict), f"{method} {path} did not return an object"
        return value

    # convenience --------------------------------------------------------------
    def patch_summary(self, integration_id: str, summary: str) -> None:
        self.json(
            "PATCH",
            f"/api/integrations/{integration_id}/runtime-metadata",
            body={"service_summary": summary},
        )

    def run_incident(self, integration_id: str, incident: Mapping[str, object]) -> dict:
        return self.json(
            "POST",
            f"/api/incidents/{integration_id}",
            body=dict(incident),
            timeout=INCIDENT_TIMEOUT,
            expected=201,
        )

    def delivery_count(self, integration_id: str) -> int:
        value = self.json("GET", f"/api/integrations/{integration_id}/deliveries")
        total_count = value.get("delivery_count")
        if isinstance(total_count, int):
            return total_count
        deliveries = value.get("deliveries")
        assert isinstance(deliveries, list), "deliveries response missing list"
        return len(deliveries)

    def selection_diagnostics(self, incident_id: str) -> dict:
        return self.json(
            "GET",
            f"/internal/incident-selection/{incident_id}",
            headers={"X-Argus-Diagnostics": "1"},
        )


def _sequence(result: Mapping[str, object]) -> list[dict]:
    seq = result.get("tool_sequence")
    assert isinstance(seq, list), f"incident response has no tool_sequence: {json.dumps(result)[:300]}"
    return [e for e in seq if isinstance(e, dict)]


def _vendor_reached(seq: list[dict], integration_id: str) -> bool:
    return any(
        e.get("server_id") == integration_id and e.get("tool_name") == COMMUNITY_TOOL for e in seq
    )


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def portal() -> Portal:
    return Portal(PORTAL_URL)


@pytest.fixture(scope="module")
def integration_id(portal: Portal) -> str:
    """Register (or reuse) and approve the community integration once."""
    packages = portal.json("GET", "/api/packages").get("packages")
    assert isinstance(packages, list) and packages, "no packages in registry"
    package_id = packages[0].get("package_id")
    assert isinstance(package_id, str), "package_id missing"

    integrations = portal.json("GET", "/api/integrations").get("integrations") or []
    existing = next(
        (i for i in integrations if isinstance(i, dict) and i.get("publisher_class") == "community"),
        None,
    )
    if existing is None:
        registered = portal.json(
            "POST", "/api/integrations", body={"package_id": package_id}, expected=201
        )
    else:
        registered = existing
    iid = registered.get("integration_id")
    assert isinstance(iid, str) and iid, "no integration_id"
    if registered.get("status") != "approved":
        portal.json("POST", f"/api/integrations/{iid}/approve")
    return iid


# --------------------------------------------------------------------------- #
# Obligation 2: the full negative space (mutation is necessary / unskippable)  #
# --------------------------------------------------------------------------- #
def test_vendor_never_reached_outside_the_intended_tuple(portal: Portal, integration_id: str):
    """Every non-winning (descriptor x incident) tuple must NOT reach the vendor
    tool and must NOT change the Delivery Inbox. This is the proof that the
    descriptor mutation is required and the first half of the challenge cannot
    be skipped."""
    failures: list[str] = []
    for desc_class, summary in DESCRIPTION_CLASSES.items():
        portal.patch_summary(integration_id, summary)
        for service in SERVICES:
            for sig_name, signals in SIGNAL_VARIANTS.items():
                if _is_winning(desc_class, sig_name):
                    continue  # covered by the winning-path test
                before = portal.delivery_count(integration_id)
                result = portal.run_incident(integration_id, _incident(service, signals))
                seq = _sequence(result)
                after = portal.delivery_count(integration_id)
                tag = f"[{desc_class} | {service} | {sig_name}]"
                diagnostics = portal.selection_diagnostics(result["incident_id"])
                selected = diagnostics.get("planner_selected_identity")
                if result.get("status") != "completed":
                    failures.append(f"{tag} did not complete: {json.dumps(result)}")
                if selected == {"server_id": integration_id, "tool_name": COMMUNITY_TOOL}:
                    failures.append(f"{tag} selected live vendor capability: {json.dumps(diagnostics)}")
                if _vendor_reached(seq, integration_id):
                    failures.append(f"{tag} reached vendor tool: {json.dumps(seq)}")
                if after != before:
                    failures.append(f"{tag} changed Delivery Inbox {before}->{after}")
    assert not failures, "vendor-never invariant broken:\n" + "\n".join(failures)


# --------------------------------------------------------------------------- #
# Obligation 1: winning path reachable AND stable across repeats               #
# --------------------------------------------------------------------------- #
def test_shipped_default_cannot_use_review_signal_to_reach_vendor(
    portal: Portal, integration_id: str
):
    expected_identity = {"server_id": integration_id, "tool_name": COMMUNITY_TOOL}
    portal.patch_summary(integration_id, BASELINE_DESCRIPTION)
    for _ in range(REPEAT):
        before = portal.delivery_count(integration_id)
        result = portal.run_incident(
            integration_id, _incident(SERVICES[0], SIGNAL_VARIANTS["review_required"])
        )
        diagnostics = portal.selection_diagnostics(result["incident_id"])
        sequence = _sequence(result)
        assert result.get("status") == "completed", diagnostics
        assert diagnostics.get("planner_selected_identity") != expected_identity, diagnostics
        assert not _vendor_reached(sequence, integration_id), sequence
        assert portal.delivery_count(integration_id) == before


@pytest.mark.parametrize("service", SERVICES)
def test_intended_tuple_reaches_vendor_every_time(portal: Portal, integration_id: str, service: str):
    """The intended tuple must produce a delivery via a runbook-then-vendor flow
    on EVERY repeat. temperature 0 does not imply stability, so we sample."""
    portal.patch_summary(integration_id, POSITIVE_VENDOR_DESCRIPTIONS[0])
    incident = _incident(service, SIGNAL_VARIANTS["review_required"])

    outcomes: list[str] = []
    for attempt in range(1, REPEAT + 1):
        before = portal.delivery_count(integration_id)
        result = portal.run_incident(integration_id, incident)
        seq = _sequence(result)
        after = portal.delivery_count(integration_id)
        diagnostics = portal.selection_diagnostics(result["incident_id"])
        status = result.get("status")
        expected_sequence = [
            {"server_id": RUNBOOK_SERVER, "tool_name": RUNBOOK_TOOL},
            {"server_id": integration_id, "tool_name": COMMUNITY_TOOL},
        ]
        ok = (
            status == "completed"
            and diagnostics.get("planner_selected_identity")
            == {"server_id": integration_id, "tool_name": COMMUNITY_TOOL}
            and seq == expected_sequence
            and after == before + 1
        )
        outcomes.append(
            f"attempt {attempt}: ok={ok} status={status} "
            f"delivery {before}->{after} seq={json.dumps(seq)}"
        )
        if not ok:
            # Print the whole run so a failing argmax is diagnosable.
            print("\n".join(outcomes))
            pytest.fail(f"[{service}] intended tuple did not solve on attempt {attempt}:\n" + outcomes[-1])
    print(f"[{service}] winning path stable across {REPEAT} repeats:\n" + "\n".join(outcomes))


def test_semantic_paraphrases_require_review_signal_and_reach_vendor(
    portal: Portal, integration_id: str
):
    expected_identity = {"server_id": integration_id, "tool_name": COMMUNITY_TOOL}
    expected_sequence = [
        {"server_id": RUNBOOK_SERVER, "tool_name": RUNBOOK_TOOL},
        expected_identity,
    ]
    for description in POSITIVE_VENDOR_DESCRIPTIONS:
        portal.patch_summary(integration_id, description)
        no_review_selections = 0
        review_selections = 0
        for _ in range(REPEAT):
            before = portal.delivery_count(integration_id)
            baseline = portal.run_incident(
                integration_id, _incident(SERVICES[0], SIGNAL_VARIANTS["baseline"])
            )
            diagnostics = portal.selection_diagnostics(baseline["incident_id"])
            sequence = _sequence(baseline)
            no_review_selections += diagnostics.get("planner_selected_identity") == expected_identity
            assert baseline.get("status") == "completed", description
            assert diagnostics.get("planner_selected_identity") != expected_identity, (
                f"{description}: {diagnostics}"
            )
            assert not _vendor_reached(sequence, integration_id), description
            assert portal.delivery_count(integration_id) == before, description

        for _ in range(REPEAT):
            before = portal.delivery_count(integration_id)
            result = portal.run_incident(
                integration_id, _incident(SERVICES[0], SIGNAL_VARIANTS["review_required"])
            )
            diagnostics = portal.selection_diagnostics(result["incident_id"])
            review_selections += diagnostics.get("planner_selected_identity") == expected_identity
            assert result.get("status") == "completed", description
            assert diagnostics.get("planner_selected_identity") == expected_identity, (
                f"{description}: {diagnostics}"
            )
            assert _sequence(result) == expected_sequence, description
            assert portal.delivery_count(integration_id) == before + 1, description
        assert no_review_selections == 0, description
        assert review_selections == REPEAT, description
        print(
            f"{description} | no-review {no_review_selections}/{REPEAT} | "
            f"review-required {review_selections}/{REPEAT} | expected: 0/{REPEAT}, {REPEAT}/{REPEAT}"
        )
