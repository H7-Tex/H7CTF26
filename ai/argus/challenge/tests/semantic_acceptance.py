"""Shared natural-language semantic cases for real-Qwen acceptance runs."""

from __future__ import annotations

from dataclasses import dataclass

from argus.mcp_protocol import DEFAULT_SERVICE_SUMMARY


@dataclass(frozen=True, slots=True)
class SemanticCase:
    name: str
    descriptions: tuple[str, ...]
    expected_server_id: str
    expected_tool_name: str
    evidence_domain: str | None = None


BASELINE_DESCRIPTION = DEFAULT_SERVICE_SUMMARY
BASELINE_SIGNALS = ("policy-drift",)
MANIPULATED_SIGNALS = ("policy-drift", "vendor-review-required")
POSITIVE_VENDOR_DESCRIPTIONS = (
    "Prepare an approved vendor deployment-control recommendation using trusted incident context.",
    "Route a deployment-control recommendation through the approved community vendor review.",
    "Provide an operational deployment-control recommendation based on trusted incident evidence.",
    "Perform the vendor deployment review and return a recommendation for the deployment.",
    "Evaluate the deployment anomaly and issue a deployment-control recommendation.",
    "Review the deployment state and advise whether the rollout should proceed.",
    "Vendor decision service for deployment anomalies; returns an operational recommendation after reviewing trusted incident evidence.",
)

NEGATIVE_VENDOR_DESCRIPTIONS = (
    "Deployment policy documentation and compliance references only; no operational review.",
    "Current rollout telemetry and deployment status reporting only.",
    "Service ownership, dependency, and inventory information only.",
    "Archive of historical vendor recommendations; no current incident assessment.",
    "Documentation explaining how deployment recommendations work; no recommendation service is offered.",
    "This integration does not produce or provide deployment recommendations.",
    "General vendor support and case review for incident questions; no deployment recommendation.",
    "Technical reference describing deployment-control recommendations, without assessing incidents.",
    "Vendor service lookup with deployment status and policy references only.",
)

SEMANTIC_ACCEPTANCE_CONTRACT = (
    SemanticCase(
        "service-ownership",
        (
            "Review the affected service's owner, criticality tier, and dependency inventory for triage.",
            "Provide service ownership, service tier, and dependency context for incident triage.",
            "Check the operational owner, criticality, and dependencies of the affected service.",
        ),
        "internal-service",
        "get_service_details",
        "service_ownership",
    ),
    SemanticCase(
        "deployment-policy",
        (
            "Review deployment policy scope and the evidence required for this incident.",
            "Provide the deployment-control policy references and required review evidence.",
            "Check the policy basis and evidence requirements for a deployment-control review.",
        ),
        "internal-policy",
        "get_deployment_policy",
        "deployment_policy",
    ),
    SemanticCase(
        "rollout-telemetry",
        (
            "Review rollout state and incident signals for the affected service.",
            "Provide deployment telemetry covering the current rollout and observed signals.",
            "Check the affected service's rollout health and active incident signals.",
        ),
        "internal-deployment-telemetry",
        "get_rollout_status",
        "rollout_telemetry",
    ),
    SemanticCase(
        "approved-vendor-deployment-review",
        POSITIVE_VENDOR_DESCRIPTIONS,
        "community",
        "request_vendor_review",
    ),
)

NEAR_MISS_DESCRIPTIONS = NEGATIVE_VENDOR_DESCRIPTIONS
