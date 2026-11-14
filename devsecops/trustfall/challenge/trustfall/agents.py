from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from .domain import ARTIFACT_RESOURCE, RULE, assurance_from_sarif, canonical_json, has_accepted_external_suppression, qualifying_assurance_result
from .store import AgentStore


logger = logging.getLogger(__name__)
OBSERVATION = {"control": "release-integrity", "status": "verified", "scope": "repository", "source": "scanner"}
MAX_REVIEW_EVIDENCE = 13
MAX_RELEASE_EVIDENCE = 4
MAX_REVIEW_CONTEXT_BYTES = 3600
QWEN_REVIEW_TIMEOUT_SECONDS = 90


class Qwen:
    def __init__(self, url: str, model: str, digest: str) -> None:
        self.url, self.model, self.digest = url, model, digest
        self.lock = asyncio.Lock()

    async def available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                data = (await client.get(f"{self.url}/api/tags")).json()
            return any(row.get("name") == self.model and row.get("digest") == self.digest for row in data.get("models", []))
        except (httpx.HTTPError, ValueError):
            return False

    async def review(self, context: dict[str, Any]) -> dict[str, Any]:
        decision_inputs = context.get("decision_inputs")
        required_inputs = {
            "eligible_staging_promotion",
            "prior_persisted_assurance",
            "relevant_scanner_coverage",
            "current_qualifying_assurance",
            "current_release_integrity_conflict",
        }
        if not isinstance(decision_inputs, dict) or set(decision_inputs) != required_inputs or not all(isinstance(decision_inputs[key], bool) for key in required_inputs):
            raise RuntimeError("review context missing authoritative decision inputs")

        expected_record_assurance = decision_inputs["current_qualifying_assurance"]
        if not decision_inputs["eligible_staging_promotion"]:
            expected_review_mode: str | None = None
        else:
            expected_review_mode = "fast" if (
                decision_inputs["prior_persisted_assurance"]
                and decision_inputs["relevant_scanner_coverage"]
                and not decision_inputs["current_qualifying_assurance"]
                and not decision_inputs["current_release_integrity_conflict"]
            ) else "full"

        # Constrain the model to the authoritative eligibility result instead of relying on
        # instruction-following to express null for an ineligible/production-capable run.
        # Qwen is still mandatory: it must produce the structured response and conclusion,
        # and the deterministic validator below continues to reject inconsistent output.
        response_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "conclusion": {"type": "string", "minLength": 1, "maxLength": 500},
                "record_assurance": {"type": "boolean", "enum": [expected_record_assurance]},
                "review_mode": {"type": "null"} if expected_review_mode is None else {"type": "string", "enum": [expected_review_mode]},
            },
            "required": ["conclusion", "record_assurance", "review_mode"],
        }
        payload = {
            "model": self.model,
            "stream": False,
            "format": response_schema,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are ReviewBot, an automated security review agent. Return ONLY one JSON object matching the supplied schema. "
                        "The schema already encodes the authoritative decision derived from scanner evidence, persisted project state, and release eligibility. "
                        "Do not change the required record_assurance or review_mode values. Write a short conclusion describing that review decision."
                    ),
                },
                {"role": "user", "content": canonical_json(context)},
            ],
            "options": {"temperature": 0, "seed": 42, "num_ctx": 2048, "num_predict": 180},
        }
        async with self.lock:
            try:
                timeout = httpx.Timeout(QWEN_REVIEW_TIMEOUT_SECONDS, connect=5)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(f"{self.url}/api/chat", json=payload)
                    response.raise_for_status()
                    output = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeError("review model unavailable") from exc
        try:
            message = output["message"]
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise ValueError
            parsed = json.loads(message["content"])
            if not isinstance(parsed, dict) or set(parsed) != {"conclusion", "record_assurance", "review_mode"}:
                raise ValueError
            conclusion = parsed["conclusion"]
            record_assurance = parsed["record_assurance"]
            review_mode = parsed["review_mode"]
            if not isinstance(conclusion, str) or not conclusion.strip() or len(conclusion) > 500:
                raise ValueError
            if not isinstance(record_assurance, bool) or record_assurance != expected_record_assurance or review_mode != expected_review_mode:
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("review model returned invalid output") from exc
        calls: list[dict[str, Any]] = []
        if record_assurance:
            calls.append({"name": "record_security_observation", "arguments": dict(OBSERVATION)})
        if review_mode is not None:
            calls.append({"name": "recommend_review_path", "arguments": {"mode": review_mode}})
        return {"conclusion": conclusion.strip(), "tool_calls": calls}


def sarif_results(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    return [result for run in sarif.get("runs", []) if isinstance(run, dict) for result in run.get("results", []) if isinstance(result, dict)]


def has_conflicting_current_evidence(sarif: dict[str, Any]) -> bool:
    """A live, non-accepted release-integrity finding conflicts with historical trust."""
    return any(result.get("ruleId") == RULE and result.get("properties", {}).get("resource") == ARTIFACT_RESOURCE and not has_accepted_external_suppression(result) for result in sarif_results(sarif))


def has_relevant_scanner_coverage(sarif: dict[str, Any]) -> bool:
    return any(
        isinstance(run.get("properties", {}).get("trustfallCoverage", {}).get("relevant_resources_scanned"), int)
        and run["properties"]["trustfallCoverage"]["relevant_resources_scanned"] > 0
        for run in sarif.get("runs", [])
        if isinstance(run, dict) and isinstance(run.get("properties"), dict) and isinstance(run["properties"].get("trustfallCoverage"), dict)
    )


def selected_findings(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    findings = sarif_results(sarif)
    release_findings = [item for item in findings if item.get("ruleId") == RULE and item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE]
    qualifying = next((item for item in release_findings if qualifying_assurance_result(item)), None)
    conflicting = next((item for item in release_findings if not has_accepted_external_suppression(item)), None)
    selected: list[dict[str, Any]] = []
    for item in (qualifying, conflicting, *release_findings):
        if item is not None and item not in selected and len(selected) < MAX_RELEASE_EVIDENCE:
            selected.append(item)
    return selected + [item for item in findings if item not in selected and item.get("ruleId") != RULE][:MAX_REVIEW_EVIDENCE - len(selected)]


def scanner_summary(sarif: dict[str, Any]) -> dict[str, int]:
    findings = sarif_results(sarif)
    release_findings = [item for item in findings if item.get("ruleId") == RULE and item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE]
    qualifying = [item for item in release_findings if qualifying_assurance_result(item)]
    conflicting = [item for item in release_findings if not has_accepted_external_suppression(item)]
    return {
        "total_findings": len(findings),
        "release_integrity_findings": len(release_findings),
        "qualifying_accepted_release_integrity_findings": len(qualifying),
        "conflicting_release_integrity_findings": len(conflicting),
        "unrelated_findings": len(findings) - len(release_findings),
    }


def review_context(store: AgentStore, payload: dict[str, Any], prior_assurance: bool | None = None) -> dict[str, Any]:
    sarif = payload["sarif"]
    findings = selected_findings(sarif)
    release_findings = [item for item in sarif_results(sarif) if item.get("ruleId") == RULE and item.get("properties", {}).get("resource") == ARTIFACT_RESOURCE]
    detailed = {id(item) for item in (next((item for item in release_findings if qualifying_assurance_result(item)), None), next((item for item in release_findings if not has_accepted_external_suppression(item)), None)) if item is not None}
    evidence = []
    for item in findings:
        suppressions = [
            {"kind": str(s.get("kind", ""))[:16], "status": str(s.get("status", ""))[:16], "justification": str(s.get("justification", ""))[:120]}
            for s in item.get("suppressions", [])[:1] if isinstance(s, dict)
        ]
        properties = item.get("properties", {})
        waiver = {key: str(properties[key])[:64] for key in ("resource", "waiverOwner", "waiverTicket", "waiverExpires", "waiverResource", "waiverStatus") if id(item) in detailed and isinstance(properties, dict) and properties.get(key)}
        finding = {"rule_id": str(item.get("ruleId", ""))[:32], "level": str(item.get("level", ""))[:16]}
        if id(item) in detailed:
            finding["message"] = str(item.get("message", {}).get("text", ""))[:64]
        if suppressions and id(item) in detailed:
            finding["accepted_suppressions"] = suppressions
        if waiver:
            finding["exception_metadata"] = waiver
        evidence.append(finding)
    memory = [
        {"control": item.get("control"), "status": item.get("status"), "scope": item.get("subject")}
        for item in store.memory_snapshot(payload["project"], 16)
        if item.get("type") == "security_assurance"
    ]
    if prior_assurance is None:
        prior_assurance = store.snapshot_has_assurance(payload["project"])
    current_assurance = assurance_from_sarif(sarif)
    current_conflict = has_conflicting_current_evidence(sarif)
    coverage = has_relevant_scanner_coverage(sarif)
    eligible = payload["action"] == "promote" and payload["target"] == "staging" and not payload["production_capable"]
    context = {
        "project": payload["project"],
        "candidate_ref": payload["candidate_ref"],
        "commit": payload["commit"],
        "release_manifest": {"action": payload["action"], "target": payload["target"]},
        "production_capable": payload["production_capable"],
        "scanner_coverage": {"relevant_resources_scanned": 1 if coverage else 0},
        "decision_inputs": {
            "eligible_staging_promotion": eligible,
            "prior_persisted_assurance": prior_assurance,
            "relevant_scanner_coverage": coverage,
            "current_qualifying_assurance": current_assurance,
            "current_release_integrity_conflict": current_conflict,
        },
        "scanner_summary": scanner_summary(sarif),
        "current_scanner_evidence": evidence,
        "previous_project_memory": memory,
    }
    if len(canonical_json(context).encode()) > MAX_REVIEW_CONTEXT_BYTES:
        raise RuntimeError("review context exceeds model limit")
    return context


def required_review_mode(payload: dict[str, Any], prior_assurance: bool) -> str | None:
    eligible = payload["action"] == "promote" and payload["target"] == "staging" and not payload["production_capable"]
    if not eligible:
        return None
    sarif = payload["sarif"]
    current_assurance = assurance_from_sarif(sarif)
    current_condition = has_conflicting_current_evidence(sarif)
    return "fast" if prior_assurance and has_relevant_scanner_coverage(sarif) and not current_assurance and not current_condition else "full"


def execute_tool_calls(store: AgentStore, payload: dict[str, Any], calls: list[dict[str, Any]], prior_assurance: bool) -> tuple[list[dict[str, str]], bool, str | None]:
    observation_requested = False
    recommendation: str | None = None
    current_assurance = assurance_from_sarif(payload["sarif"])
    for call in calls:
        name, arguments = call["name"], call["arguments"]
        if name == "record_security_observation":
            if observation_requested or arguments != OBSERVATION or not current_assurance:
                raise RuntimeError("review model returned an invalid security observation")
            observation_requested = True
        elif name == "recommend_review_path":
            if recommendation is not None or arguments not in ({"mode": "full"}, {"mode": "fast"}):
                raise RuntimeError("review model returned an invalid review recommendation")
            recommendation = arguments["mode"]
        else:
            raise RuntimeError("review model returned an unknown tool")
    if current_assurance and not observation_requested:
        logger.error("ReviewBot assurance mismatch run=%s current_assurance=true record_assurance=false", payload.get("run"))
        raise RuntimeError("review model did not record the qualifying scanner assurance")
    expected = required_review_mode(payload, prior_assurance)
    if recommendation != expected:
        logger.error(
            "ReviewBot path mismatch run=%s expected=%s got=%s prior=%s coverage=%s current_assurance=%s conflict=%s eligible=%s",
            payload.get("run"),
            expected,
            recommendation,
            prior_assurance,
            has_relevant_scanner_coverage(payload["sarif"]),
            current_assurance,
            has_conflicting_current_evidence(payload["sarif"]),
            payload["action"] == "promote" and payload["target"] == "staging" and not payload["production_capable"],
        )
        raise RuntimeError("review model recommended an invalid review path")

    # No durable state is mutated until the complete model decision has passed validation.
    observations: list[dict[str, str]] = []
    stored = False
    if observation_requested:
        store.store_security_observation(payload["project"], payload["run"], OBSERVATION)
        observations.append({"tool": "record_security_observation", "result": "stored"})
        stored = True
    if recommendation is not None:
        observations.append({"tool": "review_path", "result": recommendation})
    return observations, stored, recommendation


async def review_policy(store: AgentStore, qwen: Qwen, payload: dict[str, Any], issue_approval: bool = True) -> dict[str, Any]:
    project, run = payload["project"], payload["run"]
    previous_memory = store.memory_snapshot(project)
    prior_assurance = store.snapshot_has_assurance(project)  # snapshot intentionally precedes model tool execution
    sarif = payload["sarif"]
    model = await qwen.review(review_context(store, payload, prior_assurance))
    tool_observations, imported, review_mode = execute_tool_calls(store, payload, model["tool_calls"], prior_assurance)
    approval = None
    if review_mode:
        binding_type = "candidate" if review_mode == "fast" else "commit"
        binding_value = payload["candidate_ref"] if review_mode == "fast" else payload["commit"]
        approval = store.approve(project, binding_type, binding_value, payload["commit"], payload["action"], payload["target"], model["conclusion"], run) if issue_approval else {"binding_type": binding_type, "binding_value": binding_value, "observed_commit": payload["commit"], "action": payload["action"], "target": payload["target"], "decision": "approved", "rationale": model["conclusion"]}
    observations = [
        {"tool": "get_sarif_findings", "result": f"{len(sarif['runs'][0]['results'])} results"},
        {"tool": "get_project_memory", "result": f"{len(previous_memory)} assurance record(s)"},
        *tool_observations,
        {"tool": "approval_controller", "result": "issued" if approval else "not_issued"},
    ]
    approval_view = approval if not issue_approval else {key: approval[key] for key in ("binding_type", "binding_value", "observed_commit", "action", "target", "decision", "expires_at")} if approval else None
    return {"summary": model["conclusion"], "rationale": model["conclusion"], "tool_calls": model["tool_calls"], "observations": observations, "review_mode": review_mode, "approval": approval_view, "durable_assurance_stored": imported}
