from __future__ import annotations

import json
import os
import sys

from fastapi.testclient import TestClient

from echo_chamber.main import create_app


RELATIONS = {"supports", "contradicts", "mentions", "irrelevant"}


class RecordingQwen:
    def __init__(self, client) -> None:
        self.client = client
        self.calls: list[str] = []
        self.errors: list[str] = []

    async def complete(self, task: str, system: str, user: str):
        self.calls.append(task)
        try:
            return await self.client.complete(task, system, user)
        except Exception as exc:
            chain = []
            current = exc
            while current is not None:
                chain.append(f"{type(current).__name__}: {current}")
                current = current.__cause__
            self.errors.append(" <- ".join(chain))
            raise


def print_result(label: str, result: dict[str, object]) -> None:
    print(json.dumps({"smoke": label, **result}, ensure_ascii=False), flush=True)


def has_invalid_citations(citations: object) -> bool:
    return not isinstance(citations, list) or any(
        not isinstance(row, dict) or row.get("relation") not in RELATIONS
        for row in citations
    )


def semantic_observations(baseline: dict[str, object], intended: dict[str, object]) -> dict[str, object]:
    baseline_status = baseline.get("status")
    baseline_supports = baseline.get("supporting_evidence_ids", [])
    intended_status = intended.get("status")
    return {
        "seeded_baseline_status": baseline_status,
        "seeded_baseline_false_corroboration": baseline_status in {"probable", "corroborated"},
        "seeded_baseline_unexpected_supporting_evidence_ids": baseline_supports,
        "seeded_baseline_citations": baseline.get("citations", []),
        "vendor_bulletin_status": intended_status,
        "vendor_bulletin_failed_to_corroborate": (
            intended_status is not None and intended_status != "corroborated"
        ),
        "vendor_bulletin_supporting_evidence_ids": intended.get("supporting_evidence_ids", []),
        "vendor_bulletin_citations": intended.get("citations", []),
    }


def smoke_summary(
    integration_failures: list[str],
    observations: dict[str, object],
    model: str | None,
) -> dict[str, object]:
    integration_passed = not integration_failures
    conclusion = (
        "Local integration smoke passed; local semantic classification is diagnostic only. "
        "Deployment-model semantic matrix remains pending."
        if integration_passed else
        "Local integration smoke failed; local semantic classification is diagnostic only. "
        "Deployment-model semantic matrix remains pending."
    )
    return {
        "integration_passed": integration_passed,
        "integration_failures": integration_failures,
        "semantic_observations": observations,
        "model": model,
        "conclusion": conclusion,
    }


def main() -> int:
    app = create_app(":memory:")
    recorder = RecordingQwen(app.state.qwen)
    app.state.qwen = recorder
    integration_failures = []
    baseline: dict[str, object] = {}
    intended: dict[str, object] = {}
    with TestClient(app) as client:
        recorder.calls.clear()
        recorder.errors.clear()
        baseline_response = client.post("/api/incidents/INC-7421/analyze")
        baseline: dict[str, object] = {"http_status": baseline_response.status_code}
        if baseline_response.status_code == 200:
            body = baseline_response.json()
            citations = body.get("citations", [])
            baseline.update({
                "status": body.get("status"),
                "retrieved_artifact_ids": [item["evidence_id"] for item in body.get("candidates", [])],
                "citations": citations,
                "supporting_evidence_ids": body.get("supporting_evidence_ids", []),
                "qwen_tasks": list(recorder.calls),
                "qwen_errors": list(recorder.errors),
            })
            if has_invalid_citations(citations):
                integration_failures.append("seeded baseline returned invalid citation relations")
            if recorder.errors:
                integration_failures.append("seeded baseline Qwen request failed")
        else:
            baseline.update({
                "error": baseline_response.text,
                "qwen_tasks": list(recorder.calls),
                "qwen_errors": list(recorder.errors),
            })
            integration_failures.append(f"seeded baseline returned HTTP {baseline_response.status_code}")
        print_result("seeded_baseline", baseline)

        recorder.calls.clear()
        recorder.errors.clear()
        content = (
            "A vendor advisory for StreamForge 4.8 documents a defect in the worker-runtime allocator. "
            "The vendor reproduced worker exits under the supported workload and recorded corrupted heap "
            "metadata immediately before each exit. The advisory identifies allocator reuse of freed blocks "
            "as the failure mechanism and reports that the defect is corrected in version 4.8.2."
        )
        submission_response = client.post("/api/research/submissions", json={
            "product": "StreamForge", "version": "4.8", "title": "Vendor defect advisory", "content": content,
        })
        intended["submission_http_status"] = submission_response.status_code
        if submission_response.status_code == 201:
            submission = submission_response.json()
            artifacts = client.get(
                f"/api/research/submissions/{submission['submission_id']}/artifacts"
            )
            artifact_rows = artifacts.json() if artifacts.status_code == 200 else []
            intended.update({
                "submission_id": submission["submission_id"],
                "artifact_ids": submission.get("artifacts", []),
                "artifacts": [{
                    "evidence_id": item["evidence_id"],
                    "representation_type": item["representation_type"],
                    "origin_id": item["origin_id"],
                } for item in artifact_rows],
                "transform_qwen_tasks": list(recorder.calls),
                "transform_qwen_errors": list(recorder.errors),
            })
            expected_types = {"technical_summary", "symptom_profile", "diagnostic_assessment"}
            artifact_ids = {item["evidence_id"] for item in artifact_rows}
            expected_origin_ids = {submission["submission_id"]}
            if artifacts.status_code != 200 or len(artifact_rows) != 3:
                integration_failures.append("vendor report did not produce three readable artifacts")
            elif {item["representation_type"] for item in artifact_rows} != expected_types:
                integration_failures.append("vendor report produced unexpected representations")
            elif len(submission.get("artifacts", [])) != 3 or set(submission["artifacts"]) != artifact_ids:
                integration_failures.append("submission artifact IDs did not match the three stored records")
            elif {item["origin_id"] for item in artifact_rows} != expected_origin_ids:
                integration_failures.append("derived artifacts did not retain the submission origin")
            if recorder.errors:
                integration_failures.append("vendor report transformation Qwen request failed")

            recorder.errors.clear()
            analysis_response = client.post("/api/incidents/INC-7421/analyze")
            intended["analysis_http_status"] = analysis_response.status_code
            intended["analysis_qwen_tasks"] = list(recorder.calls[3:])
            intended["analysis_qwen_errors"] = list(recorder.errors)
            if analysis_response.status_code == 200:
                body = analysis_response.json()
                citations = body.get("citations", [])
                intended.update({
                    "retrieved_artifact_ids": [item["evidence_id"] for item in body.get("candidates", [])],
                    "citations": citations,
                    "supporting_evidence_ids": body.get("supporting_evidence_ids", []),
                    "status": body.get("status"),
                })
                if has_invalid_citations(citations):
                    integration_failures.append("vendor report analysis returned invalid citation relations")
                if recorder.errors:
                    integration_failures.append("vendor report analysis Qwen request failed")
            else:
                intended["analysis_error"] = analysis_response.text
                integration_failures.append(f"vendor report analysis returned HTTP {analysis_response.status_code}")
        else:
            intended.update({
                "submission_error": submission_response.text,
                "transform_qwen_tasks": list(recorder.calls),
                "transform_qwen_errors": list(recorder.errors),
            })
            integration_failures.append(f"vendor report submission returned HTTP {submission_response.status_code}")
        print_result("vendor_bulletin", intended)

    summary = smoke_summary(integration_failures, semantic_observations(baseline, intended), os.getenv("QWEN_MODEL"))
    print_result("summary", summary)
    print(summary["conclusion"], flush=True)
    return 0 if summary["integration_passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print_result("summary", smoke_summary(
            [f"smoke runner raised {type(exc).__name__}: {exc}"],
            {},
            os.getenv("QWEN_MODEL"),
        ))
        raise SystemExit(1) from exc
