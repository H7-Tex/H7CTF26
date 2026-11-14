#!/usr/bin/env python3
"""Solve Echo Chamber through its public research and incident APIs."""

import argparse
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPORT = (
    "A field investigation of StreamForge 4.8 worker-runtime instances recorded "
    "unexpected process exits during normal task execution. The same hosts ran "
    "StreamForge 4.7 without these exits. Core inspection after the 4.8 exits "
    "showed inconsistent heap allocator metadata and damaged free-list links. "
    "The timestamps align with worker-runtime memory reuse activity. Host memory "
    "remained below its limit, kernel logs contain no OOM event, orchestrator "
    "records show no eviction, and queue depth was normal. Reproducing the "
    "workload on 4.7 did not produce heap damage. These are observed results "
    "from the affected StreamForge 4.8 worker-runtime, not a remediation proposal."
)


def api(base: str, path: str, body: dict | None = None) -> object:
    data = None if body is None else json.dumps(body).encode()
    request = Request(base.rstrip("/") + path, data=data,
                      headers={"Content-Type": "application/json"} if data else {})
    try:
        with urlopen(request, timeout=300) as response:
            return json.load(response)
    except (HTTPError, URLError) as exc:
        detail = exc.read().decode(errors="replace") if isinstance(exc, HTTPError) else str(exc)
        raise RuntimeError(f"{path}: {detail}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("BASE_URL", "http://127.0.0.1:8000"), help="challenge base URL")
    parser.add_argument("--incident", default="INC-7421", help="incident ID")
    parser.add_argument("--submission-id", help="reuse an earlier submission instead of creating one")
    parser.add_argument("--attempts", type=int, default=10, help="analysis attempts (1-20; default: 10)")
    args = parser.parse_args()
    if not 1 <= args.attempts <= 20:
        parser.error("--attempts must be between 1 and 20")

    try:
        incident = api(args.url, f"/api/incidents/{args.incident}")
        if args.submission_id:
            submission_id = args.submission_id
        else:
            title = "Field investigation of worker runtime exits"
            submission = api(args.url, "/api/research/submissions", {
                "product": incident["product"], "version": incident["version"],
                "title": title, "content": REPORT,
            })
            submission_id = submission["submission_id"]

        artifacts = api(args.url, f"/api/research/submissions/{submission_id}/artifacts")
        print(json.dumps({"submission_id": submission_id, "artifacts": [
            {"evidence_id": item["evidence_id"], "origin_id": item["origin_id"],
             "representation_type": item["representation_type"]} for item in artifacts
        ]}, indent=2))
        if len(artifacts) != 3 or len({item["origin_id"] for item in artifacts}) != 1:
            raise RuntimeError("submission did not produce three artifacts sharing one origin")

        for attempt in range(1, args.attempts + 1):
            result = api(args.url, f"/api/incidents/{args.incident}/analyze", {})
            print(json.dumps({"attempt": attempt, "status": result.get("status"),
                              "incident_status": result.get("incident_corroboration_status"),
                              "supporting_evidence_ids": result.get("supporting_evidence_ids", []),
                              "citations": result.get("citations", [])}, indent=2))
            report_id = result.get("report_id")
            if result.get("incident_corroboration_status") == "corroborated" and report_id:
                report = api(args.url, f"/api/reports/{report_id}")
                print(json.dumps({"report_id": report_id, "diagnostic_depth": report["diagnostic_depth"],
                                  "artifacts": report["artifacts"]}, indent=2))
                return 0
            if attempt < args.attempts:
                time.sleep(1.1)
        print(f"Not corroborated after {args.attempts} attempts. Re-run with --submission-id {submission_id}.",
              file=sys.stderr)
        return 2
    except (RuntimeError, KeyError, TypeError, ValueError) as exc:
        print(f"Solver failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
