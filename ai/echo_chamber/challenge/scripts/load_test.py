#!/usr/bin/env python3
"""Post-deployment API load probe; use one URL per isolated team instance."""

import argparse
import concurrent.futures
import json
import statistics
import sys
import threading
import time
from collections import Counter, defaultdict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPORT = (
    "A field test of StreamForge 4.8 worker-runtime recorded unexpected process exits during ordinary "
    "jobs. Preserved core files showed inconsistent heap allocator metadata after the upgrade. Host memory "
    "remained below its limit, kernel logs had no OOM event, and the orchestrator recorded no eviction. "
    "The same workload on 4.7 did not produce heap damage."
)
lock = threading.Lock()
metrics: dict[str, object] = {
    "latencies": defaultdict(list), "statuses": defaultdict(Counter),
    "timeouts": 0, "malformed_output": 0, "application_5xx": 0,
    "active_team_requests": 0, "peak_team_requests": 0,
    "estimated_peak_qwen_requests": 0,
}


def request(base: str, path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object, float]:
    data = json.dumps(body).encode() if body is not None else (b"" if method != "GET" else None)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    started = time.perf_counter()
    try:
        with urlopen(Request(base.rstrip("/") + path, data=data, headers=headers, method=method),
                     timeout=300) as response:
            return response.status, json.load(response), time.perf_counter() - started
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except (ValueError, OSError):
            payload = {}
        return exc.code, payload, time.perf_counter() - started
    except (TimeoutError, URLError) as exc:
        timed_out = isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
        return (504 if timed_out else 599), {"error": str(exc)}, time.perf_counter() - started


def record(kind: str, status: int, elapsed: float) -> None:
    with lock:
        metrics["latencies"][kind].append(elapsed)
        metrics["statuses"][kind][str(status)] += 1
        if status == 504:
            metrics["timeouts"] += 1
        if status == 502:
            metrics["malformed_output"] += 1
        if 500 <= status <= 599:
            metrics["application_5xx"] += 1


def team(base: str, incident_id: str, iterations: int, total_instances: int) -> None:
    for _ in range(iterations):
        with lock:
            metrics["active_team_requests"] += 1
            metrics["peak_team_requests"] = max(metrics["peak_team_requests"], metrics["active_team_requests"])
            # Each instance's inference semaphore allows at most two simultaneous upstream requests.
            metrics["estimated_peak_qwen_requests"] = max(
                metrics["estimated_peak_qwen_requests"],
                2 * min(metrics["active_team_requests"], total_instances),
            )
        try:
            status, incident, elapsed = request(base, f"/api/incidents/{incident_id}")
            record("incident", status, elapsed)
            if status != 200:
                continue
            submission = {
                "product": incident["product"], "version": incident["version"],
                "title": "Load probe: worker runtime field report", "content": REPORT,
            }
            status, result, elapsed = request(base, "/api/research/submissions", "POST", submission)
            record("submission", status, elapsed)
            if status != 201:
                continue
            status, _, elapsed = request(base, f"/api/incidents/{incident_id}/analyze", "POST")
            record("analysis", status, elapsed)
        finally:
            with lock:
                metrics["active_team_requests"] -= 1


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))] * 1000, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urls", nargs="+", required=True, help="one base URL for each isolated instance")
    parser.add_argument("--incident", default="INC-7421")
    parser.add_argument("--iterations", type=int, default=1, help="submission+analysis cycles per instance")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.urls)) as pool:
        futures = [pool.submit(team, base, args.incident, args.iterations, len(args.urls)) for base in args.urls]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f"Load worker failed: {exc}", file=sys.stderr)

    latencies = metrics["latencies"]
    total = sum(sum(counts.values()) for counts in metrics["statuses"].values())
    submission_requests = sum(metrics["statuses"].get("submission", {}).values())
    analysis_requests = sum(metrics["statuses"].get("analysis", {}).values())
    qwen_call_estimate = submission_requests * 3 + analysis_requests
    report = {
        "instances": len(args.urls), "iterations_per_instance": args.iterations,
        "status_matrix": {name: dict(counts) for name, counts in metrics["statuses"].items()},
        "latency_ms": {name: {"p50": percentile(values, 0.50), "p95": percentile(values, 0.95)}
                       for name, values in latencies.items()},
        "inference_call_estimate": qwen_call_estimate,
        "upstream_timeout_rate": metrics["timeouts"] / qwen_call_estimate if qwen_call_estimate else 0,
        "malformed_model_output_rate": metrics["malformed_output"] / qwen_call_estimate if qwen_call_estimate else 0,
        "application_5xx_rate": metrics["application_5xx"] / total if total else 0,
        "peak_concurrent_team_requests": metrics["peak_team_requests"],
        "estimated_peak_qwen_requests": metrics["estimated_peak_qwen_requests"],
        "qwen_concurrency_note": "Estimate from the app's two-request inference semaphore per instance; "
                                 "the public API does not expose upstream live counters.",
        "flag_used": False,
    }
    print(json.dumps(report, indent=2))
    return 1 if metrics["application_5xx"] or metrics["timeouts"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
