"""Repeat the complete real-browser Compose solve with fresh instances."""
from __future__ import annotations

import os
import json
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent
ACCEPTANCE = HERE / "acceptance_compose.py"
RUNS = int(os.environ.get("ZW_RELIABILITY_RUNS", "20"))


def main() -> None:
    cycle_durations = []
    stage_latencies = []
    heap_samples = []
    container_memory_samples = []
    retry_total = 0
    for attempt in range(1, RUNS + 1):
        result = subprocess.run(
            [sys.executable, str(ACCEPTANCE)], cwd=CHALLENGE,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=360,
            env=dict(os.environ, PYTHONIOENCODING="utf-8:replace"),
        )
        expected = (
            "[PASS] player's own browser established legacy active/current waiting and completed the exported report",
            "[PASS] runtime flag is absent from Relay logs",
            '"cycle_stuck": false',
        )
        if result.returncode or any(marker not in result.stdout for marker in expected):
            raise RuntimeError(f"Compose solve {attempt}/{RUNS} failed:\n"
                               f"{result.stdout[-6000:]}\n{result.stderr[-3000:]}")
        metric_line = next((line.removeprefix("[METRIC] ") for line in result.stdout.splitlines()
                            if line.startswith("[METRIC] ")), None)
        if metric_line is None:
            raise RuntimeError(f"Compose solve {attempt}/{RUNS} did not report cycle metrics")
        metrics = json.loads(metric_line)
        if metrics["cycle_stuck"]:
            raise RuntimeError(f"dispatch cycle remained stuck on run {attempt}/{RUNS}")
        cycle_durations.append(float(metrics["cycle_duration_seconds"]))
        stage_latencies.append(float(metrics["stage_latency_seconds"]))
        if metrics["browser_heap_used_bytes"] is not None:
            heap_samples.append(int(metrics["browser_heap_used_bytes"]))
        container_memory_samples.append(int(metrics["relay_container_memory_bytes"]))
        retry_total += int(metrics["retry_count"])
        print(f"[PASS] fresh Compose instance/player profile {attempt}/{RUNS}", flush=True)
    print(f"[PASS] complete real-browser solve reliability: {RUNS}/{RUNS}", flush=True)
    print("[METRIC] " + json.dumps({
        "runs": RUNS,
        "cycle_duration_median_seconds": round(statistics.median(cycle_durations), 3),
        "cycle_duration_max_seconds": round(max(cycle_durations), 3),
        "stage_latency_median_seconds": round(statistics.median(stage_latencies), 3),
        "stage_latency_max_seconds": round(max(stage_latencies), 3),
        "retry_count_total": retry_total,
        "browser_heap_median_bytes": int(statistics.median(heap_samples)) if heap_samples else None,
        "relay_container_memory_median_bytes": int(statistics.median(container_memory_samples)),
        "relay_container_memory_max_bytes": max(container_memory_samples),
        "permanently_stuck_cycles": 0,
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
