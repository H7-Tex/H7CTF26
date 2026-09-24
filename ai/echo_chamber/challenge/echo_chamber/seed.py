from __future__ import annotations

from .db import Database


# One row per imported source keeps the initial incident evidence independent.
CORPUS = [
    ("StreamForge 4.5 TLS advisory", "StreamForge 4.5 deployments should rotate the bundled TLS trust store before the next maintenance window. The issue affects encrypted control-plane connections, not worker process stability."),
    ("StreamForge 4.6 worker tuning guide", "Worker concurrency and graceful shutdown intervals can be adjusted for high-throughput installations. Track queue depth and shutdown duration when changing worker counts."),
    ("StreamForge 4.7 heap behavior change", "StreamForge 4.7 changed memory reuse behavior for long-lived workers. The release note recommends monitoring resident memory during rolling upgrades; it does not identify a known crash condition."),
    ("StreamForge 4.8 compatibility bulletin", "StreamForge 4.8 supports the current Linux LTS releases and the documented container runtimes. Validate extension compatibility before upgrading production workers."),
    ("StreamForge 4.8 runtime migration notes", "The 4.8 branch updates worker-runtime components and adds additional allocator telemetry. Review the compatibility matrix for native extensions and collect worker diagnostics when a process exits unexpectedly."),
    ("Connection-pool exhaustion incident", "A customer API tier experienced elevated latency after exhausting its database connection pool. Worker processes remained healthy; queue delay tracked active connection count."),
    ("Worker timeout postmortem", "A worker timeout was traced to a downstream service exceeding its request deadline. Raising the timeout alone hid the symptom, while correcting the dependency latency resolved it."),
    ("Linux allocator troubleshooting", "For intermittent native process exits, preserve a core file and compare allocator diagnostics with application logs. Memory pressure and invalid native extension access can produce superficially similar symptoms."),
    ("Object storage replication advisory", "Delayed replication in one storage region can increase recovery point age. No worker runtime or application process changes are required."),
    ("Network route maintenance notice", "A route update may briefly interrupt connections to the analytics subnet. Applications should reconnect using the standard retry policy."),
    ("StreamForge 4.4 logging reference", "Worker logs include lifecycle events, task identifiers, and graceful-stop reasons. Log rotation should retain at least one complete deployment window."),
    ("StreamForge 4.6 queue backpressure note", "Backpressure limits protect worker pools when producers outpace consumers. A saturated queue generally causes delayed work rather than abrupt process termination."),
    ("Container memory limit checklist", "Compare container memory limits with observed resident set size and restart history. An enforced memory limit can terminate a process without an application-level exception."),
    ("Customer report: delayed jobs after patching", "After a routine patch, one customer saw jobs remain queued for several minutes. Increasing worker count restored throughput; no process exits appeared in the host journal."),
    ("StreamForge extension compatibility matrix", "Native extensions should be rebuilt against the runtime ABI documented for each supported StreamForge minor release. Unsupported extensions can fail during load or task execution."),
    ("Regional DNS resolution incident", "Intermittent DNS resolution failures delayed outbound requests in one region. The incident was mitigated by restoring the resolver pool; worker processes stayed online."),
    ("Metrics collector upgrade guide", "Collector upgrades can rename histogram labels. Dashboards should be checked for missing series after rollout; the collector runs separately from StreamForge workers."),
    ("StreamForge 4.3 worker shutdown advisory", "A shutdown race in an older 4.3 build could delay termination while active jobs drained. The issue was addressed in a maintenance release and differs from unexpected exits during normal processing."),
    ("Filesystem inode pressure runbook", "Low inode availability can prevent temporary files from being created. Check filesystem utilization and kernel logs when jobs fail to stage local data."),
    ("Customer report: intermittent worker restarts", "A customer observed worker restarts during a deployment window but found no common task pattern. Host memory pressure and orchestrator eviction events were still under investigation."),
    ("StreamForge 4.8 plugin migration checklist", "Before enabling a plugin on 4.8, verify its supported runtime ABI and test it with representative workloads. Capture the plugin inventory alongside worker logs if a rollout needs investigation."),
    ("Message broker certificate rotation", "Broker certificate rotation caused several clients to reconnect. The event affected connection availability and did not change local worker memory behavior."),
    ("CPU throttling operations note", "Sustained CPU throttling can increase task duration and trigger external deadlines. Compare container throttled time with application latency before changing worker concurrency."),
    ("StreamForge 4.5 configuration migration", "The 4.5 configuration parser accepts the legacy worker-count key for compatibility. New installations should use the current worker pool setting."),
    ("Backup catalog indexing delay", "A catalog index rebuild delayed search results for backup operators. Restore operations and the StreamForge execution tier were unaffected."),
    ("Kernel OOM event guide", "The kernel OOM log records processes selected after a memory limit is exceeded. Correlate timestamps with container restarts before attributing termination to application code."),
    ("StreamForge worker health endpoint", "The health endpoint reports readiness and active task count. It does not retain the reason for a process that has already exited."),
    ("Customer report: native module load failure", "A native module built for an earlier runtime ABI failed during startup after an upgrade. Rebuilding the module against the installed headers restored service."),
    ("Time synchronization troubleshooting", "Clock drift can complicate correlation across hosts. Compare NTP status and normalize timestamps before joining application and infrastructure logs."),
    ("StreamForge 4.8 rollout checklist", "Roll out 4.8 gradually, verify extension compatibility, and compare worker restart rates against the previous build. Keep application logs and runtime metrics for each canary interval."),
    ("Queue visibility timeout explanation", "A visibility timeout can cause a task to be delivered again when processing takes longer than expected. It affects task duplication, not the worker process lifecycle."),
    ("Storage volume latency report", "An overloaded volume caused slow checkpoint writes and elevated job durations. No worker exits were recorded, and replacing the volume resolved the issue."),
]


def seed_database(db: Database) -> None:
    db.seed_incident()
    with db.connection:
        for index, (title, content) in enumerate(CORPUS, start=1001):
            evidence_id = f"KB-{index}"
            db.connection.execute(
                """INSERT OR IGNORE INTO evidence
                   (evidence_id, origin_id, representation_type, title, content, processor, created_at)
                   VALUES (?, ?, 'source', ?, ?, 'seed-import-v1', '2026-01-15T00:00:00Z')""",
                (evidence_id, f"SRC-{index}", title, content),
            )
