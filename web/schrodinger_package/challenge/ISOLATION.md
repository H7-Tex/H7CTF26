# Runtime trust boundary

**Trust boundary: `runtime container == attacker-controlled after package import`.**
The smoke test imports arbitrary wheel code. Runtime source, container state,
procfs metadata, the shared read-only artifact store, and SQLite metadata are
readable from that container. A sanitized `Popen(env=...)` only controls the
child's environment; `Popen(env=...)` does not itself hide the parent
environment through `/proc`.
The parent is made non-dumpable, and seccomp denies ptrace, process-VM, pidfd,
and signal APIs. The regression test for the unprotected parent demonstrates
why the child environment allowlist alone is insufficient.

Runtime has no real flag, flag-derived data, credentials, or privileged success
operation in environment variables, command arguments, readable files, source,
mounted volumes, SQLite, or URLs. The only mounted data volume is read-only and
contains artifacts and operational metadata. Inspector has no Runtime network
membership. Runtime can receive Portal requests, but the import subprocess is
blocked from creating network sockets by its Linux seccomp filter. No Docker
socket is mounted.

Portal exclusively owns the real challenge flag. The final challenge mechanism must keep the flag outside the attacker-controlled
Runtime container and release it only through the intentionally designed
success condition added by Portal. Portal returns a released flag only in the
immediate response; persisted session output is sanitized and flag-free.
