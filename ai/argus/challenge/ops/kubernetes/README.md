# ARGUS organizer Kubernetes setup

The organizer instance manager now renders this contract, obtains a
TokenRequest credential for `argus-deployer`, and applies it before Compose is
started. The template remains a reviewable reference:

```bash
export ARGUS_NAMESPACE=argus-team-a
export ARGUS_INSTANCE_ID=team-a
export ARGUS_VERIFICATION_RESULT='replace-with-the-instance-verification-result'
export ARGUS_DEPLOYER_SERVICE_ACCOUNT=argus-deployer
export ARGUS_CREATED_AT='2026-01-01T00:00:00.000000Z'
export ARGUS_EXPIRES_AT='2026-01-01T02:00:00.000000Z'
envsubst < ops/kubernetes/team-namespace.yaml | kubectl apply -f -
```

The worker accounts are deliberately resource-name scoped. The protected
Secret stores the value under `verification_result`, matching the runtime
workload contract:

- `argus-worker` may only `get` ConfigMap `argus-public` in its namespace.
- `argus-elevated` may only `get` Secret `argus-protected` in its namespace.

The Deployment actuator account may create, inspect, and delete only ARGUS
Deployment workloads and inspect the matching pod/log result. It has no Secret,
ConfigMap, RBAC, namespace, exec, impersonation, or token-creation permission.

The external CTF janitor owns namespace TTL and deletion. ARGUS only deletes
the exact workload it created.
