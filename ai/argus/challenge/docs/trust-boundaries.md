# ARGUS trust boundaries

| Transition | Trusted input | Provenance or authority lost | Authority gained | Intentional vulnerability or boundary |
| --- | --- | --- | --- | --- |
| Registry approval → runtime catalog | Server-computed package digest and approval-time MCP descriptor snapshot | The approval is not re-bound to the later live descriptor hash | The runtime catalog can expose a fresh `tools/list` result while approval remains valid | Intentional digest-versus-live-descriptor gap |
| Registry persistence → community MCP | Fixed package identity and instance-scoped integration key | A second active fixed registration has no separate authority | One active `vendor-incident-review` integration and one corresponding MCP state row per instance | Boundary: duplicate registrations are rejected |
| MCP catalog → internal tool lookup | Server-qualified `(server_id, tool_name)` identity | A wire-level tool name is not a global identifier | Future consumers can distinguish equal names from different servers | Boundary: no global tools-by-name map |
| Portal → Incident Agent | Edge-specific `portal_agents` credential and bounded structured incident | Free-form instructions and arbitrary tool selection are not accepted as workflow input | Agents may create one bounded incident workflow | Boundary: telemetry is evidence, not a model instruction channel |
| Agents → Registry | `agents_registry` credential and one read-only approved-catalog route | Agents cannot register, approve, mutate metadata, or read deliveries through this edge | Agents receive the current live approved community semantics | Boundary: fresh catalog consumption without Registry mutation authority |
| Trusted Git → Agent context → community MCP | Per-instance control/review-contract result and validated community arguments | Agents retain provenance but do not enforce a source-taint policy | Approved community integration receives bounded Git-derived context | Intentional Phase 3 cross-tool information flow |
| Trusted Git → community input | Portal-validated repository/community data | The receiving tool does not inherit every source-side guarantee | Agents can use the community context | Intentional cross-tool information flow |
| External A2A → Coordinator | Valid A2A task shape and caller credential | External origin, owner semantics, and recommendation authority are not preserved by normalization | Coordinator may create an MCP-shaped request | Intentional semantic downgrade |
| Coordinator → Security MCP | Authenticated `coordinator_security` MCP `tools/call` for `security/request_approval` | Authentication does not prove that the original recommendation was authorized | Security may issue one bounded approval | Intentional semantic downgrade; MCP structure and edge auth remain valid |
| Security approval → Deployment | Signed approval with the complete canonical set: instance_id, approval_id, task_id, control_id, target, granted_capability, expires_at, and key_id | No general credential, profile selector, or raw manifest is transferred | Deployment may claim one matching approval once and derive its profile | Boundary: valid approval is not generic authority |
| DeploymentProfile → Kubernetes | Trusted profile, instance ID, deployment ID, image | Player input cannot select arbitrary objects or roles | One namespaced service account acts on one resource | Boundary: external resourceName-scoped RBAC |

An A2A message being structurally valid is not proof of authority. Coordinator authentication is not proof that the external recommendation should be trusted. The semantic downgrade is the intended flaw: Security signs `PROTECTED_RUNTIME` after receiving the normalized request, and Deployment correctly maps that capability to `TEAM_NAMESPACE_ELEVATED`. Likewise, Kubernetes is an actuator: its profiles enforce the foundation contract, while organizer-provisioned RBAC and the external janitor remain outside the application’s authority.

An approval is authority for exactly one instance, control, target, capability, and expiry. It is not a generic deployment switch.

The registry package digest identifies the fixed artifact; the MCP descriptor describes current live service semantics. Those values are recorded separately, and neither package identity nor the server-qualified tool identity is inferred from a mutable description.

The implementation intentionally preserves the three challenge weaknesses above. Other service boundaries should fail closed, keep credentials edge-specific, enforce size limits, and avoid returning secrets or raw cluster data.

Deployment verifies the signed Security authority, atomically makes it single-use, derives a profile, and never revisits the original A2A provenance. The loss of provenance is earlier; Deployment correctly consumes the resulting excessive signed capability. Its H7 adapter accepts only derived workload operations and bounded readiness/result paths. The app has no Kubernetes API credentials. The organizer host provisioner reconciles per-instance resources; the in-namespace broker receives only its bounded workload-lifecycle Role.

The workload itself verifies the organizer RBAC invariant: the exact counterpart resource must return HTTP 403, then the intended resource must succeed. This is runtime safety evidence, not another challenge vulnerability. The workload emits exactly one `isolation_verified=true` result and remains alive so Kubernetes readiness remains stable.

The final actuator remains bounded: `TEAM_NAMESPACE` can read only `ConfigMap/argus-public`, and `TEAM_NAMESPACE_ELEVATED` can read only `Secret/argus-protected` in the Anvil instance namespace. The broker cannot read either object. Deployment and Kubernetes are not vulnerable; they correctly implement the excessive authority produced by the earlier semantic downgrade.

H7 runs the five logical application roles as child processes in one Anvil app
pod so they share exactly one SQLite file. The Agents process calls the
organizer's external Qwen service at `https://qwen.h7tex.com`; there is no
per-team model container or inference Docker network. Anvil namespace deletion
cleans the per-team broker, protected Secret, and runtime workloads.

The exact Phase 4 source-to-target mapping is deliberately narrow: public A2A Agent Card discovery, followed by authenticated/versioned HTTP+JSON SendMessage and GetTask operations. ARGUS implements this bounded A2A v1.0 profile rather than the complete protocol/TCK surface. A `ROLE_USER` Message and one structured JSON data Part preserve external partner metadata (`sourceType=external-partner`) plus `type=deployment-review`. Agents creates the A2A Task and context IDs and stores the original SendMessage request. Coordinator commits the operational projection as MCP `tools/call` arguments `task_id`, `control_id`, `target`, and `decision`; it omits source metadata and review type. Security receives those arguments over authenticated `coordinator_security`, reloads the persisted projection, derives `PROTECTED_RUNTIME` only from the fixed decision after checking trusted control and target, then signs the canonical `instance_id`, `approval_id`, `task_id`, `control_id`, `target`, `granted_capability`, `expires_at`, and `key_id` claims. The approval row also persists the exact key ID. A2A conformance is not the vulnerability; the loss occurs during the A2A-to-MCP translation.

The public Portal forwards only these fixed A2A operations and injects the
internal `portal_agents` edge credential. It never forwards arbitrary upstream
URLs, methods, paths, or credentials. Agent Card discovery is public; the
operational operation remains authenticated and version-gated internally.
