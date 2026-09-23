# ARGUS challenge design

ARGUS is a cross-protocol trust-boundary challenge. The intended solve follows a benign registration path, observes where provenance is lost, and uses the resulting approved workflow to complete the Deployment verification workflow. The player should not need arbitrary network access, raw Kubernetes manifests, or hidden service credentials.

| Stage | Player capability | Trust assumption | Failure or semantic loss | Observable result |
| --- | --- | --- | --- | --- |
| 1. Portal discovery | Inspect the public workflow | Portal routes only bounded requests | Public behavior reveals the role graph | The service edges become discoverable |
| 2. Package registration | Submit a package descriptor | Registry verifies the package digest | Approval does not bind the live descriptor hash | A package can remain approved after descriptor mutation |
| 3. MCP cataloging | Request the approved catalog | Registry exposes only approved packages | Runtime metadata is trusted separately from the original submission | A live tool descriptor is available |
| 4. Descriptor observation | Read a bounded tool descriptor | Registry metadata is authoritative | The current descriptor is not cryptographically re-bound | Tool behavior and approval can diverge |
| 5. Community input | Submit trusted Git/community context | Agents accept the declared community source | Cross-tool information flow crosses service boundaries | Agent context contains the community claim |
| 6. Agent task creation | Start an A2A task | Agents authenticate the caller | Origin and ownership are carried as data, not universal authority | A bounded task is stored |
| 7. External recommendation | Supply or receive a vendor recommendation | A2A structure is valid | Structural validity is later treated too much like authority | The recommendation enters Coordinator input |
| 8. Coordinator normalization | Advance the task to MCP | Coordinator authentication is valid | A2A provenance and ownership are semantically downgraded | A normalized MCP request exists |
| 9. Security decision | Request the control decision | Security sees a valid normalized request | The downgrade allows the wrong semantic source to influence the decision | A signed, expiring approval grants one bounded capability |
| 10. Approval claim | Present the approval to Deployment | Approval is instance-, control-, target-, and capability-bound | Deployment derives the matching trusted runtime profile | The approval becomes single-use |
| 11. Normal profile | Create a benign workload | Worker access is namespaced | Normal authority is limited to `ConfigMap/argus-public` | A safe Deployment is observed |
| 12. Elevated profile | Use the approved elevated path | Deployment is the sole actuator | Elevated authority reaches only the protected namespaced resource | The deployment verification result is reachable |
| 13. Evidence | Read deployment status | Evidence is bounded and non-secret | No secret dump or raw manifest is exposed | Readiness and event summaries are returned |
| 14. Cleanup | Finish or abandon the run | Anvil owns the instance namespace | Local cleanup requests are advisory | Namespace deletion removes all instance resources |

The intended causal chain is one agent workflow: a post-approval descriptor mutation changes semantic tool selection; the Agent invokes a trusted Git tool; Git returns private control/schema material; the same workflow then invokes a community MCP tool with that material in its arguments. The player does not manually submit the private Git output as a separate action.

Phase 3 keeps provenance and information-flow enforcement distinct. Agents records server-qualified tool calls and bounded result projections for organizer verification, but it intentionally permits the trusted Git result to move through Agent working context into the approved community MCP call. The community delivery read model exposes only what that integration received; it does not expose prompts, hidden reasoning, credentials, or raw internal rows.

Stage 1 uses a fixed internal MCP route and the stateless 2026-07-28 `tools/list` request. Registry approval records both the server-computed package digest and approval-time descriptor hash. Later catalog reads refresh the live descriptor and store new snapshots without comparing the fresh hash to the approval hash. The package artifact cannot be changed through the player workflow; only bounded post-approval service metadata changes the description.

The intentionally vulnerable transitions are narrow: package digest versus live descriptor hash, cross-tool information flow, and A2A-to-MCP semantic downgrade. Kubernetes is an actuator and does not add a new exploit surface. The semantic downgrade causes Security to sign the stronger capability; Deployment then enforces that capability correctly.

The Phase 4 task is observable through A2A v1.0 discovery, `POST /message:send`, and `GET /tasks/{id}`. The server-created Task history retains the valid `ROLE_USER` Message, the external partner source metadata, and the deployment-review data. Its metadata exposes the normalized MCP request (`task_id`, `control_id`, `target`, `decision`) and the artifact contains approval metadata (approval ID, bindings, capability, expiry, persisted key ID, and signature). The Coordinator sends that request as MCP `tools/call` to server `security`, tool `request_approval`; it does not send credentials or source metadata. The source review is valid structured input; the intended weakness is that normalization no longer carries enough provenance to distinguish an external recommendation from an authorized control decision.

## Phase 5 actuator contract

After Phase 4, the player submits the signed approval to the normal Deployment workflow through the `portal_deployment` edge. Deployment verifies the complete canonical claim and consumes it once. It derives the workload name, image, ServiceAccount, and profile from the signed capability and trusted instance configuration; the internal broker uses its own Pod namespace, and the player never supplies a profile or Kubernetes object.

The normal signed capability maps to `TEAM_NAMESPACE` and `argus-worker`, whose external namespaced RBAC permits only `get` on `ConfigMap/argus-public`; the trusted workload first verifies that `Secret/argus-protected` returns exactly 403. The protected signed capability maps to `TEAM_NAMESPACE_ELEVATED` and `argus-elevated`, whose external namespaced RBAC permits only `get` on `Secret/argus-protected`; its workload first verifies that `ConfigMap/argus-public` returns exactly 403. Each workload emits one fixed result with `isolation_verified=true` and remains alive after its one-shot result, keeping Deployment readiness stable. Deployment exposes only readiness/evidence and, for the elevated profile, the final verification result. It does not expose Kubernetes credentials, raw logs, manifests, Secret objects, or arbitrary events.

Deployment and Kubernetes are intentionally not a second exploit. Authentication remains correct, and authorization is enforced correctly at the actuator. The excessive authority was produced earlier because recommendation provenance was lost during the authenticated A2A-to-MCP translation.

The player-facing Portal is an explicit workflow surface, not a generic reverse
proxy. It exposes package discovery, the bounded Registry operations, incident
operations, public Agent Card/A2A operations, and signed-approval Deployment
evidence. It does not reveal the internal service graph or automate the causal
transitions. The exact observable evidence expected for each inference is kept
in `docs/fairness-checklist.md`.

Organizer topology is separate from the player challenge: the instance manager
derives one internal inference network per team and attaches only that team's
Agents plus the shared pinned Ollama container. No player input selects a
network, endpoint, image, or workload specification, and the development-only
Portal port overlay is never loaded for competition instances.

## Player-facing composition

The Portal is an ordinary operations application rather than a solve wizard.
Overview, Integrations, Incidents, Agent Interop, and Runtime are independently
reachable areas, and the application does not store or display challenge
progression. Package discovery, integration details, live runtime catalog,
delivery history, incident evidence, task inspection, and deployment records
remain available as separate bounded views.

Protocol discoverability is provided by the public Agent Card and a read-only
`deployment-control-review` contract that documents the wire shape, field
names, types, supported constant values, protocol version, media types, and
output mode. The raw A2A composer starts blank and the signed-approval editor
in Runtime also starts blank. The UI never links a Delivery Inbox value into
an A2A request or a Task artifact into Deployment. Observable evidence is
required; guided exploit sequencing is not.
