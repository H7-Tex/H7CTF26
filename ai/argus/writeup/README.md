# ARGUS intended path

ARGUS is an AI-security challenge about package identity, mutable capability
semantics, trusted context, and protocol translation. Kubernetes and the
protected runtime are bounded, correct actuators; the solve does not depend on
a Kubernetes exploit.

## Intended solve

1. Register and approve the community integration through the Portal. Its
   approval binds the package identity, while its live descriptor remains
   mutable.
2. Inspect the incident evidence and integration delivery records. Internal
   context supplies the control and target values needed by the community
   capability.
3. Change the live service summary to accurately claim incident assessment and
   a recommended next action. Submit the incident and confirm the trusted
   internal runbook context flows into the approved community tool.
4. Submit that recommendation as a valid A2A request. Coordinator normalizes it
   into the MCP Security request and drops the recommendation semantics.
5. Security issues the signed `protected-runtime` approval. Submit it to
   Deployment. The bounded broker creates the derived `argus-elevated`
   workload in the existing Anvil instance namespace.
6. Read the completed deployment result. The elevated runtime reads only
   `Secret/argus-protected`, and returns the exact per-instance
   `H7CTF{...}` value as `verification_result`.

The chain ends at the deployed runtime. There is no raw manifest path, arbitrary
image execution, direct flag endpoint, or alternate model path.

## Evidence screenshots

Place screenshots in `writeup/img/` and capture these states from a clean
instance:

- approved integration and package identity;
- live service-summary mutation after approval;
- incident event and approved community-tool delivery showing trusted context;
- A2A task and normalized MCP Security approval artifact;
- protected-runtime deployment profile and bounded readiness evidence;
- final `H7CTF{...}` verification result.
