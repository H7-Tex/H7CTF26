# Trustfall CI intended path

This document is organizer-only. It is outside the challenge build context and must not be served by the player-facing container.

## 1. Initial observation

The player sees a repository portal with source editing, commits, pipeline runs, scanner artifacts, repository assurances, and release requests. The only public service is the portal. Direct production release is denied because no active approval exists.

Observable evidence: the seeded repository has a staging release manifest, Terraform storage and audit files, a scanner artifact view, and an initially unverified `release-integrity` assurance.

Player inference: the path to the protected secret goes through the pipeline and its state transitions rather than a direct release endpoint.

## 2. Repository and pipeline behavior

The portal accepts a bounded repository tree, creates immutable commits, and runs the current candidate commit. The scanner receives that snapshot over an authenticated internal connection. The pipeline rejects historical commits and marks a run stale if the candidate advances before review or approval.

Observable evidence: a run exposes counts, bounded SARIF findings, review status, assurance events, and approval projections without exposing internal prompts, credentials, raw tool calls, or approval binding fields.

Player inference: the scanner result is genuine runtime evidence, and a successful run is not itself a production authorization.

## 3. Genuine Trivy evidence

The pinned Trivy 0.58.2 binary scans the materialized Terraform snapshot with checks updates disabled. Removing the logging block from `aws_s3_bucket.artifacts` produces the pinned `s3-bucket-logging` result. The scanner adds coverage metadata and no player-controlled SARIF can be uploaded directly.

Observable evidence: the artifact identifies Trivy 0.58.2, contains the expected rule, and includes locations for the Terraform resource.

Player inference: an arbitrary result or a fabricated SARIF document will not create the required authority; the finding must come from the exact scanned resource.

Exploit action: edit the artifact bucket to remove its logging block.

Resulting state transition: the current pipeline contains a live release-integrity finding.

## 4. Narrow accepted exception

The repository exception adapter accepts only a well-formed, non-expired exception whose rule, resource, owner, ticket, status, and justification match the finding. Add an accepted exception for `s3-bucket-logging` and `aws_s3_bucket.artifacts`.

Observable evidence: the same genuine Trivy result now carries ordinary accepted external suppression metadata and the exact waiver resource and ticket.

Player inference: the exception is narrow scanner evidence, not a general release authorization.

Exploit action: commit the Terraform change and matching `security-exceptions.json`, then run the staging pipeline.

Resulting state transition: the first run passes full review and the repository has a scanner-grounded qualifying observation.

## 5. Authority laundering into durable memory

ReviewBot receives bounded current SARIF, release-manifest context, and historical project memory. Qwen is mandatory and must return the structured decision. Python validates the decision and records only the broad `release-integrity` assurance when the exact qualifying result is present.

Observable evidence: the first run reports `assurance_updated`, records a security observation, and shows a verified repository assurance whose source is Trivy. The durable record no longer preserves the exception’s narrow source provenance.

Player inference: a repository-controlled exception has acquired broader authority as a persistent project fact.

Resulting state transition: agent memory now contains repository-level release-integrity assurance tied to the poisoning run.

## 6. Historical assurance and fast review

Restore the clean storage Terraform, remove the exception, and make a harmless repository edit. Keep the release manifest as a staging promotion. The new scan is clean but still reports relevant Terraform scanner coverage.

Observable evidence: the second run loads historical assurance, reports no new assurance update, and selects the fast review path. The approval is issued for staging and its public projection identifies the mutable deployment candidate.

Player inference: the durable assurance is being consumed as historical authority even though the current scan no longer contains the accepted finding.

Resulting state transition: the approval controller stores a real approval whose binding type is `candidate`, while separately recording the commit reviewed by ReviewBot.

## 7. Approval binding flaw and TOCTOU

After the legitimate staging approval exists, change only `release.json` from staging to production and commit it. This advances the mutable `candidate` ref to a different commit. A production-capable candidate does not receive a new approval.

Observable evidence: the production-capable run has no new approval, but the earlier candidate approval remains active and still names the candidate ref in its public projection.

Player inference: approval was bound to the mutable ref rather than immutably to the reviewed commit and intended staging subject. The candidate changed after approval, so the release request observes a different state than the review did.

Exploit action: request production promotion for the candidate ref after the post-approval commit.

Resulting state transition: the release service reads the current production-capable tree, finds the active candidate approval, and accepts it without rebinding the observed commit, action, or target.

## 8. Privileged release and dynamic flag

Only the internal release service receives `FLAG`. It validates the current manifest and asks the agents service for an active approval. For a candidate approval it checks the candidate ref, decision, project, and expiry, but intentionally does not compare the reviewed commit, action, or target with the current request.

Observable evidence: the public release endpoint returns a lease only after the internal release flow succeeds.

Player inference: the final authority is the approval-binding confused deputy, not a direct portal bypass.

Exploit action: submit the production release request against the mutated candidate.

Resulting state transition: the release service returns the exact runtime-injected `FLAG`.

## Why the obvious shortcuts fail

- Direct production release has no active approval and is denied.
- Poisoning one run is insufficient because the poisoning run is full review and commit-bound; a second clean staging run is required to produce the candidate-bound fast approval.
- Arbitrary or unrelated Trivy findings do not satisfy the exact rule/resource assurance predicate.
- Malformed, expired, or mismatched waivers are not attached to genuine scanner results.
- Starting a run for a stale commit is rejected, and candidate advancement during scan or review makes the run stale before approval finalization.
- Qwen cannot be bypassed; model availability, model name, digest, structured output, and deterministic policy validation are all enforced.
- Internal scanner, agents, release, and Ollama services are not published and require the internal token.
- A production-capable candidate never receives a fresh approval, so the exploit must mutate state after legitimate staging approval.
