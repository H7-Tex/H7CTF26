# Phase 3: downstream report packaging

Phase 3 is the consequence reached after the player's stale-worker replay publishes JOB-3887.

The legacy adapter materializes a historical `relay.report-package/v1` package. Relay records the package metadata after validating the exact signed operation, but does not read the runtime flag. A normal **Prepare report package** request sends the published report metadata to the private exporter. The exporter recognizes the historical complete package and writes the runtime `FLAG` into `attachments/commissioning-note.txt` in the resulting ZIP.

Deployment has only public Relay and private exporter services. The player's browser owns the actual v1/v2 lifecycle and P-256 key; no server-side victim or bot performs publication. The platform manifest injects `${FLAG}` only into exporter. The exporter has no published port and no egress. Relay uses its internal token but is configured without the flag. Image tags for this release are pinned to `phase3-v0.2.4`; publication and fresh Anvil verification are still required before rollout.

The page, API, and workers share the player-facing HTTPS origin. The ingress preserves Host and forwards `X-Forwarded-Proto: https`, so Relay sets a Secure, HttpOnly session cookie. `acceptance_https_ingress.py --local-tls` verifies this topology locally. A live Anvil instance is needed for external deployment evidence.
