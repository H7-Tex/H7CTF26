# Phase 2 design: player-owned stale-worker replay

## Services and trust boundaries

Production has two containers per instance:

| Service | Visibility | Secrets | Purpose |
| --- | --- | --- | --- |
| Relay | Public through HTTPS; 8080 internally | `EXPORTER_TOKEN`; never `FLAG` | PWA, API, release state, dispatch snapshots, signature verification |
| Exporter | Private; no published port | Runtime `FLAG`, `EXPORTER_TOKEN` | Builds a report archive after Relay publishes the report |

There is no deployed Chromium/victim service. The player browser performs the reference lifecycle, stages the outbox, and requests replay. The challenge does not claim that browser headers attest a browser; same-origin checks are CSRF defenses, not identity proofs. Likewise, a server cannot prove that an ordinary P-256 key was created inside a Service Worker. The legacy worker's non-extractable WebCrypto key is realistic application design and protects it from normal page-script export, but it is not an adversarial provenance boundary.

A player may intentionally emulate the complete protocol with their own signing key. That is an accepted expert alternate solve, not a shortcut: Relay recomputes the exact stale-v1 conversion from the authoritative v2 plan, immutable dispatch snapshot, source release/contract, session's saved v1 preference and revision, operation expiry, and one-use staging state. The emulated envelope must exactly match the legacy adapter output; replay must sign that exact envelope after staging. Merely enrolling a key, guessing a v1-shaped object, or signing a client-authored plan is insufficient. The official/reference solve remains a clean real Chromium lifecycle and stale-worker investigation.

## Release and Service Worker lifecycle

Every new Relay session is initially served the real v1 shell and API contract. The v1 document registers `/sw-2026.09.24.1.js`; its initial install caches its shell and runtime resources, creates a P-256 WebCrypto keypair with a non-extractable private key, persists the CryptoKey in IndexedDB, and registers only the public JWK. The user's v1 report-package setting is saved in the worker's `report-settings` object store.

The ordinary **Sync now** action posts `/api/runtime/ready`. Relay advances only that session to v2 after a public key was enrolled and a v1 setting was saved. The old page reloads; the network-first navigation obtains the v2 shell/API. The v2 document registers the byte-distinct `/sw-2026.09.24.2.js`. Chromium installs current but does not activate it while the legacy-controlled client is still open. The browser's actual `registration.active`, `.waiting`, and `navigator.serviceWorker.controller` expose the mismatch. The code does not call `skipWaiting()` or make v2 call `clients.claim()`. Legacy's first activation calls `clients.claim()` only so its initial same-scope page becomes controlled; it contains no upgrade takeover behavior. Closing the legacy client lets Chromium activate waiting current through the normal lifecycle.

Release files are selected per Relay session; this is release delivery only. Relay never decides which worker controls a page. Player and acceptance evidence is collected through the real browser APIs. Current and legacy script contents differ and `/sw-*.js` use `no-cache, no-store, must-revalidate`.

## Historical preference and current contract

The v1 release includes `static/assets/contracts/report-package-v1.json`, hashed in its release manifest and cached by the legacy shell. It documents ordinary v1 package material for `summary`, `record`, and `complete`. Before rollout, the player selects a v1 profile through the normal job form. Relay stores the v1 preference in that session; the worker stores the same profile/revision in IndexedDB. The v2 form/API accepts exactly `{contract, scope}` with `scope=summary|record`; extra keys such as `profile` return 422.

V2's global field preference is guarded by ETags and a lock. The Relay form handles 412 by refreshing and explaining that a newer setting was saved. Dispatch takes one deep, immutable preference snapshot under that same lock at the collection boundary. A late setting edit is assigned to the next cycle. The short production default collection/cooldown is 8 seconds/2 seconds; tests can tune both via environment variables.

## Semantic downgrade, outbox, and publication

V2's plan is an observation with `delivery.persist=false` and `effects=["draft:inspect"]`. Current worker passes it through and never stages it. The legacy adapter applies its old normalization and durable outbox behavior. Its stored pre-rollout package profile wins over the v2 scope during conversion; that is the intended semantic mismatch. A plan is tied to one snapshot, session, release, and expiry. The worker reconstructs the expected envelope from the authoritative plan and its persisted profile before signing; it does not blindly sign IndexedDB JSON.

The stale worker persists a candidate to IndexedDB, then stages the exact materialization at `/api/sync/outbox`. Accepted staging returns the ordinary `reconciliation_receipt` included in `CHECKPOINT_FLAG`; the worker stores that receipt alongside the queued item, and Relay's normal outbox status displays it as a dispatch receipt. It marks the semantic-downgrade materialization only; it does not publish the report or replace the final flag. Staging alone has no publication effect. The application exposes **Send queued updates** after the worker reports a nonempty outbox. A deliberate MessageChannel `RELAY_OUTBOX_FLUSH` makes the worker revalidate, P-256-sign, and POST `/api/sync/replay`. Relay verifies the enrolled key signature, operation/session binding, exact server-recomputed and staged envelope, expiry, and one-use state. Replay of the historical complete package publishes JOB-3887. The normal report export endpoint then asks the private exporter to create the archive; only that service reads `FLAG` and writes `attachments/commissioning-note.txt`.

Background Sync is registered only after the user deliberately requests replay and that attempt is deferred. Offline queue entries carry expiry; expired entries are removed and the next dispatch cycle can proceed. A processed revision cannot publish again. V2 current worker's message implementation reports an empty outbox and does not replay.

## State-changing route inventory

| Route | State change | Intended boundary |
| --- | --- | --- |
| `POST /api/runtime/ready` | Advances the caller's session v1 to v2 | Requires same-origin request, an enrolled v1 key, and saved v1 preference |
| `POST /api/sync/worker-key` | Enrolls the first v1 key; permits only exact reuse after rollout | Public key only; no private material is returned |
| `PUT /api/jobs/JOB-3887/report-preference` | Stores legacy session preference in v1, shared scope in v2 | V2 schema rejects extensions; ETag protects concurrent edits |
| `GET /api/jobs/JOB-3887/report-preference` | Observes preferences and advances due snapshot boundary | Public operational state; one immutable snapshot per cycle |
| `GET/POST /api/sync/plan` | Creates or returns a plan for the current cycle snapshot | Plan is bound to server-side immutable snapshot |
| `POST /api/sync/outbox` | Binds one exact legacy envelope to its operation | Requires valid session and exact materialization |
| `POST /api/sync/replay` | Verifies signature and consumes operation; may publish | Requires pre-rollout key, staged envelope, one-use operation |
| `POST /api/jobs/{job_id}/exports` | Starts an export for an already published report | Relay-to-exporter internal credential; exporter is private |

The dispatch receipt is returned only after the exact semantic-downgrade envelope has been accepted into the outbox. It is a separate dynamically injected flag (`CHECKPOINT_FLAG`); final `FLAG` remains private to the exporter and unavailable before publication. No endpoint takes arbitrary lifecycle strings as proof. A bare preference write, fabricated or extended v1 JSON, unsigned replay, replay before staging, altered source plan, changed operation ID, expired operation, or second replay must not publish.

## Testing and deployment

Browser acceptance starts clean on v1, verifies actual legacy active/controller, uses the normal rollout, verifies actual v2 frontend/API plus legacy active/controller and current waiting, observes durable staging, proves staging alone is inert, then explicitly flushes and exports. A separate update path closes the old client and proves current activates and remains safe. API tests cover the v2 extension rejection, key/session gates, snapshot and export boundaries; Compose acceptance verifies secret isolation and runs the reference solve. TLS acceptance uses the same single-origin HTTPS topology as players and verifies forwarded Host/scheme and the Secure cookie. A newly provisioned Anvil origin is still needed for external ingress confirmation.

Localhost HTTP is a Chromium secure-context exception. Production requires HTTPS or a trusted TLS terminator that preserves Host and forwards `X-Forwarded-Proto: https`. Anvil schema currently provides no service-specific application readiness probe; the browser acceptance itself is the readiness check.
