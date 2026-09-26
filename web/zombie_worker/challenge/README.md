# Relay challenge service

Relay is a field-dispatch PWA with a public application/API and a private report exporter. The player's browser is the lifecycle actor: a new session starts on v1, registers and controls the legacy worker, then advances to v2 while that client remains open. The v2 worker installs and waits. There is no private browser bot. Only the exporter receives the runtime `FLAG`.

## Local run

```sh
export FLAG='H7CTF{dummy}'
export EXPORTER_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
docker compose up --build
```

For PowerShell:

```powershell
$env:FLAG = 'H7CTF{dummy}'
$env:EXPORTER_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
docker compose up --build
```

Open `http://localhost:8080`; localhost is treated as a secure context by Chromium. Production must use HTTPS through ingress that preserves `Host` and sends `X-Forwarded-Proto: https`, which causes Relay to set the `Secure; HttpOnly; SameSite=Lax` session cookie. The Compose network disables bridge masquerading and only Relay publishes a port.

## Tests and acceptance

Install test dependencies, then run:

```sh
python -m pip install -r requirements.txt -r requirements-test.txt
python -m playwright install chromium
python -m pytest -s -q tests/test_api.py tests/test_exporter.py tests/acceptance_lifecycle.py tests/acceptance_phase2.py
python tests/acceptance_compose.py
python tests/acceptance_https_ingress.py --local-tls
ZW_RELIABILITY_RUNS=5 python tests/run_reliability.py
```

These use real Chromium Service Worker registrations, the actual active/controller/waiting workers, IndexedDB, a non-extractable WebCrypto key, and MessageChannel replay. `../solution/solve_phase2.py` is the reference player path. A complete protocol emulation is also intentionally accepted: the platform cannot attest that a P-256 key originated inside a Service Worker, so the server instead verifies the exact authoritative stale-v1 transformation, complete staged envelope, signature, expiry, and one-use replay. Run `ZW_RELIABILITY_RUNS=20 python tests/run_reliability.py` for the extended gate. A live Anvil HTTPS instance is required to claim platform ingress verification; local TLS acceptance does not substitute for it.

## Release and sync model

New Relay sessions begin on v1. The normal v1 Sync now request advances that session to v2 after the legacy worker has enrolled its public signing key and the user has saved a v1 report-package preference. The open page reloads with the v2 shell. Chromium detects the distinct worker script, installs it, and leaves it waiting while the legacy-controlled page remains alive. Closing the old client lets the waiting worker activate naturally.

The historical package contract is listed in `/__release/manifest/v1.json` and its compatibility document is `/assets/contracts/report-package-v1.json`. It records the normal material associated with each historic package profile. The v2 form exposes only `scope=summary|record`; its API rejects additional properties such as the old v1 field. Saved preference changes are snapshotted atomically at the visible dispatch boundary. A late write is used in the next cycle.

V2 returns a preview with `persist=false`. The current worker leaves it transient. The still-controlling legacy adapter interprets it under the retained v1 preference, writes a durable IndexedDB outbox entry, and stages the exact materialization. Relay returns a dispatch reconciliation receipt only after accepting the complete conversion; the worker persists it with the queued entry and the application shows it as a routine receipt. This marks the accepted semantic conversion, not report publication. The user explicitly chooses **Send queued updates**, which sends `RELAY_OUTBOX_FLUSH` over MessageChannel to the actual controller. The worker reconstructs the expected operation, signs it with its persisted non-extractable key, and replays it once. Staging alone does not publish. Expired queue items are discarded and the dispatch cycle advances; after an offline replay attempt, Background Sync may retry the same still-valid staged item.

The shared v2 preference uses ETags and atomic revisions. If another technician saves first, the UI refreshes and explains that a newer setting was saved. The immutable cycle snapshot cannot be torn by concurrent edits.

## Runtime and deployment boundaries

`challenge.yml` reserves immutable `phase3-v0.2.4` image tags for the public Relay and private exporter. Both have egress disabled and explicit resource limits. Relay receives the independent runtime `CHECKPOINT_FLAG` and internal exporter token, but never the final `FLAG`; the private exporter receives `FLAG` and the token. The reconciliation receipt is returned only after exact stale materialization staging. The final flag appears only in the ordinary export attachment after replay publishes the report. No victim image or readiness service is deployed. These images must be built and published from this revision before Anvil deployment.

Anvil currently has no per-service application readiness probe in the supported challenge schema; the real-browser acceptance verifies the lifecycle after instance startup. Run `python tests/acceptance_https_ingress.py --url https://<fresh-instance>` against a newly provisioned instance for the player-facing TLS path. No Anvil origin was available in this checkout, so that external gate remains unverified.

State-changing routes: `POST /api/runtime/ready` advances an enrolled v1 browser session; `POST /api/sync/worker-key` enrolls the first v1 worker key and permits only exact key reuse after rollout; `PUT /api/jobs/JOB-3887/report-preference` updates the public preference; `/api/sync/plan` observes a snapshot; `/api/sync/outbox` binds the exact worker materialization and returns the dispatch receipt; `/api/sync/replay` verifies and consumes its signature; `POST /api/jobs/{job_id}/exports` requests a package from the exporter. The exporter has no public port.
