# Changelog

## v0.2.4 - staged receipt and release polish

- Expose the reconciliation receipt only after the exact stale semantic materialization is staged; keep the final flag in the private exporter.
- Keep the browser-based lifecycle as the reference path and document complete protocol emulation as an expert alternate.
- Clarify that the completed package depends on the report setting saved before rollout and that a fresh session allows a retry.
- Protect all sync-operation writes and pruning with the shared state lock.
- Rename browser-visible cache namespaces to Relay-specific names and align deployment image references on `phase3-v0.2.4`.

## v0.2.3 - deliberate legacy profile

- The v1 selector now offers only summary and record; the v1 API still accepts the historical complete profile for deliberate use.
- The reference solve now writes the v1 preference and mirrors its revision to the legacy worker over MessageChannel before rollout.
- Added coverage that summary and record profiles do not publish or produce an export, while the crafted complete path still succeeds.
- Moved v1 installation, release transition, stale-controller update, outbox staging, and deliberate replay onto the player's real browser.
- Removed the private victim browser service and its bootstrap/readiness routes.
- Rejected legacy extension fields in the v2 report preference API and retained legitimate v1 package settings in the old worker's IndexedDB.
- Kept final flag injection isolated to the private exporter.
