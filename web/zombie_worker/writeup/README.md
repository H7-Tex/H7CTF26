# ZOMBIE WORKER — official writeup

## 1. Establish the old client before rollout

A fresh Relay session loads the v1 page and API. Let `/sw-2026.09.24.1.js` install and control that page before pressing **Sync now**. On first initialization the worker creates a P-256 WebCrypto keypair, keeps the private key non-extractable, persists the `CryptoKey` in IndexedDB, and registers only its public JWK. This is normal worker-side key handling, not a server-verifiable proof of where the key was created. Select the v1 package setting through the ordinary job form; the setting and revision are retained by the legacy worker.

Sync now advances that same session to v2 and reloads its page. The page now contains the v2 build and talks to the v2 API. It registers `/sw-2026.09.24.2.js`, whose bytes differ from the legacy script. Chromium installs current but leaves it waiting because the existing page remains controlled by the active legacy worker. Verify this directly in DevTools or the console:

```js
const registration = await navigator.serviceWorker.getRegistration("/");
registration.active?.scriptURL;
registration.waiting?.scriptURL;
navigator.serviceWorker.controller?.scriptURL;
```

Do not close the old page during the solve; once the old client goes away, current can activate normally.

## 2. Find the historical package contract

The predecessor release manifest points to a digested compatibility artifact at `/assets/contracts/report-package-v1.json`. It documents which material the normal v1 package profiles included. The v1 UI let technicians save that setting before rollout. The v2 UI exposes only summary/record scope and the v2 API rejects the old top-level field.

Open JOB-3887 and set the ordinary v2 report detail to **Field record**. The dispatch API exposes the next sync boundary and the saved revision. Relay snapshots one immutable preference revision at that boundary; edits after it apply only to a later cycle.

The completed package depends on the report setting saved before the update. A session that rolled forward with another setting cannot revise that historical choice; start a fresh Relay session to retry.

## 3. Let the old controller process the v2 plan

Once the intended revision appears in the dispatch snapshot, press **Sync now**. The plan returned by v2 describes a preview with `persist=false`. Under the v2 worker this stays transient. The old worker still controlling this page runs its legacy adapter. It reads the saved pre-rollout v1 package preference and applies the older conversion to the v2 plan, persisting a v1-shaped operation in IndexedDB.

The worker stages that exact conversion with Relay. Relay returns an in-world dispatch reconciliation receipt only after accepting the complete semantic conversion into the outbox; this is the intermediate progress marker and does not publish the report. The app shows the receipt and **Send queued updates** because the worker reports pending outbox work. Choose it to send `RELAY_OUTBOX_FLUSH` to the real controller over MessageChannel. The legacy worker reconstructs the authoritative envelope, signs it with the private key in IndexedDB, and sends the one-use replay.

Relay recomputes the entire expected v1 envelope from the stored v2 dispatch operation and session state, then checks the registered public key, P-256 signature, exact staged envelope, snapshot/session binding, expiry, and one-use operation. A correct replay changes JOB-3887 to published; replay cannot be repeated to publish again. Current worker behavior remains safe and leaves the preview nonpersistent.

## Expert alternate: reproduce the protocol

The intended solve above uses Chromium's real active-legacy/current-waiting state. The web platform does not give Relay a trustworthy way to distinguish a P-256 key created in a Service Worker from a player-created key, so full external protocol emulation is deliberately accepted. It is equivalent only when the solver reconstructs the same authoritative v2 plan, snapshot revision/digest and cycle, v1 preference/revision, legacy conversion, expiry, exact staging, and signed one-use replay. A key plus a guessed or incomplete envelope does not work. The reference solve remains browser-based.

## 4. Retrieve the final flag normally

Open JOB-3887, choose **Prepare report package**, and download the resulting archive. The private exporter receives the runtime final `FLAG` and includes it in `attachments/commissioning-note.txt` only when Relay has published the v1 complete package. Relay stores report metadata but never reads that final flag. The intermediate `CHECKPOINT_FLAG` is separately injected into Relay and appears only in the accepted dispatch reconciliation receipt.

## 5. Architecture and recovery

There is no private victim browser; the player's own profile performs the v1 install, rollout, stale-client lifecycle, outbox staging, and explicit replay. `skipWaiting()` and upgrade-time `clients.claim()` are intentionally absent so the browser can retain the stale controller. The initial v1 `clients.claim()` only gives its initial page control. Closing the legacy-controlled page eventually allows waiting current to activate.

V2 preference writes are ETag-protected and atomic. The immutable cycle snapshot prevents concurrent edits from tearing the plan; a 412 makes the UI refresh and explain that a newer setting was saved. Expired outbox operations are discarded and a later dispatch cycle can run. Background Sync is registered only after deliberate replay was deferred. The app remains same-origin; production access requires HTTPS through the player ingress.

## 6. Verification

`challenge/tests/acceptance_lifecycle.py` demonstrates the real active legacy/controller legacy/waiting current state and the safe current-worker recovery. `acceptance_phase2.py` runs the reference browser solve from a clean profile and verifies staging before explicit replay. `acceptance_compose.py` checks the two-service deployment and runtime flag isolation. `acceptance_https_ingress.py --local-tls` runs the same player path through TLS termination. A live Anvil origin is required to claim external deployment acceptance.
