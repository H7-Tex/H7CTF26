# Phase 1 design: browser-owned worker lifecycle

One FastAPI process serves per-session release shells, API metadata, assets, and two stable Service Worker script URLs. A fresh player session begins on v1. The normal Sync now action posts `/api/runtime/ready` after the legacy worker has enrolled its key and the user has saved a v1 report setting; Relay advances that session to v2. This changes the shell and API responses only. It never stores or decides which worker controls a client.

The v2 document registers `/sw-2026.09.24.2.js` at the same `/` scope as the active legacy worker. The script bytes differ and the server sends no-cache/no-store headers for both worker scripts. Chromium installs current and waits because the open v2 page remains controlled by legacy. Neither worker calls `skipWaiting()`. Legacy uses `clients.claim()` during initial activation; current deliberately has no `clients.claim()`. Current may activate after old clients close.

Each generation has release-derived static/runtime Cache Storage namespaces. The current install does not delete the legacy cache; cache cleanup runs only once current activates. Lifecycle state is observed through the browser's real `ServiceWorkerRegistration.active`, `.waiting`, and `navigator.serviceWorker.controller` properties, with `MessageChannel` available for direct worker version inspection. After the exact stale-v1 materialization is accepted into the outbox, Relay returns a dispatch reconciliation receipt; it does not accept client-declared lifecycle versions as proof.

Chromium considers localhost and loopback HTTP secure contexts for development. Public deployment must expose the page, API, and Service Worker scripts over one HTTPS origin through a TLS ingress.
