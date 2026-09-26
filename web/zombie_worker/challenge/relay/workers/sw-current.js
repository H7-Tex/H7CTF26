/* Relay field sync worker for the 2026.09.24.2 release. */
const BUILD_ID = "2026.09.24.2";
const RELEASE_ID = "__RELEASE_ID__";
const WORKER_SCRIPT = "/sw-2026.09.24.2.js";
const STATIC_CACHE = `relay-static-2026.09.${RELEASE_ID}`;
const RUNTIME_CACHE = `relay-runtime-2026.09.${RELEASE_ID}`;
const OUTBOX_DB = "relay-offline-outbox";
const OUTBOX_STORE = "outbox";
const SHELL = ["/", "/assets/relay-v2.css", "/assets/relay-v2.js", "/assets/relay-job-detail.css", "/manifest.webmanifest", "/icons/relay.svg"];

self.addEventListener("install", event => {
  event.waitUntil(Promise.all([caches.open(STATIC_CACHE).then(cache => cache.addAll(SHELL)), caches.open(RUNTIME_CACHE)]));
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    await caches.open(RUNTIME_CACHE);
    for (const name of await caches.keys()) {
      if ((name.startsWith("relay-static-2026.09.") && name !== STATIC_CACHE) || (name.startsWith("relay-runtime-2026.09.") && name !== RUNTIME_CACHE)) {
        await caches.delete(name);
      }
    }
    await discardExpiredOutbox();
    await discardSigningKey();
  })());
});

function openOutboxDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(OUTBOX_DB, 4);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(OUTBOX_STORE)) db.createObjectStore(OUTBOX_STORE, { keyPath: "sync_id" });
      if (!db.objectStoreNames.contains("worker-keys")) db.createObjectStore("worker-keys", { keyPath: "id" });
      if (!db.objectStoreNames.contains("report-settings")) db.createObjectStore("report-settings", { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function discardExpiredOutbox() {
  const db = await openOutboxDb();
  const entries = await idbResult(db.transaction(OUTBOX_STORE).objectStore(OUTBOX_STORE).getAll());
  const expired = entries.filter(entry => entry.expires_at_ms && entry.expires_at_ms <= Date.now());
  if (expired.length) {
    const transaction = db.transaction(OUTBOX_STORE, "readwrite");
    for (const entry of expired) transaction.objectStore(OUTBOX_STORE).delete(entry.sync_id);
    await new Promise((resolve, reject) => {
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }
  db.close();
}

async function discardSigningKey() {
  const db = await openOutboxDb();
  if (db.objectStoreNames.contains("worker-keys")) {
    const transaction = db.transaction("worker-keys", "readwrite");
    transaction.objectStore("worker-keys").clear();
    await new Promise((resolve, reject) => {
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }
  db.close();
}

self.addEventListener("message", event => {
  if (!event.ports[0]) return;
  if (event.data?.type === "RELAY_VERSION") {
    event.ports[0].postMessage({ build: BUILD_ID, release_id: RELEASE_ID, script: WORKER_SCRIPT });
  } else if (event.data?.type === "RELAY_OUTBOX_FLUSH") {
    event.ports[0].postMessage({ status: "complete", accepted: 0, remaining: 0, build: BUILD_ID, release_id: RELEASE_ID, script: WORKER_SCRIPT });
  } else if (event.data?.type === "RELAY_OUTBOX_STATUS") {
    event.ports[0].postMessage({ count: 0, build: BUILD_ID, release_id: RELEASE_ID, script: WORKER_SCRIPT });
  }
});

async function networkFirst(request) {
  return fetch(request);
}

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname === "/api/sync/plan" && request.method === "POST") {
    event.respondWith(fetch(request));
    return;
  }
  if (request.method !== "GET") return;

  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request).catch(async () => (await caches.open(STATIC_CACHE)).match("/")));
    return;
  }

  if (url.pathname === "/api/sync/plan") {
    event.respondWith((async () => {
      await discardExpiredOutbox().catch(() => {});
      return fetch(request);
    })());
    return;
  }

  if (url.pathname.startsWith("/assets/") || url.pathname.startsWith("/icons/")) {
    event.respondWith((async () => {
      const cache = await caches.open(STATIC_CACHE);
      return (await cache.match(request)) || fetch(request).then(response => {
        if (response.ok) cache.put(request, response.clone());
        return response;
      });
    })());
  }
});
