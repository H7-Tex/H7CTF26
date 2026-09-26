/* Relay's offline adapter for field clients using the original sync contract. */
const BUILD_ID = "2026.09.24.1";
const RELEASE_ID = "__RELEASE_ID__";
const WORKER_SCRIPT = "/sw-2026.09.24.1.js";
const STATIC_CACHE = `relay-static-2026.09.${RELEASE_ID}`;
const RUNTIME_CACHE = `relay-runtime-2026.09.${RELEASE_ID}`;
const OUTBOX_DB = "relay-offline-outbox";
const OUTBOX_STORE = "outbox";
const KEY_STORE = "worker-keys";
const SETTINGS_STORE = "report-settings";
const SIGNING_KEY_ID = "relay-p256-signing-key";
const SHELL = ["/", "/assets/relay-v1.css", "/assets/relay-v1.js", "/assets/relay-job-detail.css", "/assets/contracts/report-package-v1.json", "/manifest.webmanifest", "/icons/relay.svg"];
const encoder = new TextEncoder();

self.addEventListener("install", event => {
  event.waitUntil(Promise.all([
    caches.open(STATIC_CACHE).then(cache => cache.addAll(SHELL)),
    caches.open(RUNTIME_CACHE),
    ensureSigningKey(),
  ]));
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    await self.clients.claim();
    await registerPublicKey();
  })());
});

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(OUTBOX_DB, 4);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(OUTBOX_STORE)) db.createObjectStore(OUTBOX_STORE, { keyPath: "sync_id" });
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE, { keyPath: "id" });
      if (!db.objectStoreNames.contains(SETTINGS_STORE)) db.createObjectStore(SETTINGS_STORE, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function keyRecord() {
  const db = await openDb();
  const result = await requestResult(db.transaction(KEY_STORE).objectStore(KEY_STORE).get(SIGNING_KEY_ID));
  db.close();
  return result || null;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function ensureSigningKey() {
  const existing = await keyRecord();
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  if (pair.privateKey.extractable) throw new Error("offline signing key must remain non-extractable");
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const thumbprint = { crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x, y: publicKey.y };
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canonicalJson(thumbprint)));
  const record = { id: SIGNING_KEY_ID, key_id: base64url(new Uint8Array(digest)), private_key: pair.privateKey, public_key: publicKey };
  const db = await openDb();
  const transaction = db.transaction(KEY_STORE, "readwrite");
  transaction.objectStore(KEY_STORE).put(record);
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
  return record;
}

async function registerPublicKey() {
  const record = await ensureSigningKey();
  const response = await fetch("/api/sync/worker-key", {
    method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_id: record.key_id, public_key: record.public_key }),
  });
  if (!response.ok) throw new Error(`worker key registration failed: ${response.status}`);
  return record;
}

function openOutbox() { return openDb(); }

async function savedReportPackage() {
  const db = await openDb();
  const value = await requestResult(db.transaction(SETTINGS_STORE).objectStore(SETTINGS_STORE).get("report-package"));
  db.close();
  return value || null;
}

async function storeReportPackage(profile, revision) {
  if (!["summary", "record", "complete"].includes(profile) || !Number.isInteger(revision) || revision < 1) {
    throw new Error("report setting could not be stored");
  }
  const db = await openDb();
  const transaction = db.transaction(SETTINGS_STORE, "readwrite");
  transaction.objectStore(SETTINGS_STORE).put({ id: "report-package", profile, revision, saved_at: Date.now() });
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
}

async function persistOutbox(envelope) {
  const db = await openOutbox();
  const transaction = db.transaction(OUTBOX_STORE, "readwrite");
  const expiresAt = envelope.expires_at || envelope.source_plan?.expires_at;
  transaction.objectStore(OUTBOX_STORE).put({ sync_id: envelope.sync_id, envelope, expires_at_ms: expiresAt ? expiresAt * 1000 : null, queued_at: Date.now() });
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
}

async function saveReconciliationReceipt(syncId, receipt) {
  if (!receipt) return;
  const db = await openOutbox();
  const transaction = db.transaction(OUTBOX_STORE, "readwrite");
  const store = transaction.objectStore(OUTBOX_STORE);
  const entry = await requestResult(store.get(syncId));
  if (entry) store.put({ ...entry, reconciliation_receipt: receipt });
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
}

async function readOutbox() {
  const db = await openOutbox();
  const entries = await requestResult(db.transaction(OUTBOX_STORE).objectStore(OUTBOX_STORE).getAll());
  db.close();
  return entries;
}

async function removeOutbox(syncId) {
  const db = await openOutbox();
  const transaction = db.transaction(OUTBOX_STORE, "readwrite");
  transaction.objectStore(OUTBOX_STORE).delete(syncId);
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
}

async function scheduleBackgroundReplay() {
  try { await self.registration.sync?.register("relay-offline-replay"); } catch (_) { /* retry is available only after an explicit replay attempt */ }
}

async function stageQueuedDelivery(envelope) {
  if (!envelope.source_plan) return null;
  const response = await fetch("/api/sync/outbox", {
    method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ envelope }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.detail?.message || body.detail || `queued update deferred: ${response.status}`);
    error.status = response.status;
    error.code = body.detail?.code || null;
    throw error;
  }
  const result = await response.json().catch(() => ({}));
  await saveReconciliationReceipt(envelope.sync_id, result.reconciliation_receipt);
  return result;
}

async function normalizeDelivery(plan, response) {
  if (!plan.delivery && !plan.report_package?.scope) return plan;
  const deliveredFields = { ...plan, ...(plan.delivery || {}) };
  const storedPreference = await savedReportPackage();
  if (!storedPreference?.revision) throw new Error("saved package setting is unavailable");
  const packageScope = storedPreference.profile || plan.report_package?.scope || "summary";
  const sourceContract = response.headers.get("X-Semantic-Contract") || plan.contract || null;
  const envelope = {
    ...deliveredFields,
    schema_version: 1,
    state: deliveredFields.state || "pending-sync",
    sync_id: deliveredFields.sync_id || deliveredFields.operation_id,
    operation_id: deliveredFields.operation_id,
    persistence: deliveredFields.persistence || "outbox",
    source_release: response.headers.get("X-Release-Id") || "unknown",
    source_contract: sourceContract,
    source_delivery: plan.delivery || null,
    source_plan: plan,
    package_preference_revision: storedPreference.revision,
    report_package: { contract: "relay.report-package/v1", profile: packageScope },
  };
  return envelope;
}

async function inspectSyncPlan(response) {
  const plan = await response.clone().json();
  const envelope = await normalizeDelivery(plan, response);
  if (envelope.state === "pending-sync" && envelope.persistence === "outbox" && envelope.sync_id) {
    await persistOutbox(envelope);
    try { await stageQueuedDelivery(envelope); } catch (_) { /* retry from the durable outbox */ }
  }
  return response;
}

async function signAndReplay(entry) {
  const record = await keyRecord();
  if (!record) throw new Error("offline signing key is unavailable");
  const authoritative = await fetch("/api/sync/plan", { cache: "no-store" });
  if (!authoritative.ok) throw new Error("dispatch plan is not available for replay");
  const expectedEnvelope = await normalizeDelivery(await authoritative.clone().json(), authoritative);
  if (canonicalJson(expectedEnvelope) !== canonicalJson(entry.envelope)) {
    throw new Error("queued sync data no longer matches the saved dispatch plan");
  }
  const signed = { key_id: record.key_id, envelope: expectedEnvelope };
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, record.private_key, encoder.encode(canonicalJson(signed)));
  const response = await fetch("/api/sync/replay", {
    method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...signed, signature: base64url(new Uint8Array(signature)) }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.detail?.message || body.detail || `queued update deferred: ${response.status}`);
    error.status = response.status;
    error.code = body.detail?.code || null;
    throw error;
  }
  await removeOutbox(entry.sync_id);
  return response.json();
}

let replayTask = null;

async function replayOutbox() {
  if (replayTask) return replayTask;
  replayTask = replayPending();
  try { return await replayTask; }
  finally { replayTask = null; }
}

async function replayPending() {
  const results = [];
  let expired = 0;
  while (true) {
    const entries = await readOutbox();
    if (!entries.length) return { accepted: results.length, expired, remaining: 0, status: "complete" };
    if (self.navigator.onLine === false) {
      await scheduleBackgroundReplay();
      return { accepted: results.length, expired, remaining: entries.length, status: "deferred" };
    }
    for (const entry of entries) {
      if (entry.expires_at_ms && entry.expires_at_ms <= Date.now()) {
        await removeOutbox(entry.sync_id);
        expired += 1;
        continue;
      }
      try {
        await stageQueuedDelivery(entry.envelope);
        results.push(await signAndReplay(entry));
      } catch (error) {
        if ((error.status === 410 && error.code === "operation_expired")
            || (error.status === 409 && ["operation_consumed", "operation_invalidated"].includes(error.code))) {
          await removeOutbox(entry.sync_id);
          expired += 1;
          continue;
        }
        if (!error.status || error.status >= 500) await scheduleBackgroundReplay();
        return { accepted: results.length, expired, remaining: (await readOutbox()).length, status: "deferred" };
      }
    }
  }
}

self.addEventListener("message", event => {
  const port = event.ports[0];
  if (!port) return;
  if (event.data?.type === "RELAY_VERSION") {
    port.postMessage({ build: BUILD_ID, release_id: RELEASE_ID, script: WORKER_SCRIPT });
    return;
  }
  if (event.data?.type === "RELAY_KEY_STATUS") {
    event.waitUntil((async () => {
      const key = await keyRecord();
      port.postMessage({ available: Boolean(key), key_id: key?.key_id || null, private_key_extractable: key?.private_key?.extractable ?? null });
    })());
    return;
  }
  if (event.data?.type === "RELAY_REPORT_PACKAGE_SAVE") {
    event.waitUntil(storeReportPackage(event.data.profile, event.data.revision)
      .then(() => port.postMessage({ status: "saved" }))
      .catch(() => port.postMessage({ status: "unavailable" })));
    return;
  }
  if (event.data?.type === "RELAY_OUTBOX_STATUS") {
    event.waitUntil(readOutbox().then(entries => port.postMessage({
      count: entries.length,
      reconciliation_receipt: entries.find(entry => entry.reconciliation_receipt)?.reconciliation_receipt || null,
      build: BUILD_ID, release_id: RELEASE_ID, script: WORKER_SCRIPT,
    })));
    return;
  }
  if (event.data?.type === "RELAY_OUTBOX_FLUSH") event.waitUntil(replayOutbox().then(result => port.postMessage(result)));
});

self.addEventListener("sync", event => {
  if (event.tag === "relay-offline-replay") event.waitUntil(replayOutbox());
});

async function networkFirst(request) { return fetch(request); }

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  const syncPlanPost = url.pathname === "/api/sync/plan" && request.method === "POST";
  if (url.origin !== self.location.origin || (request.method !== "GET" && !syncPlanPost)) return;
  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request).catch(async () => (await caches.open(STATIC_CACHE)).match("/")));
    return;
  }
  if (url.pathname === "/api/sync/plan" && ["GET", "POST"].includes(request.method)) {
    event.respondWith(fetch(request).then(inspectSyncPlan).catch(() => new Response(JSON.stringify({ offline: true }), { status: 503, headers: { "Content-Type": "application/json" } })));
    return;
  }
  if (["/api/jobs", "/api/activity", "/api/drafts"].includes(url.pathname)) {
    event.respondWith(networkFirst(request).then(async response => {
      if (response.ok) await (await caches.open(RUNTIME_CACHE)).put(request, response.clone());
      return response;
    }).catch(async () => (await caches.open(RUNTIME_CACHE)).match(request) || new Response(JSON.stringify({ items: [] }), { headers: { "Content-Type": "application/json" } })));
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
