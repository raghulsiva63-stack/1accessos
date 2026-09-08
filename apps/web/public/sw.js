/* Only public offline assets enter this cache. Account, API and vault responses
 * always use the network; no credentials, encrypted vault snapshots or HTML app
 * sessions are persisted by this worker. */
const CACHE = "passkey-x-offline-v1";
const PUBLIC_ASSETS = ["/offline.html", "/favicon.png", "/brand/passkey-x-app-icon.png"];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(PUBLIC_ASSETS)));
});
self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key.startsWith("passkey-x-offline-") && key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});
self.addEventListener("message", event => {
  if (event.data?.type === "PX_ACTIVATE_UPDATE" && event.source?.type === "window" && new URL(event.source.url).origin === self.location.origin) void self.skipWaiting();
});
self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/") || request.headers.has("authorization")) return;
  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(async () => {
      const cached = await (await caches.open(CACHE)).match("/offline.html");
      return cached ?? new Response("You are offline. Reconnect to open Passkey-X.", { status: 503, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } });
    }));
  } else if (!url.search && PUBLIC_ASSETS.includes(url.pathname)) {
    event.respondWith(caches.open(CACHE).then(async cache => (await cache.match(url.pathname)) ?? fetch(request)));
  }
});
