import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');
function worker({ offline = false } = {}) {
  const handlers = {}, stored = new Map(), deleted = [];
  let claimed = false, activated = false;
  const cache = { async addAll(urls) { for (const url of urls) stored.set(url, new Response('public:' + url)); }, async match(url) { return stored.get(url)?.clone(); } };
  const self = { location: { origin: 'https://passkey-x.com' }, clients: { async claim() { claimed = true; } }, async skipWaiting() { activated = true; }, addEventListener(name, fn) { handlers[name] = fn; } };
  vm.runInNewContext(source, { self, URL, Response,
    caches: { async open() { return cache; }, async keys() { return ['passkey-x-offline-old', 'unrelated-cache']; }, async delete(name) { deleted.push(name); } },
    async fetch(request) { if (offline) throw new Error('offline'); return new Response('network:' + request.url); },
  });
  async function lifecycle(name) { let work; handlers[name]({ waitUntil(promise) { work = promise; } }); await work; }
  async function request(path, options = {}) {
    let response;
    handlers.fetch({ request: { url: new URL(path, self.location.origin).href, method: 'GET', mode: 'navigate', headers: new Headers(), ...options }, respondWith(value) { response = value; } });
    return response ? (await response).text() : null;
  }
  return { handlers, stored, deleted, lifecycle, request, activated: () => activated, claimed: () => claimed };
}
test('installation caches only a public fallback and two icons', async () => {
  const h = worker(); await h.lifecycle('install');
  assert.deepEqual([...h.stored.keys()].sort(), ['/offline.html', '/favicon.png', '/brand/passkey-x-app-icon.png'].sort());
  await h.lifecycle('activate'); assert.deepEqual(h.deleted, ['passkey-x-offline-old']); assert.equal(h.claimed(), true);
});
test('online app and pairing navigation always use the network and never enter cache', async () => {
  const h = worker(); await h.lifecycle('install');
  for (const path of ['/', '/#access', '/extension/connect?extension_id=synthetic']) assert.match(await h.request(path), /^network:/);
  assert.equal(h.stored.size, 3);
});
test('API, authenticated, mutation and cross-origin requests are untouched', async () => {
  const h = worker({ offline: true }); await h.lifecycle('install');
  for (const [path, options] of [
    ['/api/v1/vault-items', {}], ['/anything', { method: 'POST' }],
    ['https://example.invalid/auth/v1/token', {}], ['/private', { headers: new Headers({ Authorization: 'Bearer synthetic' }) }],
    ['/_next/static/app.js', { mode: 'cors' }],
  ]) assert.equal(await h.request(path, options), null);
});
test('offline navigation shows the public locked screen without storing the URL', async () => {
  const h = worker({ offline: true }); await h.lifecycle('install');
  assert.equal(await h.request('/?sensitive=synthetic'), 'public:/offline.html'); assert.equal(h.stored.size, 3);
});
test('worker updates require a same-origin window request', () => {
  const h = worker();
  for (const source of [undefined, { type: 'window', url: 'https://evil.invalid/' }, { type: 'worker', url: 'https://passkey-x.com/' }]) {
    h.handlers.message({ data: { type: 'PX_ACTIVATE_UPDATE' }, source }); assert.equal(h.activated(), false);
  }
  h.handlers.message({ data: { type: 'PX_ACTIVATE_UPDATE' }, source: { type: 'window', url: 'https://passkey-x.com/' } }); assert.equal(h.activated(), true);
});
