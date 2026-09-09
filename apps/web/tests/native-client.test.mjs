import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveClientMode } from '../lib/browser/client-mode.ts';
import { nativeRequest, validNativeContext } from '../lib/browser/native-autofill.ts';

test('entry routes, legacy launches and installed mode select the intended interface', () => {
  assert.equal(resolveClientMode('/', '', false, false), 'web');
  assert.equal(resolveClientMode('/', '#access', false, false), 'login');
  assert.equal(resolveClientMode('/login', '', false, false), 'login');
  assert.equal(resolveClientMode('/', '#access', true, false), 'mobile');
  assert.equal(resolveClientMode('/', '#access', false, true), 'desktop');
  for (const client of ['mobile', 'desktop', 'android']) assert.equal(resolveClientMode(`/app/${client}`, '', false, false), client);
  assert.equal(resolveClientMode('/app/android.attacker', '', false, false), 'web');
});

test('native context rejects expired, unbounded and malformed credential requests', () => {
  const now = Date.now();
  const valid = { id: crypto.randomUUID(), kind: 'save', packageName: 'com.example.app', appLabel: 'Example', expiresAt: now + 100_000, username: 'uat-user', password: 'synthetic-example' };
  assert.ok(validNativeContext(valid, now));
  for (const changes of [{ expiresAt: now }, { expiresAt: now + 300_000 }, { expiresAt: NaN }, { id: '../../operation' }, { packageName: 'https://bank.test' }, { password: '' }, { password: 'x'.repeat(4097) }, { username: 123 }, { kind: 'export' }]) assert.equal(validNativeContext({ ...valid, ...changes }, now), false);
});

test('native replies are bound to their request, including out-of-order concurrent replies', async () => {
  const sent = [];
  const previous = globalThis.window;
  globalThis.window = { location: { origin: 'https://passkey-x.com' }, PasskeyXNative: { onmessage: null, postMessage(raw) { sent.push(JSON.parse(raw)); } } };
  try {
    const first = nativeRequest('status'); const second = nativeRequest('context');
    const reply = (requestId, data) => window.PasskeyXNative.onmessage({ data: JSON.stringify({ requestId, data }) });
    reply('unknown-id', 'untrusted'); reply(sent[1].requestId, 'second'); reply(sent[0].requestId, 'first');
    assert.equal(await first, 'first'); assert.equal(await second, 'second');
    window.location.origin = 'https://passkey-x.com.attacker.test';
    await assert.rejects(nativeRequest('context'), /installed Android app/u);
  } finally { if (previous === undefined) delete globalThis.window; else globalThis.window = previous; }
});
