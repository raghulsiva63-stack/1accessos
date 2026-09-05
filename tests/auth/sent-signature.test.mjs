import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { registerHooks } from 'node:module';
import { test, after } from 'node:test';

// Execute the real Edge helper under Node; database access is forbidden here.
const hook = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'npm:@supabase/supabase-js@2.115.0') {
      return { shortCircuit: true, url: 'data:text/javascript,export function createClient(){throw new Error("Unexpected database access")}' };
    }
    return nextResolve(specifier, context);
  },
});
const environment = new Map();
const previousDeno = globalThis.Deno;
globalThis.Deno = { env: { get: (name) => environment.get(name) } };
const { verifySentWebhook, safeCode } = await import('../../supabase/functions/_shared/sent.ts');
after(() => { hook.deregister(); if (previousDeno === undefined) delete globalThis.Deno; else globalThis.Deno = previousDeno; });
const secret = Buffer.alloc(32, 7);
const rotated = Buffer.alloc(32, 8);
const body = new TextEncoder().encode('{"field":"message","event":"message.delivered"}');
function configured() {
  environment.clear();
  environment.set('SENT_DM_WEBHOOK_SECRET', `whsec_${secret.toString('base64')}`);
}
function signed(key = secret, seconds = Math.floor(Date.now() / 1000)) {
  const id = 'test-delivery-001';
  const signature = createHmac('sha256', key).update(`${id}.${seconds}.`).update(body).digest('base64');
  return new Headers({ 'x-webhook-id': id, 'x-webhook-timestamp': String(seconds), 'x-webhook-signature': `v1,${signature}` });
}
test('accepts a valid independently signed raw payload', async () => {
  configured(); await verifySentWebhook(signed(), body);
});
test('rejects body, identifier, and signature tampering', async () => {
  configured();
  await assert.rejects(verifySentWebhook(signed(), new TextEncoder().encode('{}')), /invalid_signature/);
  const changedId = signed(); changedId.set('x-webhook-id', 'other-event');
  await assert.rejects(verifySentWebhook(changedId, body), /invalid_signature/);
  await assert.rejects(verifySentWebhook(signed(rotated), body), /invalid_signature/);
});
test('rejects signatures older than five minutes and future-dated signatures', async () => {
  configured();
  const now = Math.floor(Date.now() / 1000);
  for (const timestamp of [now - 301, now + 600]) {
    await assert.rejects(verifySentWebhook(signed(secret, timestamp), body), /stale_signature/);
  }
});
test('rejects missing, malformed, and unsupported signature headers', async () => {
  configured();
  for (const name of ['x-webhook-id', 'x-webhook-timestamp', 'x-webhook-signature']) {
    const headers = signed(); headers.delete(name);
    await assert.rejects(verifySentWebhook(headers, body), /invalid_signature/);
  }
  for (const value of ['v2,AAAA', 'v1,!!!', 'v1,AAAA']) {
    const headers = signed(); headers.set('x-webhook-signature', value);
    await assert.rejects(verifySentWebhook(headers, body), /invalid_signature/);
  }
  const headers = signed(); headers.set('x-webhook-timestamp', 'not-a-time');
  await assert.rejects(verifySentWebhook(headers, body), /stale_signature/);
});
test('accepts previous key only during the configured rotation window', async () => {
  configured();
  environment.set('SENT_DM_WEBHOOK_SECRET', `whsec_${rotated.toString('base64')}`);
  environment.set('SENT_DM_WEBHOOK_SECRET_PREVIOUS', `whsec_${secret.toString('base64')}`);
  await verifySentWebhook(signed(), body);
  await verifySentWebhook(signed(rotated), body);
  environment.delete('SENT_DM_WEBHOOK_SECRET_PREVIOUS');
  await assert.rejects(verifySentWebhook(signed(), body), /invalid_signature/);
});
test('fails closed without configured signing keys', async () => {
  environment.clear();
  await assert.rejects(verifySentWebhook(signed(), body), /webhook_not_configured/);
});
test('does not expose provider error text through public error codes', () => {
  assert.equal(safeCode(new Error('provider returned confidential payload')), 'provider_unavailable');
  assert.equal(safeCode(new Error('missing:SENT_DM_API_KEY')), 'sms_not_configured');
  assert.equal(safeCode(new Error('invalid_signature')), 'invalid_signature');
});
