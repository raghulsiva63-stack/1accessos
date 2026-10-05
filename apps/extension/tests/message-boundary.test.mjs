import assert from 'node:assert/strict';
import test from 'node:test';
import { authorizedExtensionMessage as allowed } from '../src/message-boundary.ts';
const id = 'test-extension-id';
const popup = `chrome-extension://${id}/popup.html`;
const page = { id, url: 'https://example.test/login', frameId: 0, tab: { id: 12, url: 'https://example.test/login' } };
const candidate = { type: 'PX_CANDIDATE', origin: 'https://example.test', url: 'https://example.test/login', username: 'test-user', secret: 'synthetic-password' };
const check = (request, sender = page) => allowed(request, sender, id, popup);

test('only the exact extension popup may execute privileged commands', () => {
  for (const type of ['PX_STATUS','PX_CONNECT','PX_DISCONNECT','PX_UNLOCK','PX_LOCK','PX_SAVE','PX_NEVER','PX_FILL']) {
    assert.equal(check({type}, {id, url: popup}), true);
    assert.equal(check({type}, page), false);
    assert.equal(check({type}, {id, url: popup, tab: {id: 12}}), false);
    assert.equal(check({type}, {id, url: popup + '?injected=1'}), false);
    assert.equal(check({type}, {id: 'other-extension', url: popup}), false);
  }
});
test('accepts only top-frame candidates tied to browser-supplied origins', () => {
  assert.equal(check(candidate), true);
  assert.equal(check(candidate, {...page, tab: {...page.tab, id: 0}}), true);
  for (const sender of [
    {...page, frameId: 1}, {...page, frameId: undefined},
    {...page, url: 'https://attacker.test/'},
    {...page, tab: {id:12,url:'https://attacker.test/'}},
    {...page, id:'other-extension'}, {...page, tab:undefined},
  ]) assert.equal(check(candidate, sender), false);
});
test('rejects payload origin substitution and oversized capture', () => {
  for (const change of [
    {origin:'https://attacker.test'}, {url:'https://attacker.test/'},
    {url:'javascript:void(0)'}, {url:null}, {secret:''},
    {secret:'x'.repeat(65537)}, {username:'x'.repeat(4097)},
    {secret: {}},
  ]) assert.equal(check({...candidate,...change}), false);
});
test('fails closed for unknown and malformed requests', () => {
  for (const request of [null, [], 'PX_FILL', {}, {type:'PX_DECRYPT'}, {type:3}]) {
    assert.equal(check(request, {id,url:popup}), false);
  }
});

const { authorizedPairingMessage } = await import('../src/message-boundary.ts');
const now = 1_000_000;
const nonce = 'a'.repeat(64);
const pending = { nonce, tabId: 7, expiresAt: now + 300_000 };
const sender = { url: 'https://passkey-x.com/extension/connect?extension_id=' + id, frameId: 0, tab: { id: 7 } };
const pair = { type: 'PX_PAIR_SESSION', extensionId: id, nonce, accessToken: 'synthetic-access', refreshToken: 'synthetic-refresh' };
test('pairing accepts only a live one-use request in its originating top-level tab', () => {
  assert.equal(authorizedPairingMessage(pair, sender, id, pending, now), true);
  for (const changed of [undefined, {...pending, expiresAt:now}, {...pending, expiresAt:now+300001}, {...pending, nonce:'b'.repeat(64)}, {...pending, tabId:8}]) {
    assert.equal(authorizedPairingMessage(pair, sender, id, changed, now), false);
  }
});
test('pairing rejects lookalike hosts, HTTP, other routes, iframes and unsolicited tokens', () => {
  for (const url of ['http://passkey-x.com/extension/connect', 'https://passkey-x.com.evil.test/extension/connect', 'https://evil.test/extension/connect', 'https://www.passkey-x.com/extension/connect', 'https://passkey-x.com/', 'https://passkey-x.com:444/extension/connect']) {
    assert.equal(authorizedPairingMessage(pair, {...sender,url}, id, pending, now), false);
  }
  for (const change of [{frameId:1},{frameId:undefined},{tab:undefined},{tab:{id:8}}]) assert.equal(authorizedPairingMessage(pair, {...sender,...change}, id, pending, now), false);
  for (const change of [{extensionId:'attacker'}, {nonce:''}, {type:'PX_FILL'}, {accessToken:''}, {refreshToken:'x'.repeat(16385)}]) assert.equal(authorizedPairingMessage({...pair,...change}, sender, id, pending, now), false);
});
test('Guard: only the warning page in a tab may leave, proceed or dispute', () => {
  const warning = `chrome-extension://${id}/warning.html`;
  const fromWarning = { id, url: `${warning}#%7B%7D`, frameId: 0, tab: { id: 12, url: `${warning}#%7B%7D` } };
  for (const type of ['PX_GUARD_LEAVE', 'PX_GUARD_PROCEED', 'PX_GUARD_DISPUTE']) {
    assert.equal(allowed({ type }, fromWarning, id, popup, warning), true);
    assert.equal(allowed({ type }, fromWarning, id, popup), false, 'no warning page configured');
    assert.equal(allowed({ type }, { ...fromWarning, url: popup }, id, popup, warning), false);
    assert.equal(allowed({ type }, { ...fromWarning, url: `${warning}x` }, id, popup, warning), false);
    assert.equal(allowed({ type }, { ...fromWarning, tab: undefined }, id, popup, warning), false);
    assert.equal(allowed({ type }, { ...fromWarning, frameId: 2 }, id, popup, warning), false);
    assert.equal(allowed({ type }, page, id, popup, warning), false);
    assert.equal(allowed({ type }, { id, url: popup }, id, popup, warning), false);
  }
});
test('Guard: page context comes only from the top frame of the page it describes', () => {
  const context = { type: 'PX_PAGE_CONTEXT', origin: 'https://example.test', hasPasswordField: true };
  assert.equal(check(context), true);
  assert.equal(check({ ...context, origin: 'https://other.test' }), false);
  assert.equal(check({ ...context, hasPasswordField: 'yes' }), false);
  assert.equal(check(context, { ...page, frameId: 1 }), false);
  assert.equal(check(context, { id, url: popup }), false);
  for (const type of ['PX_GUARD_STATUS', 'PX_REPORT_PHISHING']) {
    assert.equal(check({ type }, { id, url: popup }), true);
    assert.equal(check({ type }, page), false);
  }
});
