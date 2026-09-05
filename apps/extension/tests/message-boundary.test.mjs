import assert from 'node:assert/strict';
import test from 'node:test';
import { authorizedExtensionMessage as allowed } from '../src/message-boundary.ts';
const id = 'test-extension-id';
const popup = `chrome-extension://${id}/popup.html`;
const page = { id, url: 'https://example.test/login', frameId: 0, tab: { id: 12, url: 'https://example.test/login' } };
const candidate = { type: 'PX_CANDIDATE', origin: 'https://example.test', url: 'https://example.test/login', username: 'test-user', secret: 'synthetic-password' };
const check = (request, sender = page) => allowed(request, sender, id, popup);

test('only the exact extension popup may execute privileged commands', () => {
  for (const type of ['PX_STATUS','PX_UNLOCK','PX_LOCK','PX_SAVE','PX_NEVER','PX_FILL']) {
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
