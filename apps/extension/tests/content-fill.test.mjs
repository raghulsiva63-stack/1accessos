import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const code = ts.transpileModule(await readFile(new URL('../src/content.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
function page({ origin = 'https://login.example.test', action, autocomplete = 'current-password', hidden = false, disabled = false, topFrame = true } = {}) {
  const sent = [], events = {};
  class Input {
    constructor() { this.storedValue = ''; this.disabled = disabled; this.readOnly = false; this.autocomplete = autocomplete; this.form = null; }
    get value() { return this.storedValue; } set value(value) { this.storedValue = value; }
    getBoundingClientRect() { return { width: 200, height: hidden ? 0 : 40 }; }
    closest() { return null; }
    dispatchEvent() {}
  }
  const password = new Input(), username = new Input();
  class Form { constructor() { this.action = action ?? origin + '/session'; } querySelectorAll(selector) { return selector === 'input[type="password"]' ? [password] : [username]; } }
  const form = new Form(); password.form = form; username.form = form;
  const document = { querySelectorAll: selector => form.querySelectorAll(selector), addEventListener: (name, fn) => { events[name] = fn; } };
  const chrome = { runtime: { id: 'test-extension', async sendMessage(value) { sent.push(value); }, onMessage: { addListener(fn) { events.message = fn; } } } };
  const window = {}; window.top = topFrame ? window : {};
  vm.runInNewContext(code, { document, chrome, window, location: { origin, href: origin + '/login?token=synthetic#fragment', hostname: new URL(origin).hostname, pathname: '/login' }, URL, HTMLInputElement: Input, HTMLFormElement: Form, getComputedStyle: () => ({ visibility: 'visible', display: 'block', opacity: '1' }), Event, exports: {} });
  const fill = (changes = {}, sender = { id: 'test-extension' }) => { let result; events.message({ type: 'PX_FILL', origin, username: 'synthetic-user', secret: 'synthetic-password', ...changes }, sender, value => { result = value; }); return result; };
  return { fill, password, username, sent, submit: () => events.submit({ target: form }) };
}
test('explicit fill reaches a visible current-password form on the exact origin', () => {
  const p = page(); assert.equal(p.fill().ok, true);
  assert.equal(p.password.value, 'synthetic-password'); assert.equal(p.username.value, 'synthetic-user');
});
test('wrong sender, origin, iframe, hidden fields, new password and foreign actions never receive secrets', () => {
  for (const options of [{ topFrame: false }, { hidden: true }, { disabled: true }, { autocomplete: 'new-password' }, { action: 'https://attacker.invalid/collect' }]) {
    const p = page(options); p.fill(); assert.equal(p.password.value, '');
  }
  const p = page(); p.fill({ origin: 'https://attacker.invalid' }); p.fill({}, { id: 'another-extension' }); assert.equal(p.password.value, '');
});
test('save candidates omit query tokens and never capture Passkey-X or iframe passwords', () => {
  const p = page(); p.password.value = 'synthetic-password'; p.submit();
  assert.equal(p.sent.length, 1); assert.equal(p.sent[0].url, 'https://login.example.test/login');
  for (const options of [{ origin: 'https://passkey-x.com' }, { origin: 'https://www.passkey-x.com' }, { topFrame: false }]) {
    const protectedPage = page(options); protectedPage.password.value = 'synthetic-vault-password'; protectedPage.submit(); assert.equal(protectedPage.sent.length, 0);
  }
});
