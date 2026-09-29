import assert from 'node:assert/strict';
import test from 'node:test';
import { watchVaultLifetime } from '../lib/browser/vault-lifecycle.ts';

function target() {
  const handlers = new Map();
  return {
    hidden: false,
    addEventListener(name, fn) { if (!handlers.has(name)) handlers.set(name, new Set()); handlers.get(name).add(fn); },
    removeEventListener(name, fn) { handlers.get(name)?.delete(fn); },
    emit(name, event = {}) { for (const fn of handlers.get(name) ?? []) fn(event); },
  };
}
function harness(options = {}) {
  const doc = target(), win = target(), timers = new Map();
  let time = 0, locks = 0, id = 0;
  const dispose = watchVaultLifetime({ ...options, documentObject: doc, windowObject: win, onLock: () => locks++, now: () => time,
    schedule(fn, delay) { const key = ++id; timers.set(key, { fn, at: time + delay }); return key; },
    cancel(key) { timers.delete(key); },
  });
  function advance(ms) {
    time += ms;
    for (const [key, timer] of [...timers]) if (timer.at <= time) { timers.delete(key); timer.fn(); }
  }
  return { doc, win, dispose, advance, count: () => locks, timers, jump: value => { time = value; } };
}
test('background, page close, freeze and update each lock once', () => {
  for (const [source, name] of [['doc','visibilitychange'], ['doc','freeze'], ['win','pagehide'], ['win','passkey-x:lock']]) {
    const h = harness(); if (name === 'visibilitychange') h.doc.hidden = true;
    h[source].emit(name); assert.equal(h.count(), 1);
    h.doc.hidden = false; h.doc.emit('visibilitychange'); h.win.emit('pagehide'); h.advance(600000);
    assert.equal(h.count(), 1); h.dispose();
  }
});
test('trusted input extends the idle deadline, synthetic input does not', () => {
  const h = harness(); h.advance(240000); h.doc.emit('pointerdown', { isTrusted: true });
  h.advance(60000); assert.equal(h.count(), 0);
  h.doc.emit('keydown', { isTrusted: false }); h.advance(240000); assert.equal(h.count(), 1);
});
test('an event after suspended timers cannot revive an expired vault', () => {
  const h = harness(); h.jump(600000); h.doc.emit('pointerdown', { isTrusted: true }); assert.equal(h.count(), 1);
});
test('clock rollback and lifecycle cleanup cannot extend access', () => {
  const h = harness(); h.jump(-1); h.doc.emit('pointerdown', { isTrusted: true }); assert.equal(h.count(), 1);
  const clean = harness(); clean.dispose(); clean.win.emit('pagehide'); clean.advance(600000); assert.equal(clean.count(), 0); assert.equal(clean.timers.size, 0);
});

test('desktop mode keeps a hidden window unlocked only until the idle limit', () => {
  const h = harness({ lockWhenHidden: false, idleMs: 1000 });
  h.doc.hidden = true; h.doc.emit('visibilitychange');
  assert.equal(h.count(), 0);
  h.advance(999); assert.equal(h.count(), 0);
  h.advance(1); assert.equal(h.count(), 1);
  const lockEvent = harness({ lockWhenHidden: false });
  lockEvent.win.emit('passkey-x:lock'); assert.equal(lockEvent.count(), 1);
});
