import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  acknowledgeBreaches, applyBreachResults, breachCheckDue, EMPTY_BREACH_WATCH, parseBreachWatch,
  recallBreachResults, rememberBreachResults, forgetBreachResults,
} from "../../apps/web/lib/enterprise/breach-watch.ts";
import { buildFixQueue, changePasswordUrl } from "../../apps/web/lib/vault/change-password.ts";

const DAY = 86_400_000;

test("Breach Watch is opt-in and tolerates bad stored data", () => {
  assert.equal(parseBreachWatch(null).enabled, false);
  assert.equal(parseBreachWatch("{not json").enabled, false);
  assert.deepEqual(parseBreachWatch('{"enabled":true,"lastCheckedAt":"nope","known":[1,"a"],"fresh":"x"}'),
    { enabled: true, lastCheckedAt: null, known: ["a"], fresh: [] });
  assert.equal(breachCheckDue(EMPTY_BREACH_WATCH), false);
});

test("checks are due weekly once turned on", () => {
  const now = Date.parse("2026-10-10T00:00:00Z");
  const on = { ...EMPTY_BREACH_WATCH, enabled: true };
  assert.equal(breachCheckDue(on, now), true);
  assert.equal(breachCheckDue({ ...on, lastCheckedAt: new Date(now - 6 * DAY).toISOString() }, now), false);
  assert.equal(breachCheckDue({ ...on, lastCheckedAt: new Date(now - 7 * DAY).toISOString() }, now), true);
});

test("only newly breached passwords raise a fresh alert", () => {
  const now = Date.parse("2026-10-10T00:00:00Z");
  let state = applyBreachResults({ ...EMPTY_BREACH_WATCH, enabled: true }, new Map([["a", 3], ["b", 0]]), ["a", "b"], now);
  assert.deepEqual(state.known, ["a"]);
  assert.deepEqual(state.fresh, ["a"]);
  state = acknowledgeBreaches(state);
  state = applyBreachResults(state, new Map([["a", 3], ["b", 9], ["gone", 5]]), ["a", "b"], now + 7 * DAY);
  assert.deepEqual(state.known, ["a", "b"]);
  assert.deepEqual(state.fresh, ["b"]);
  // Changing the password clears it from both lists.
  state = applyBreachResults(state, new Map([["a", 3], ["b", 0]]), ["a", "b"], now + 14 * DAY);
  assert.deepEqual(state.fresh, []);
  assert.equal(state.lastCheckedAt, new Date(now + 14 * DAY).toISOString());
});

test("latest results are shared in memory only and cleared on lock", () => {
  rememberBreachResults("t1", new Map([["a", 1]]));
  assert.equal(recallBreachResults("t1")?.get("a"), 1);
  assert.equal(recallBreachResults(null), undefined);
  forgetBreachResults();
  assert.equal(recallBreachResults("t1"), undefined);
});

test("change-password links use the well-known address on https sites only", () => {
  assert.equal(changePasswordUrl("https://accounts.example.com/login?next=/"), "https://accounts.example.com/.well-known/change-password");
  assert.equal(changePasswordUrl("example.com"), "https://example.com/.well-known/change-password");
  assert.equal(changePasswordUrl("http://example.com"), null);
  assert.equal(changePasswordUrl("javascript:alert(1)"), null);
  assert.equal(changePasswordUrl("intranet"), null);
  assert.equal(changePasswordUrl(""), null);
});

test("fix queue orders breached, then reused, then weak, once per item", () => {
  const item = (id, title, secret = "x", url) => ({ id, payload: { title, secret, url } });
  const items = [item("w", "Weak site"), item("r1", "Reused B"), item("r2", "Reused A"), item("b", "Breached", "x", "https://b.example"), item("n", "No secret", "")];
  const queue = buildFixQueue(items, { breached: ["b", "r1"], reused: [["r1", "r2"]], weak: ["w", "b", "n"] });
  assert.deepEqual(queue.map((task) => task.itemId), ["b", "r1", "r2", "w"]);
  assert.deepEqual(queue[0].reasons, ["breached", "weak"]);
  assert.equal(queue[0].changeUrl, "https://b.example/.well-known/change-password");
  assert.equal(queue[3].changeUrl, null);
});

test("Home and Security are wired to Breach Watch and the fix queue", async () => {
  const page = await readFile("apps/web/app/page.tsx", "utf8");
  const card = await readFile("apps/web/components/app/breach-watch.tsx", "utf8");
  const center = await readFile("apps/web/components/enterprise/security-center.tsx", "utf8");
  assert.match(page, /<BreachWatchCard key=\{tenantId \?\? "none"\} identityId=\{identityId\} tenantId=\{tenantId\}/);
  assert.match(page, /function lockVault\(\) \{ clearPendingClipboard\(\); forgetBreachResults\(\);/);
  assert.match(page, /onRotate=\{\(id\) => \{ const item = items\.find/);
  assert.match(center, /<FixQueue tasks=\{buildFixQueue\(items, report\)\}/);
  assert.match(card, /policy\.breachMonitoring === "off"\) return null/);
  assert.doesNotMatch(card, /localStorage\.setItem\([^)]*secret/);
});
