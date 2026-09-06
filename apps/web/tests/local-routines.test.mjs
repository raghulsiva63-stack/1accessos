import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
const root = fileURLToPath(new URL("..", import.meta.url));
const vite = await createServer({ appType: "custom", configFile: false, root, resolve: { alias: { "@": root } }, server: { middlewareMode: true, hmr: false } });
after(async () => vite.close());
const routines = await vite.ssrLoadModule("/lib/automations/local.ts");
const tools = await vite.ssrLoadModule("/lib/vault/tools.ts");
const now = Date.parse("2026-09-05T12:00:00Z"), day = 86_400_000;
function item(id, secret, extras = {}) { return { id, contentType: "login", revision: 1, deletedAt: null, payload: { version: 1, title: `Private ${id}`, secret, updatedAt: new Date(now).toISOString() }, ...extras }; }
function enabled() { const p = routines.parsePreferences(null, now); for (const id of Object.keys(p)) p[id].enabled = true; return p; }

test("preferences are isolated by identity, tenant and workspace, including delimiters", () => {
  const key = routines.preferenceKey;
  assert.equal(new Set([key("a", "b", "c"), key("x", "b", "c"), key("a", "x", "c"), key("a", "b", "x"), key("a:b", "c", "d"), key("a", "b:c", "d")]).size, 6);
});
test("damaged, oversized and unversioned preferences fail safely", () => {
  for (const raw of [null, "{", "null", "[]", '"text"', '[]'.repeat(3000), JSON.stringify({ version: 2, recipes: enabled() })]) {
    assert.deepEqual(routines.parsePreferences(raw, now), routines.parsePreferences(null, now));
  }
});
test("preference validation rejects future times and truthy non-boolean switches", () => {
  const parsed = routines.parsePreferences(JSON.stringify({ version: 1, recipes: { "weekly-health": { enabled: "yes", reviewedAt: now + 1 }, "device-review": { enabled: true, reviewedAt: -1 } } }), now);
  assert.deepEqual(parsed["weekly-health"], { enabled: false, reviewedAt: 0 });
  assert.deepEqual(parsed["device-review"], { enabled: true, reviewedAt: 0 });
});
test("persistence allowlists switches and timestamps without vault content", () => {
  const p = enabled(); p["weekly-health"].secret = "must-not-persist"; p.findings = ["Private title"];
  const serialized = routines.serializePreferences(p, now);
  assert.doesNotMatch(serialized, /must-not-persist|Private title|findings|secret/);
  assert.deepEqual(routines.parsePreferences(serialized, now), enabled());
});
test("enabled routines are due immediately and recur only after their review interval", () => {
  const p = enabled(); assert.equal(routines.dueReminders([], p, now).length, 3);
  for (const id of Object.keys(p)) p[id].reviewedAt = now;
  assert.equal(routines.dueReminders([], p, now + 7 * day - 1).length, 0);
  assert.deepEqual(routines.dueReminders([], p, now + 7 * day).map(r => r.id), ["weekly-health", "stale-passwords"]);
  assert.equal(routines.dueReminders([], p, now + 30 * day).length, 3);
  p["device-review"].enabled = false;
  assert.equal(routines.dueReminders([], p, now + 31 * day).length, 2);
});
test("clock rollback cannot hide an enabled review indefinitely", () => {
  const p = enabled(); for (const id of Object.keys(p)) p[id].reviewedAt = now;
  assert.equal(routines.dueReminders([], p, now - day).length, 3);
});
test("local checks identify reused and older records without returning secrets or titles", () => {
  const a = item("a", "reused-secret"); const b = item("b", "reused-secret");
  b.payload.updatedAt = new Date(now - 366 * day).toISOString();
  const result = routines.dueReminders([a, b], enabled(), now);
  assert.deepEqual(result.find(r => r.id === "weekly-health").itemIds, ["a", "b"]);
  assert.deepEqual(result.find(r => r.id === "stale-passwords").itemIds, ["b"]);
  assert.doesNotMatch(JSON.stringify(result), /reused-secret|Private a|Private b/);
});
test("archived, deleted and non-login items do not create login findings", () => {
  const archived = item("a", "weak"); archived.payload.archived = true;
  const deleted = item("d", "weak", { deletedAt: new Date(now).toISOString() });
  const note = item("n", "weak", { contentType: "secure-note" });
  for (const reminder of routines.dueReminders([archived, deleted, note], enabled(), now)) assert.deepEqual(reminder.itemIds, []);
});
test("invalid timestamps do not masquerade as proven record age", () => {
  const a = item("a", "LongUniqueSecret45!"); a.payload.updatedAt = "not-a-date";
  assert.deepEqual(routines.dueReminders([a], enabled(), now).find(r => r.id === "stale-passwords").itemIds, []);
});
test("password generation respects the selected character groups with ambiguity allowed", () => {
  for (let i = 0; i < 30; i++) {
    assert.match(tools.generatePassword({ length: 24, uppercase: false, lowercase: false, numbers: true, symbols: false, avoidAmbiguous: false }), /^\d{24}$/);
    assert.match(tools.generatePassword({ length: 24, uppercase: false, lowercase: true, numbers: false, symbols: false, avoidAmbiguous: false }), /^[a-z]{24}$/);
  }
  assert.throws(() => tools.generatePassword({ length: NaN }), /finite/);
  assert.throws(() => tools.generatePassword({ length: 24 }), /character group/);
});
test("passphrases use the full unique dictionary, seven words by default, and at least six", async () => {
  const { default: words } = await vite.ssrLoadModule("/lib/vault/eff-words.json");
  assert.equal(words.length, 7776); assert.equal(new Set(words).size, 7776);
  assert.ok(7 * Math.log2(words.length) > 90);
  const phrase = tools.generatePassphrase();
  assert.equal(phrase.split(" ").length, 7);
  assert.ok(phrase.split(" ").every(word => words.includes(word)));
  assert.equal(tools.generatePassphrase(1).split(" ").length, 6);
  assert.throws(() => tools.generatePassphrase(NaN), /finite/);
  assert.throws(() => tools.generatePassphrase(7, ""), /separator/);
});

test("a late response cannot cross workspace switches, including A to B to A", async () => {
  const { WorkspaceRequestGate } = await vite.ssrLoadModule("/lib/vault/request-gate.ts");
  const gate = new WorkspaceRequestGate(); gate.select("a"); const old = gate.issue("a", "items");
  gate.select("b"); assert.equal(gate.accepts(old), false); assert.equal(gate.issue("a", "items"), null);
  gate.select("a"); assert.equal(gate.accepts(old), false); assert.equal(gate.accepts(gate.issue("a", "items")), true);
});
test("out-of-order refreshes use the latest response without canceling unrelated channels", async () => {
  const { WorkspaceRequestGate } = await vite.ssrLoadModule("/lib/vault/request-gate.ts");
  const gate = new WorkspaceRequestGate(); gate.select("a");
  const old = gate.issue("a", "items"), entitlement = gate.issue("a", "entitlement"), latest = gate.issue("a", "items");
  assert.equal(gate.accepts(old), false); assert.equal(gate.accepts(latest), true); assert.equal(gate.accepts(entitlement), true);
  gate.select(null); assert.equal(gate.accepts(latest), false); assert.equal(gate.accepts(entitlement), false);
});
