import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("..", import.meta.url));
const vite = await createServer({
  appType: "custom",
  configFile: false,
  root,
  resolve: { alias: { "@": root } },
  server: { middlewareMode: true, hmr: false },
});

after(async () => vite.close());

const load = (path) => vite.ssrLoadModule(path);

function item(id, secret, extra = {}) {
  return {
    id, contentType: "login", revision: 1, deletedAt: null,
    payload: { version: 1, title: `Item ${id}`, username: "synthetic", secret, url: "https://example.invalid", updatedAt: new Date().toISOString(), ...extra },
  };
}

test("normalizes organization policies with safe defaults and clamping", async () => {
  const policies = await load("/lib/enterprise/policies.ts");
  const policy = policies.normalizePolicies([
    { policy_type: "session_timeout_minutes", configuration: { minutes: 9999 }, source_scope_type: "tenant" },
    { policy_type: "clipboard_clear_seconds", configuration: { seconds: 1 } },
    { policy_type: "minimum_vault_password", configuration: { min_length: 16, min_strength: 3 } },
    { policy_type: "sharing_mode", configuration: { mode: "internal_only" }, source_scope_type: "department" },
    { policy_type: "export_policy", configuration: { mode: "nonsense" } },
    { policy_type: "passkey_required", configuration: { required: "yes" } },
    { policy_type: "unknown_policy", configuration: { anything: true } },
  ]);
  assert.equal(policy.sessionTimeoutMinutes, 480);
  assert.equal(policy.clipboardClearSeconds, 5);
  assert.equal(policy.minVaultPasswordLength, 16);
  assert.equal(policy.minVaultPasswordStrength, 3);
  assert.equal(policy.sharingMode, "internal_only");
  assert.equal(policy.exportMode, "allowed");
  assert.equal(policy.passkeyRequired, false, "only boolean true enables a requirement");
  assert.equal(policy.managed.sharing_mode, "department");
  assert.equal(policies.exportAllowed({ ...policy, exportMode: "admins_only" }, "member"), false);
  assert.equal(policies.exportAllowed({ ...policy, exportMode: "admins_only" }, "owner"), true);
  assert.equal(policies.exportAllowed({ ...policy, exportMode: "blocked" }, "owner"), false);
});

test("serializes policy editor values and rejects out-of-range input", async () => {
  const policies = await load("/lib/enterprise/policies.ts");
  assert.deepEqual(policies.serializePolicy("minimum_vault_password", { min_length: "14", min_strength: "3" }), { min_length: 14, min_strength: 3 });
  assert.deepEqual(policies.serializePolicy("sharing_mode", { mode: "disabled" }), { mode: "disabled" });
  assert.deepEqual(policies.serializePolicy("mfa_required", { required: true }), { required: true });
  assert.throws(() => policies.serializePolicy("session_timeout_minutes", { minutes: "0" }), /between 1 and 480/);
  assert.throws(() => policies.serializePolicy("export_policy", { mode: "everyone" }), /supported option/);
  const coverage = policies.baselineCoverage([{ id: "1", policy_type: "mfa_required", configuration: { required: true }, scope_type: "tenant", scope_id: null, enforced: true, version: 1, updated_at: null }]);
  assert.equal(coverage.met, 1);
  assert.equal(coverage.total, policies.RECOMMENDED_BASELINE.length);
});

test("estimates password strength conservatively", async () => {
  const health = await load("/lib/enterprise/health.ts");
  assert.ok(health.estimateStrength("password123").score <= 1);
  assert.ok(health.estimateStrength("aaaaaaaaaaaaaaaa").score <= 1);
  assert.ok(health.estimateStrength("qwertyuiop").score <= 1);
  assert.ok(health.estimateStrength("correct-Horse-battery-7-staple!").score >= 3);
  assert.equal(health.estimateStrength("").score, 0);
});

test("analyzes vault health locally and folds in k-anonymity breach results", async () => {
  const health = await load("/lib/enterprise/health.ts");
  const old = new Date(Date.now() - 400 * 86_400_000).toISOString();
  const items = [
    item("a", "Tr0ub4dor&3-long-unique-A"),
    item("b", "Tr0ub4dor&3-long-unique-A"),
    item("c", "123456"),
    item("d", "Zq9!mP2#vL8@xR4$", { updatedAt: old, url: "http://insecure.invalid" }),
  ];
  let requested = [];
  const fakeFetch = async (url, init) => {
    requested.push(url);
    assert.equal(init.headers["Add-Padding"], "true");
    // SHA-1("123456") = 7C4A8D09CA3762AF61E59520943DC26494F8941B
    return { ok: true, text: async () => "D09CA3762AF61E59520943DC26494F8941B:37359195\r\n0000000000000000000000000000000000A:0" };
  };
  const breaches = await health.checkBreachedPasswords(items, fakeFetch, "https://breach.invalid/range/");
  assert.ok(requested.every((url) => /\/range\/[0-9A-F]{5}$/.test(url)), "only 5-character prefixes are sent");
  assert.equal(breaches.get("c"), 37359195);
  const report = health.analyzeVaultHealth(items, breaches);
  assert.deepEqual(report.reused, [["a", "b"]]);
  assert.ok(report.weak.includes("c"));
  assert.deepEqual(report.breached, ["c"]);
  assert.deepEqual(report.old, ["d"]);
  assert.deepEqual(report.insecureUrl, ["d"]);
  assert.ok(report.score < 100);
  assert.equal(report.breachChecked, true);
  assert.equal(health.analyzeVaultHealth([]).score, 100);
});

test("summarizes organization risk from member overview rows", async () => {
  const admin = await load("/lib/enterprise/admin.ts");
  const now = Date.parse("2026-09-27T00:00:00Z");
  const base = { email: null, job_title: null, department_id: null, lifecycle_status: "active", joined_at: "2026-01-01T00:00:00Z", login_count: 1, passkey_count: 0, old_count: 0, health_reported_at: null, trusted_devices: 1 };
  const summary = admin.summarizeOrganization([
    { ...base, identity_id: "1", display_name: "A", tenant_role: "owner", membership_status: "active", admin_roles: [], mfa_factors: 1, last_sign_in_at: "2026-09-26T00:00:00Z", health_score: 90, weak_count: 0, reused_count: 0, breached_count: 0 },
    { ...base, identity_id: "2", display_name: "B", tenant_role: "member", membership_status: "active", admin_roles: [], mfa_factors: 0, last_sign_in_at: "2026-07-01T00:00:00Z", health_score: 50, weak_count: 3, reused_count: 2, breached_count: 1 },
    { ...base, identity_id: "3", display_name: "C", tenant_role: "member", membership_status: "active", admin_roles: ["security_admin"], mfa_factors: 1, last_sign_in_at: null, health_score: null, weak_count: null, reused_count: null, breached_count: null },
    { ...base, identity_id: "4", display_name: "D", tenant_role: "member", membership_status: "suspended", admin_roles: [], mfa_factors: 0, last_sign_in_at: null, health_score: 10, weak_count: 9, reused_count: 9, breached_count: 9 },
  ], now);
  assert.equal(summary.members, 4);
  assert.equal(summary.active, 3);
  assert.equal(summary.admins, 2);
  assert.equal(summary.withoutMfa, 1);
  assert.equal(summary.inactive30, 2);
  assert.equal(summary.neverReported, 1);
  assert.equal(summary.averageScore, 70);
  assert.equal(summary.atRisk, 1);
  assert.equal(summary.breached, 1);
});

test("audit CSV export neutralizes spreadsheet formulas", async () => {
  const audit = await load("/lib/enterprise/audit.ts");
  const csv = audit.auditToCsv([{ sequence: 1, occurred_at: "2026-09-27T00:00:00Z", actor_identity_id: null, actor_name: "=HYPERLINK(\"x\")", action: "vault.exported", target_type: "client_activity", target_id: null, metadata: { a: 1 }, hash_version: 2, event_hash: "ab" }]);
  const [, row] = csv.split("\r\n");
  assert.match(row, /^1,2026-09-27T00:00:00Z,"'=HYPERLINK\(""x""\)"/);
  assert.equal(audit.describeAuditAction("item.revealed"), "Revealed a secret");
});

test("rejects weak or oversized key-derivation profiles", async () => {
  const cryptoModule = await load("/lib/crypto/vault.ts");
  assert.throws(() => cryptoModule.assertKdfProfile({ memoryKib: 8192, iterations: 1, parallelism: 1, hashLength: 32 }), /secure range/);
  assert.throws(() => cryptoModule.assertKdfProfile({ memoryKib: 65536, iterations: 3, parallelism: 64, hashLength: 32 }), /secure range/);
  assert.deepEqual(cryptoModule.assertKdfProfile(cryptoModule.WEB_KDF_PROFILE), cryptoModule.WEB_KDF_PROFILE);
});

test("Secure Send encrypts with a link-only key and a separate access proof", async () => {
  const send = await load("/lib/enterprise/send.ts");
  const id = "3b7c1c9e-9f7e-4c35-9d7a-2a5f0e1b4c6d";
  const payload = { v: 1, kind: "text", text: "synthetic secret" };
  const encrypted = await send.encryptSend(id, payload);
  assert.equal(encrypted.linkKey.byteLength, 32);
  assert.equal(encrypted.proof.byteLength, 32);
  assert.equal(encrypted.salt, null);
  const material = await send.deriveSendMaterial(id, encrypted.linkKey);
  assert.deepEqual(material.proof, encrypted.proof, "proof is deterministic for the link key");
  assert.deepEqual(await send.decryptSend(id, "text", material.key, encrypted.nonce, encrypted.ciphertext), payload);
  await assert.rejects(() => send.decryptSend(id, "file", material.key, encrypted.nonce, encrypted.ciphertext), /changed/);
  const other = await send.deriveSendMaterial("00000000-0000-4000-8000-000000000000", encrypted.linkKey);
  assert.notDeepEqual(other.proof, encrypted.proof, "proof is bound to the send id");

  const link = send.sendLink("https://passkey-x.com/", { id, key: encrypted.linkKey });
  assert.match(link, /^https:\/\/passkey-x\.com\/send#[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  const parsed = send.parseSendLink(new URL(link).hash);
  assert.equal(parsed.id, id);
  assert.deepEqual(parsed.key, encrypted.linkKey);
  assert.equal(send.parseSendLink("#not-a-link"), null);

  const withPassphrase = await send.encryptSend(id, payload, "correct horse battery");
  assert.equal(withPassphrase.salt.byteLength, 16);
  assert.equal(send.sendStatus({ revoked_at: null, expires_at: new Date(Date.now() + 1000).toISOString(), view_count: 1, max_views: 1 }), "Used");
});
