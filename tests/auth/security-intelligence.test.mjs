import assert from "node:assert/strict";
import { register } from "node:module";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

register("../support/web-lib-loader.mjs", import.meta.url);
const { assessSite, lookalikePairs, decodePunycode } = await import("../../apps/web/lib/security/phishing.ts");
const { scanForExposedSecrets } = await import("../../apps/web/lib/security/secret-scan.ts");
const { analyzeVaultHealth, healthMetrics, summarizeHealth } = await import("../../apps/web/lib/security/score.ts");
const directory = await import("../../apps/web/lib/security/site-directory.ts");
const { validatePolicyAdvice, validateTriage } = await import("../../apps/web/lib/security/ai-output.ts");
const { validPolicyConfiguration } = await import("../../apps/web/lib/security/policy-rules.ts");
const templates = await import("../../supabase/functions/_shared/security-templates.ts");
const hibp = await import("../../supabase/functions/_shared/hibp.ts");

const now = Date.parse("2026-10-04T12:00:00Z");
function item(id, extra = {}, payload = {}) {
  return { id, contentType: "login", revision: 1, deletedAt: null, ...extra,
    payload: { version: 1, title: `Title ${id}`, updatedAt: new Date(now).toISOString(), ...payload } };
}

test("look-alike sites are caught, real sites and other brands are not", () => {
  const saved = ["https://www.paypal.com/signin", "https://github.com", "https://bank.example.co.uk", "gmail.com"];
  assert.equal(assessSite("https://paypal.com/login", saved).kind, "trusted");
  assert.equal(assessSite("https://login.bank.example.co.uk", saved).kind, "trusted");
  assert.deepEqual(assessSite("https://paypa1.com", saved), { kind: "lookalike", domain: "paypa1.com", resembles: "paypal.com", reason: "homoglyph" });
  assert.equal(assessSite("https://xn--pypal-4ve.com", saved).reason, "punycode");
  assert.equal(assessSite("https://paypal.com.account-check.io", saved).reason, "subdomain_trick");
  assert.equal(assessSite("https://githbu.com", saved).reason, "typo");
  assert.equal(assessSite("https://mail.com", saved).kind, "unknown");
  assert.equal(assessSite("https://gitlab.com", saved).kind, "unknown");
  assert.equal(assessSite("not a url at all", saved).kind, "unknown");
  assert.equal(decodePunycode("pypal-4ve"), "pаypal");
  assert.deepEqual(lookalikePairs([{ id: "a", url: "amazon.com" }, { id: "b", url: "amazon.de" }]), []);
  assert.equal(lookalikePairs([{ id: "a", url: "paypal.com" }, { id: "b", url: "paypa1.com" }]).length, 1);
});

test("secret scanner finds keys in notes, masks them, and respects proper item types", () => {
  const aws = "AKIAIOSFODNN7EXAMPLE";
  const items = [
    item("note", { contentType: "secure-note" }, { notes: `prod key ${aws}\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc` }),
    item("api", { contentType: "api-key" }, { notes: aws }),
    item("ssh", { contentType: "ssh-key" }, { notes: "-----BEGIN OPENSSH PRIVATE KEY-----" }),
    item("login", {}, { secret: aws, fields: { "Backup card": "4111 1111 1111 1111", phone: "4111 1111 1111 1112" } }),
    item("card", { contentType: "payment-card" }, { notes: "4111111111111111" }),
  ];
  const findings = scanForExposedSecrets(items);
  assert.deepEqual(findings.map((finding) => `${finding.itemId}:${finding.kind}`).sort(),
    ["login:card_number", "note:aws_key", "note:private_key"]);
  const text = JSON.stringify(findings);
  assert.doesNotMatch(text, /AKIAIOSFODNN7EXAMPLE|4111 1111 1111 1111/);
  assert.equal(findings.find((finding) => finding.kind === "aws_key").preview, "AKIA…MPLE");
});

test("one score for Home, Security and the organization report", () => {
  const items = [
    item("a", {}, { secret: "Tr0ub4dor&3-horse-Battery", url: "https://paypal.com" }),
    item("b", {}, { secret: "Tr0ub4dor&3-horse-Battery", url: "https://paypa1.com" }),
    item("c", {}, { secret: "password1" }),
    item("n", { contentType: "secure-note" }, { notes: "AKIAIOSFODNN7EXAMPLE" }),
  ];
  const report = analyzeVaultHealth(items, new Map([["c", 12]]), now);
  assert.equal(report.lookalikes.length, 1);
  assert.equal(report.exposedSecrets.length, 1);
  assert.ok(report.items.find((entry) => entry.itemId === "n").issues.includes("exposed_secret"));
  const summary = summarizeHealth(report);
  assert.equal(summary.score, report.score);
  assert.deepEqual(summary.findings.map((finding) => finding.id).slice(0, 3), ["breached", "lookalike", "reused-0"]);
  const metrics = healthMetrics(report, { passkeyReady: 2, twoFactorReady: 3 });
  assert.deepEqual(Object.keys(metrics).sort(), ["breached", "exposed_secrets", "items", "logins", "lookalikes", "missing_totp",
    "old", "passkey_ready", "passkeys", "reused", "score", "two_factor_ready", "weak"]);
  assert.doesNotMatch(JSON.stringify(metrics), /paypal|Title|Tr0ub/);
  assert.equal(healthMetrics(analyzeVaultHealth(items, undefined, now)).breached, null);
  assert.equal(analyzeVaultHealth([], undefined, now).score, 100);
});

test("site directory: public lists are normalised and matched on the device", () => {
  const sites = directory.normalizeTwoFactorDirectory([
    ["GitHub", { domain: "github.com", tfa: ["totp", "u2f", "sms"], documentation: "https://docs.github.com/2fa", "additional-domains": ["gist.github.com"] }],
    ["Evil", { domain: "javascript:alert(1)", tfa: ["totp"] }],
    ["NoTfa", { domain: "plain.example", tfa: [] }],
  ]);
  directory.normalizePasskeyDirectory({ "github.com": { passwordless: "allowed", mfa: "allowed" }, "shop.example": { passwordless: "allowed", documentation: "javascript:x" } }, sites);
  assert.deepEqual(Object.keys(sites).sort(), ["gist.github.com", "github.com", "shop.example"]);
  assert.equal(sites["github.com"][0], directory.SITE_FLAGS.totp | directory.SITE_FLAGS.sms | directory.SITE_FLAGS.securityKey | directory.SITE_FLAGS.passkeySignIn | directory.SITE_FLAGS.passkeyTwoStep);
  assert.equal(sites["shop.example"][1], undefined);
  const dir = { generatedAt: "x", sites };
  const suggestions = directory.upgradeSuggestions([
    item("gh", {}, { url: "https://www.github.com/login", secret: "x" }),
    item("gh2", {}, { url: "https://github.com", username: "work", secret: "x", fields: { TOTP: "JBSWY3DP" } }),
    item("pk", { contentType: "passkey" }, { url: "https://shop.example" }),
    item("shop", {}, { url: "https://shop.example", secret: "y" }),
  ], dir);
  assert.deepEqual(suggestions.map((entry) => [entry.itemId, entry.twoStep, entry.passkey]), [["gh", true, true], ["gh2", false, true]]);
});

test("AI answers are checked before an admin sees them", () => {
  const triage = validateTriage({ summary: "Start with sign-ins", items: [
    { kind: "sign_in.many_networks", priority: 1, why: "Possible stolen session", next_step: "Contact the member" },
    { kind: "made.up", priority: 1, why: "x", next_step: "y" },
    { kind: "vault.exported", priority: 9, why: "x", next_step: "y" },
    { kind: "vault.exported", priority: 2, why: "Export", next_step: "Confirm" },
  ] }, new Set(["sign_in.many_networks", "vault.exported"]));
  assert.deepEqual(triage.items.map((entry) => entry.kind), ["sign_in.many_networks", "vault.exported"]);
  const advice = validatePolicyAdvice({ summary: "s", recommendations: [
    { policy_type: "mfa_required", configuration_json: '{"required":true}', reason: "Only 40% use two-step" },
    { policy_type: "session_timeout_minutes", configuration_json: '{"minutes":9999}', reason: "bad" },
    { policy_type: "sharing_mode", configuration_json: '{"mode":"internal_only"}', reason: "already on" },
    { policy_type: "export_policy", configuration_json: "not json", reason: "bad" },
    { policy_type: "drop_table", configuration_json: "{}", reason: "bad" },
    { policy_type: "breach_monitoring", configuration_json: '{"mode":"off"}', reason: "loosening" },
    { policy_type: "export_policy", configuration_json: '{"mode":"allowed"}', reason: "loosening" },
    { policy_type: "session_timeout_minutes", configuration_json: '{"minutes":30}', reason: "longer than now" },
    { policy_type: "organization_recovery", configuration_json: '{"enabled":true}', reason: "trade-off" },
    { policy_type: "minimum_vault_password", configuration_json: '{"min_length":16,"min_strength":3}', reason: "Stronger" },
  ] }, [{ type: "sharing_mode", configuration: { mode: "internal_only" } }, { type: "session_timeout_minutes", configuration: { minutes: 10 } },
    { type: "minimum_vault_password", configuration: { min_length: 14, min_strength: 3 } }]);
  assert.deepEqual(advice.recommendations.map((entry) => entry.policy_type), ["mfa_required", "minimum_vault_password"]);
  assert.equal(validPolicyConfiguration("minimum_vault_password", { min_length: 14, min_strength: 3 }), true);
  assert.equal(validPolicyConfiguration("minimum_vault_password", { min_length: 14, extra: 1 }), false);
});

test("notification templates escape everything and never include secrets", () => {
  const alert = templates.renderNotification("security_alert", { title: "<img src=x onerror=alert(1)>", severity: "critical" });
  assert.doesNotMatch(alert.html, /<img/);
  assert.match(alert.html, /&lt;img/);
  const breach = templates.renderNotification("breach_exposure", { breach: "New <b>Leak</b>\nline", includes_passwords: true });
  assert.doesNotMatch(breach.html, /<b>Leak/);
  assert.doesNotMatch(breach.text, /\nline/);
  assert.equal(breach.sms, null);
  const weekly = templates.renderNotification("weekly_report", { score: 76, score_week_ago: 70, alerts_new_7d: 3,
    top_risks: [{ key: "breached_passwords", count: 2 }, { key: "<script>", count: 1 }] });
  assert.match(weekly.subject, /76\/100/);
  assert.match(weekly.text, /\+6 since last week/);
  assert.match(weekly.text, /2 passwords found in known breaches/);
  assert.doesNotMatch(weekly.html, /script/);
  assert.equal(templates.renderNotification("unknown_template", {}), null);
  for (const name of ["new_sign_in", "new_country", "many_networks", "passkey_nudge", "rotation_assigned"]) {
    const rendered = templates.renderNotification(name, { device: "Chrome on Windows", country: "D<E", title: "Q4", count: 2, due: "2026-11-01" });
    assert.ok(rendered.subject && rendered.html && rendered.text, name);
    assert.doesNotMatch(rendered.html, /D<E/);
  }
});

test("breach watch keeps only real breaches and safe fields", () => {
  const parsed = hibp.parseBreaches([
    { Name: "Adobe", Title: "Adobe", Domain: "adobe.com", BreachDate: "2013-10-04", DataClasses: ["Email addresses", "Passwords"], Description: "<a>html</a>" },
    { Name: "Fake", IsFabricated: true }, { Name: "Spam", IsSpamList: true }, { Name: "bad;name" },
  ]);
  assert.deepEqual(parsed, [{ name: "Adobe", title: "Adobe", domain: "adobe.com", date: "2013-10-04", data_classes: ["Email addresses", "Passwords"] }]);
  assert.throws(() => hibp.parseBreaches({}));
  assert.equal(hibp.breachedAccountUrl(" a+b@x.io "), "https://haveibeenpwned.com/api/v3/breachedaccount/a%2Bb%40x.io?truncateResponse=false");
  assert.equal(hibp.spacingMs(10), 6100);
});

test("database: sign-in tracking never stores full IP addresses and never blocks sign-in", async () => {
  const sql = await readFile(new URL("../../supabase/migrations/20261004090000_security_intelligence.sql", import.meta.url), "utf8");
  assert.match(sql, /exception when others then\s+null;/);
  assert.match(sql, /set_masklen\(p_ip, 24\)/);
  const config = await readFile(new URL("../../supabase/config.toml", import.meta.url), "utf8");
  assert.match(config, /\[functions\.security-notify\]\nverify_jwt = false/);
  assert.match(config, /\[functions\.breach-watch\]\nverify_jwt = false/);
});
