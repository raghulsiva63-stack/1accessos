import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { reminderMessage, rolloutCsv, rolloutRow, summarizeRollout } from "../../apps/web/lib/enterprise/rollout.ts";

const NOW = Date.parse("2026-10-01T00:00:00Z");
const member = (overrides) => ({
  identity_id: overrides.id, email: `${overrides.id}@example.com`, display_name: overrides.id, job_title: null, department_id: null,
  tenant_role: "member", membership_status: "active", lifecycle_status: "active", admin_roles: [], mfa_factors: 0,
  last_sign_in_at: null, joined_at: "2026-09-01T00:00:00Z", health_score: null, weak_count: null, reused_count: null,
  old_count: null, breached_count: null, login_count: null, passkey_count: null, health_reported_at: null, trusted_devices: 0,
  ...overrides,
});

test("each person gets the right stage and next step", () => {
  assert.equal(rolloutRow(member({ id: "a" }), NOW).stage, "not_started");
  assert.equal(rolloutRow(member({ id: "b", last_sign_in_at: "2026-09-30T00:00:00Z" }), NOW).stage, "signed_in");
  assert.equal(rolloutRow(member({ id: "c", last_sign_in_at: "2026-09-30T00:00:00Z", login_count: 4 }), NOW).stage, "vault_in_use");
  const done = rolloutRow(member({ id: "d", last_sign_in_at: "2026-09-30T00:00:00Z", health_reported_at: "2026-09-30T00:00:00Z", mfa_factors: 1 }), NOW);
  assert.equal(done.stage, "protected");
  assert.match(done.nextStep, /all set/);
  const stale = rolloutRow(member({ id: "e", last_sign_in_at: "2026-07-01T00:00:00Z", login_count: 1, passkey_count: 1 }), NOW);
  assert.equal(stale.stage, "protected");
  assert.match(stale.nextStep, /inactive/);
});

test("summary counts active members only and lists least-progressed first", () => {
  const summary = summarizeRollout([
    member({ id: "z", last_sign_in_at: "2026-09-30T00:00:00Z", login_count: 1, mfa_factors: 1 }),
    member({ id: "y" }),
    member({ id: "gone", membership_status: "revoked" }),
  ], NOW);
  assert.equal(summary.total, 2);
  assert.equal(summary.percentComplete, 50);
  assert.deepEqual(summary.rows.map((row) => row.identityId), ["y", "z"]);
});

test("CSV export neutralises spreadsheet formulas and the reminder has no secrets", () => {
  const csv = rolloutCsv(summarizeRollout([member({ id: "x", display_name: "=HYPERLINK(1)" })], NOW));
  assert.match(csv, /^Name,Email,Status/);
  assert.match(csv, /'=HYPERLINK\(1\)/);
  const text = reminderMessage("Acme", "https://passkey-x.com");
  assert.match(text, /Acme/);
  assert.match(text, /https:\/\/passkey-x\.com\/help/);
});

test("the admin console shows the Team rollout tab", async () => {
  const consoleSource = await readFile("apps/web/components/admin/admin-console.tsx", "utf8");
  const panel = await readFile("apps/web/components/admin/rollout-panel.tsx", "utf8");
  assert.match(consoleSource, /\{ id: "rollout", label: "Team rollout", icon: Rocket \}/);
  assert.match(consoleSource, /<RolloutPanel vault=\{vault\}/);
  assert.match(panel, /summarizeRollout\(members, now\)/);
  assert.doesNotMatch(panel, /payload\.(secret|title|username|url)/);
});
