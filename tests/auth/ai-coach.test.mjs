import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const fn = await readFile("apps/web/netlify/functions/security-advice.mts", "utf8");
const coach = await readFile("apps/web/components/app/ai-security-coach.tsx", "utf8");
const center = await readFile("apps/web/components/enterprise/security-center.tsx", "utf8");
const migration = await readFile("supabase/migrations/20261001090000_ai_coach_and_monthly_allowances.sql", "utf8");

test("AI Security Coach sends only on-device vault-health totals", () => {
  assert.match(fn, /"vault_health"/);
  assert.match(fn, /VAULT_HEALTH_KEYS = \["score", "logins", "weak", "reused", "old", "breached", "insecure_sites", "missing_two_step", "passkeys"\]/);
  assert.match(fn, /Object\.keys\(input\)\.some\(\(key\) => !\(VAULT_HEALTH_KEYS/);
  assert.match(fn, /categories = \["vault_health_counts"\]/);
  assert.match(fn, /startError\?\.code === "54000"\) return response\(429/);
  assert.match(coach, /body: JSON\.stringify\(\{ tenantId, useCase: "vault_health", metrics \}\)/);
  assert.doesNotMatch(coach, /payload\.(secret|title|username|url)/);
  assert.match(center, /<AiSecurityCoach tenantId=\{tenantId\}/);
});

test("coach admission is member-scoped and credits refill monthly", () => {
  assert.match(migration, /p_use_case = 'vault_health'/);
  assert.match(migration, /private\.has_tenant_role\(p_tenant_id,array\['owner','admin','member','auditor'\]\)/);
  assert.match(migration, /p_context_categories is distinct from array\['vault_health_counts'\]::text\[\]/);
  assert.match(migration, /not private\.has_business_entitlement\(p_tenant_id\)/);
  assert.match(migration, /cron\.schedule\('px-refill-monthly-allowances','5 0 1 \* \*'/);
  assert.match(migration, /revoke all on function private\.refill_monthly_allowances\(\) from public,anon,authenticated/);
});
