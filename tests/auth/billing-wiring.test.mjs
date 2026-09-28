import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const shared = await readFile("supabase/functions/_shared/billing.ts", "utf8");
const billing = await readFile("supabase/functions/billing/index.ts", "utf8");
const webhook = await readFile("supabase/functions/stripe-webhook/index.ts", "utf8");
const policy = await readFile("supabase/migrations/20260905193000_billing_catalog_entitlements.sql", "utf8");
const client = await readFile("apps/web/lib/billing/client.ts", "utf8");
const page = await readFile("apps/web/app/page.tsx", "utf8");
const plansView = await readFile("apps/web/components/billing/plans-view.tsx", "utf8");
const publicSite = (await readFile("apps/web/components/public-site.tsx", "utf8")) + (await readFile("apps/web/components/marketing/pricing-section.tsx", "utf8"));

test("all five self-serve packages require twenty distinct Stripe prices", () => {
  assert.match(shared, /personal.*family.*professional.*team.*business/s);
  assert.match(shared, /EXPECTED_PRICE_COUNT/);
  assert.match(shared, /new Set\(choices\.map/);
  assert.match(shared, /price\.lookup_key !== lookupKey/);
  assert.match(shared, /price\.unit_amount !== EXPECTED_UNIT_AMOUNTS\[lookupKey\]/);
  assert.match(shared, /price\.metadata\.passkey_x_catalog_version !== "2026-09-v2\.2"/);
});

test("checkout uses trusted catalog policy, server quantity bounds, trials, and idempotency", () => {
  assert.match(billing, /\.from\("plan_catalog"\)/);
  assert.match(billing, /checkoutQuantity\(body\.quantity/);
  assert.match(billing, /const trialDays = existing \? 0 : catalogPlan\.trial_days/);
  assert.match(billing, /trial_period_days: trialDays/);
  assert.match(billing, /idempotencyKey: `passkey-x-checkout-/);
  assert.doesNotMatch(billing, /payment_method_types|automatic_tax/);
});

test("webhook and entitlement transaction recognize Professional and paid seat quantity", () => {
  assert.match(webhook, /"professional"/);
  assert.match(policy, /p_quantity < v_policy\.min_quantity/);
  assert.match(policy, /p_quantity > v_policy\.max_quantity/);
  assert.match(policy, /grant usage on schema private to service_role/);
  assert.match(policy, /then p_quantity/);
  assert.match(policy, /v_policy\.ai_credits_per_unit \* case/);
  assert.match(policy, /ai_credits_remaining=excluded\.ai_credits_remaining/);
});

test("public package choice survives authentication and opens verified billing", () => {
  assert.match(publicSite, /rememberPlanSelection\(plan\.code\)/);
  assert.match(client, /passkey-x:pending-plan/);
  assert.match(client, /SELF_SERVE_PLANS/);
  assert.match(page, /useState<View>\(\(\) => readPlanSelection\(\) \|\|[^\n]*\? "billing" : "home"\)/);
  assert.match(plansView, /readPlanSelection\(\)/);
  assert.match(plansView, /clearPlanSelection\(\);\s*window\.location\.assign\(url\)/);
});
