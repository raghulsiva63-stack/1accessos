import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const migration = await readFile("supabase/migrations/20260905021321_phase4_billing.sql", "utf8");
const advisorFixes = await readFile("supabase/migrations/20260905021623_phase4_advisor_fixes.sql", "utf8");
const enforcement = await readFile("supabase/migrations/20260905022119_phase4_entitlement_enforcement.sql", "utf8");
const integrity = await readFile("supabase/migrations/20260905022758_phase4_billing_integrity.sql", "utf8");
const performance = await readFile("supabase/migrations/20260905023231_phase4_billing_performance.sql", "utf8");
const shared = await readFile("supabase/functions/_shared/billing.ts", "utf8");
const billing = await readFile("supabase/functions/billing/index.ts", "utf8");
const webhook = await readFile("supabase/functions/stripe-webhook/index.ts", "utf8");
const config = await readFile("supabase/config.toml", "utf8");
const page = await readFile("apps/web/app/page.tsx", "utf8");
const client = await readFile("apps/web/lib/billing/client.ts", "utf8");
const environment = await readFile("apps/web/.env.example", "utf8");
const netlify = await readFile("netlify.toml", "utf8");

for (const table of ["tenant_entitlements", "billing_customers", "billing_subscriptions", "billing_events"]) {
  assert.match(migration, new RegExp(`alter table public\\.${table} enable row level security`, "u"));
}
assert.match(migration, /tenant_entitlements_read_member/);
assert.match(migration, /security invoker/iu);
assert.match(migration, /grant execute on function public\.apply_stripe_billing_event[\s\S]*to service_role/);
assert.match(migration, /on conflict \(stripe_event_id\) do nothing/);
assert.match(migration, /delivery_count = delivery_count \+ 1/);
assert.doesNotMatch(migration, /raw_payload|card_number|master_password|recovery_key/iu);
assert.match(advisorFixes, /billing_customers_deny_clients/);
assert.match(advisorFixes, /billing_subscriptions_deny_clients/);
assert.match(advisorFixes, /billing_events_deny_clients/);
assert.match(enforcement, /tenant_membership_plan_limit/);
assert.match(enforcement, /tenant_workspace_plan_limit/);
assert.match(enforcement, /tenant member limit reached/);
assert.match(enforcement, /tenant workspace limit reached/);
assert.match(integrity, /billing_subscriptions_tenant_mode_fkey/);
assert.match(integrity, /duplicate billing event integrity mismatch/);
assert.match(integrity, /billing_event_mode_guard/);
assert.match(performance, /billing_subscriptions_tenant_mode_idx/);

assert.match(shared, /npm:stripe@22\.4\.0/);
assert.match(shared, /2026-07-29\.dahlia/);
assert.match(shared, /STRIPE_RESTRICTED_KEY/);
assert.match(shared, /STRIPE_LIVEMODE/);
assert.match(shared, /expectedStripeLivemode/);
assert.match(shared, /SUPABASE_SECRET_KEYS/);
assert.match(shared, /APP_ORIGINS/);
assert.match(billing, /integration_identifier: INTEGRATION_IDENTIFIER/);
assert.match(billing, /mode: "subscription"/);
assert.match(billing, /billingPortal\.sessions\.create/);
assert.match(billing, /mapping\.livemode !== expectedLivemode/);
assert.doesNotMatch(`${billing}\n${shared}`, /payment_method_types/);
assert.doesNotMatch(`${billing}\n${shared}`, /automatic_tax/);
assert.match(webhook, /constructEventAsync/);
assert.match(webhook, /stripe-signature/);
assert.match(webhook, /crypto\.subtle\.digest\("SHA-256"/);
assert.match(webhook, /expectedStripeLivemode\(\)/);
assert.match(webhook, /apply_stripe_billing_event_checked/);
assert.match(webhook, /subscriptions\.retrieve\(delivered\.id\)/);
assert.match(config, /\[functions\.billing\][\s\S]*verify_jwt = true/);
assert.match(config, /\[functions\.stripe-webhook\][\s\S]*verify_jwt = false/);

assert.equal(environment.match(/NEXT_PUBLIC_BILLING_ENABLED=(.*)/)?.[1], "false");
assert.match(client, /loadTenantEntitlement/);
assert.match(client, /supabase\.functions\.invoke\("billing"/);
assert.match(page, /Plans & billing/);
assert.match(page, /INR/);
assert.match(page, /USD/);
assert.match(page, /signed Stripe webhook/);
assert.match(netlify, /NEXT_PUBLIC_BILLING_ENABLED = "false"/);
assert.doesNotMatch(`${page}\n${client}\n${netlify}`, /(?:sk|rk)_(?:live|test)_/);

console.log("Phase 4 tenant billing, webhook replay, secret boundary, pricing UI, and safe-disable checks passed.");
