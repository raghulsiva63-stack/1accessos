import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const migration = await readFile("supabase/migrations/20260905042216_phase6_commercial_catalog.sql", "utf8");
const sqlTest = await readFile("supabase/tests/phase6_commercial_catalog.sql", "utf8");
const catalogClient = await readFile("apps/web/lib/billing/client.ts", "utf8");
const publicSite = await readFile("apps/web/components/public-site.tsx", "utf8");
const page = await readFile("apps/web/app/page.tsx", "utf8");
const scope = await readFile("docs/phase6/commercial-experience-scope.md", "utf8");
const traceability = await readFile("docs/phase6/requirements-traceability.md", "utf8");

for (const table of ["plan_catalog", "plan_prices", "feature_catalog", "plan_entitlements"]) {
  assert.match(migration, new RegExp(`create table public\\.${table}`, "u"));
  assert.match(migration, new RegExp(`alter table public\\.${table} enable row level security`, "u"));
}
for (const plan of ["free", "personal", "family", "professional", "team", "business", "enterprise"]) {
  assert.match(migration, new RegExp(`'2026-09-v2\\.2','${plan}'`, "u"));
}
assert.match(migration, /published catalog versions are immutable/u);
assert.match(migration, /stripe_price_id is null/u);
assert.match(sqlTest, /set local role anon/u);
assert.match(sqlTest, /Published catalog mutation unexpectedly succeeded/u);
assert.match(catalogClient, /loadPublicPlanCatalog/u);
assert.match(publicSite, /Product[\s\S]*Teams[\s\S]*Business[\s\S]*Security[\s\S]*Pricing/u);
assert.match(publicSite, /Choose Team for one workgroup\. Choose Business for an organization\./u);
assert.match(publicSite, /paid checkout remains safely disabled/iu);
assert.doesNotMatch(page, /const BILLING_PLANS/u);
assert.match(scope, /not.*declaration.*Phase 6/isu);
assert.match(traceability, /SaaS\/AI Manager[\s\S]*Not complete/u);
assert.match(traceability, /PAM[\s\S]*Not started/u);
assert.doesNotMatch(`${migration}\n${catalogClient}\n${publicSite}`, /(?:sk|rk)_(?:live|test)_/u);

console.log("Commercial catalog, public navigation, office-package guidance, safe billing boundary, and traceability checks passed.");
