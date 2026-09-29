import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readAppShell } from "./lib/app-source.mjs";

const migration = await readFile("supabase/migrations/20260905042216_phase6_commercial_catalog.sql", "utf8");
const sqlTest = await readFile("supabase/tests/phase6_commercial_catalog.sql", "utf8");
const catalogClient = await readFile("apps/web/lib/billing/client.ts", "utf8");
const publicSite = [
  await readFile("apps/web/components/public-site.tsx", "utf8"),
  await readFile("apps/web/components/marketing/pricing-section.tsx", "utf8"),
].join("\n");
const marketingNav = await readFile("apps/web/components/marketing/marketing-shell.tsx", "utf8");
const marketingCatalog = await readFile("apps/web/lib/marketing/catalog.ts", "utf8");
const page = await readAppShell();
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
assert.match(marketingNav, /label="Products"[\s\S]*label="Solutions"[\s\S]*href="\/security">Security[\s\S]*href="\/pricing">Pricing/u);
assert.match(marketingCatalog, /slug: "teams"[\s\S]*slug: "business"/u);
assert.match(publicSite, /<MarketingHeader \/>[\s\S]*<PricingSection \/>/u);
assert.match(publicSite, /Choose Team for one workgroup\. Choose Business for an organization\./u);
assert.match(publicSite, /Sales-assisted plan.*self-service checkout is unavailable/iu);
assert.doesNotMatch(page, /const BILLING_PLANS/u);
assert.match(scope, /not.*declaration.*Phase 6/isu);
assert.match(traceability, /SaaS\/AI Manager[\s\S]*Engineering control-plane checkpoint complete/u);
assert.match(traceability, /Privileged access \+ agent\/machine identity[\s\S]*Not started as a release/u);
assert.match(traceability, /Revised Engineering Phase Plan v2\.2/u);
assert.match(traceability, /0 of 9/u);
assert.doesNotMatch(`${migration}\n${catalogClient}\n${publicSite}\n${marketingNav}\n${marketingCatalog}`, /(?:sk|rk)_(?:live|test)_/u);

console.log("Commercial catalog, public navigation, office-package guidance, safe billing boundary, and traceability checks passed.");
