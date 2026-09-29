import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { formatPrice, preferredCurrency, upgradeTarget, yearlySavingsPercent } from "../../apps/web/lib/billing/nudges.ts";

const plan = (month, year) => ({ prices: [
  { currency: "usd", interval: "month", unitAmount: month, scope: "plan" },
  { currency: "usd", interval: "year", unitAmount: year, scope: "plan" },
] });

test("yearly saving is computed from real catalog prices", () => {
  assert.equal(yearlySavingsPercent(plan(300, 3000), "usd"), 17);
  assert.equal(yearlySavingsPercent(plan(300, 3600), "usd"), null);
  assert.equal(yearlySavingsPercent(plan(300, 3000), "inr"), null);
  assert.equal(yearlySavingsPercent(undefined, "usd"), null);
});

test("upgrade target follows the workspace kind", () => {
  assert.equal(upgradeTarget("personal"), "personal");
  assert.equal(upgradeTarget(null), "personal");
  assert.equal(upgradeTarget("family"), "family");
  assert.equal(upgradeTarget("organization"), "team");
});

test("currency and price formatting", () => {
  assert.equal(preferredCurrency("en-IN", "UTC"), "inr");
  assert.equal(preferredCurrency("en-US", "Asia/Kolkata"), "inr");
  assert.equal(preferredCurrency("en-GB", "Europe/London"), "usd");
  assert.equal(formatPrice(29900, "inr"), "₹299");
  assert.equal(formatPrice(299, "usd"), "$2.99");
});

test("Home shows a guided next step, Breach Watch and an honest plan panel", async () => {
  const home = await readFile("apps/web/components/app/shell/home-view.tsx", "utf8");
  assert.match(home, /Your next step/);
  assert.match(home, /<BreachWatchCard key=\{tenantId \?\? "none"\}/);
  assert.match(home, /yearlySavingsPercent\(target, currency\)/);
  assert.match(home, /30-day money-back guarantee/);
  assert.doesNotMatch(home, /SponsorCard/);
});
