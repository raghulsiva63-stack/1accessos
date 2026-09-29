import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { claimMessage, normalizeReferralCode, parseStoredReferral, referralLink, storedReferralValue } from "../../apps/web/lib/referral-codes.ts";

const DAY = 86_400_000;

test("invite codes are normalised and look-alike characters are rejected", () => {
  assert.equal(normalizeReferralCode(" abcd2345 "), "ABCD2345");
  assert.equal(normalizeReferralCode("ABCD0123"), null);
  assert.equal(normalizeReferralCode("ABCDI234"), null);
  assert.equal(normalizeReferralCode("<script>"), null);
  assert.equal(referralLink("https://passkey-x.com/", "ABCD2345"), "https://passkey-x.com/?ref=ABCD2345");
});

test("a remembered code expires after 30 days and bad storage is ignored", () => {
  const now = Date.parse("2026-10-02T00:00:00Z");
  assert.equal(parseStoredReferral(storedReferralValue("ABCD2345", now - 29 * DAY), now), "ABCD2345");
  assert.equal(parseStoredReferral(storedReferralValue("ABCD2345", now - 31 * DAY), now), null);
  assert.equal(parseStoredReferral("{oops", now), null);
  assert.equal(parseStoredReferral('{"code":"ABCD0000","at":1}', 2), null);
  assert.match(claimMessage("claimed"), /30-day free trial/);
  assert.equal(claimMessage("invalid_code"), null);
});

test("checkout extends a referred friend's first trial and tags the subscription", async () => {
  const billing = await readFile("supabase/functions/billing/index.ts", "utf8");
  assert.match(billing, /REFERRAL_TRIAL_DAYS = 30/);
  assert.match(billing, /\.eq\("referred_identity_id", manager\.identityId\)\s*\.eq\("status", "signed_up"\)/);
  assert.match(billing, /trial_period_days: trialDays \+ referralBonusDays/);
  assert.match(billing, /passkey_x_referral_id: referralId/);
});

test("rewards are paid once, never block the webhook, and browsers cannot touch the tables", async () => {
  const webhook = await readFile("supabase/functions/stripe-webhook/index.ts", "utf8");
  const rewards = await readFile("supabase/functions/_shared/referrals.ts", "utf8");
  const migration = await readFile("supabase/migrations/20261002090000_referrals.sql", "utf8");
  assert.match(webhook, /try \{ await handleReferralRewards\(/);
  assert.match(webhook, /referral_reward_deferred/);
  assert.match(rewards, /if \(event\.type !== "invoice\.paid"\) return;/);
  assert.match(rewards, /\.eq\("id", row\.id\)\.eq\("status", "converted"\)/);
  assert.match(rewards, /idempotencyKey: `passkey-x-referral-\$\{row\.id\}`/);
  assert.match(rewards, /amount: -amount/);
  assert.match(migration, /revoke all on public\.referral_codes, public\.referrals from public, anon, authenticated/);
  assert.match(migration, /interval '14 days'/);
  assert.match(migration, /check \(referrer_identity_id <> referred_identity_id\)/);
});

test("Home shows the referral card and the site remembers ?ref= links", async () => {
  const home = await readFile("apps/web/components/app/shell/home-view.tsx", "utf8");
  const layout = await readFile("apps/web/app/layout.tsx", "utf8");
  assert.match(home, /<ReferralCard \/>/);
  assert.match(layout, /<ReferralCapture \/>/);
});
