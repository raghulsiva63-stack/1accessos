import type Stripe from "npm:stripe@22.4.0";
import { adminSupabase, expectedStripeLivemode } from "./billing.ts";

type Admin = ReturnType<typeof adminSupabase>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MAX_REWARDS_PER_RUN = 12;

/**
 * Referral rewards ("give a month, get a month"), run after a paid invoice is recorded.
 * 1. If the invoice belongs to a referred friend's subscription, the referral becomes "converted".
 * 2. Every converted referral whose inviter now has a paying workspace is paid out once, as Stripe
 *    customer-balance credit worth one month of the inviter's plan (one seat). Each payout is
 *    claimed in the database first and uses a Stripe idempotency key, so retries never pay twice.
 * An inviter without a paid plan keeps the reward pending until their own first paid invoice.
 */
export async function handleReferralRewards(
  stripe: Stripe,
  admin: Admin,
  event: Stripe.Event,
  subscription: Stripe.Subscription | null,
  tenantId: string | null,
) {
  if (event.type !== "invoice.paid") return;
  const invoice = event.data.object as unknown as { amount_paid?: number };
  if (!invoice.amount_paid || invoice.amount_paid <= 0) return;

  const referrers = new Set<string>();
  const referralId = subscription?.metadata?.passkey_x_referral_id;
  if (referralId && UUID.test(referralId)) {
    const { data: converted, error } = await admin.from("referrals")
      .update({ status: "converted", converted_at: new Date().toISOString() })
      .eq("id", referralId).eq("status", "signed_up")
      .select("referrer_identity_id").maybeSingle();
    if (error) throw error;
    if (converted) referrers.add(converted.referrer_identity_id as string);
    else {
      const { data: row } = await admin.from("referrals").select("referrer_identity_id,status").eq("id", referralId).maybeSingle();
      if (row?.status === "converted") referrers.add(row.referrer_identity_id as string);
    }
  }

  // The payer may themselves be an inviter with rewards waiting for a paid plan.
  if (tenantId && UUID.test(tenantId)) {
    const { data: owners } = await admin.from("tenant_memberships")
      .select("identity_id").eq("tenant_id", tenantId).eq("role", "owner").eq("status", "active");
    for (const owner of owners ?? []) referrers.add(owner.identity_id as string);
  }

  for (const referrer of referrers) await payReferrer(stripe, admin, referrer);
}

async function payReferrer(stripe: Stripe, admin: Admin, referrerId: string) {
  const { data: pending, error: pendingError } = await admin.from("referrals")
    .select("id").eq("referrer_identity_id", referrerId).eq("status", "converted")
    .order("converted_at").limit(MAX_REWARDS_PER_RUN);
  if (pendingError) throw pendingError;
  if (!pending?.length) return;

  const { data: owned } = await admin.from("tenant_memberships")
    .select("tenant_id").eq("identity_id", referrerId).eq("role", "owner").eq("status", "active");
  const tenantIds = (owned ?? []).map((row) => row.tenant_id as string);
  if (!tenantIds.length) return;
  const { data: subscriptions } = await admin.from("billing_subscriptions")
    .select("tenant_id,stripe_price_id,billing_interval,currency")
    .in("tenant_id", tenantIds).in("status", ["active", "past_due"])
    .eq("livemode", expectedStripeLivemode())
    .order("created_at").limit(1);
  const paying = subscriptions?.[0];
  if (!paying) return; // Reward waits until the inviter pays for a plan.
  const { data: customer } = await admin.from("billing_customers")
    .select("stripe_customer_id").eq("tenant_id", paying.tenant_id).maybeSingle();
  if (!customer?.stripe_customer_id) return;

  const price = await stripe.prices.retrieve(paying.stripe_price_id as string);
  const unit = price.unit_amount ?? 0;
  const amount = paying.billing_interval === "year" ? Math.round(unit / 12) : unit;
  if (amount <= 0) return;

  for (const row of pending) {
    const { data: claimed, error: claimError } = await admin.from("referrals")
      .update({ status: "rewarded", rewarded_at: new Date().toISOString(), reward_amount_minor: amount, reward_currency: paying.currency })
      .eq("id", row.id).eq("status", "converted")
      .select("id").maybeSingle();
    if (claimError) throw claimError;
    if (!claimed) continue;
    try {
      const transaction = await stripe.customers.createBalanceTransaction(customer.stripe_customer_id as string, {
        amount: -amount,
        currency: paying.currency as string,
        description: "Passkey-X referral reward: one free month",
        metadata: { passkey_x_referral_id: row.id as string },
      }, { idempotencyKey: `passkey-x-referral-${row.id}` });
      await admin.from("referrals").update({ stripe_balance_transaction_id: transaction.id }).eq("id", row.id);
    } catch (reason) {
      // Hand the reward back so the next paid invoice retries it (same idempotency key).
      await admin.from("referrals")
        .update({ status: "converted", rewarded_at: null, reward_amount_minor: null, reward_currency: null })
        .eq("id", row.id).is("stripe_balance_transaction_id", null);
      throw reason;
    }
  }
}
