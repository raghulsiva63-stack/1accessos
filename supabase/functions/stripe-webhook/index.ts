import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import Stripe from "npm:stripe@22.4.0";
import {
  adminSupabase, expectedStripeLivemode, json, priceMetadata, required, safeCode,
  stripeClient, stripeId,
} from "../_shared/billing.ts";

type SubscriptionSnapshot = {
  tenantId: string;
  customerId: string;
  subscriptionId: string;
  productId: string;
  priceId: string;
  plan: "personal" | "family" | "professional" | "team" | "business";
  interval: "month" | "year";
  currency: "inr" | "usd";
  status: string;
  quantity: number;
  periodStart: string | null;
  periodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  canceledAt: string | null;
};

function iso(seconds: number | null | undefined): string | null {
  return seconds ? new Date(seconds * 1000).toISOString() : null;
}

async function snapshot(subscription: Stripe.Subscription): Promise<SubscriptionSnapshot | null> {
  const item = subscription.items.data[0];
  const price = item?.price;
  if (!price) return null;
  const configured = priceMetadata(price.id);
  const tenantId = subscription.metadata.passkey_x_tenant_id;
  const customerId = stripeId(subscription.customer);
  const productId = stripeId(price.product);
  if (!configured || !tenantId || !customerId || !productId) return null;
  const record = subscription as unknown as Record<string, unknown>;
  const itemRecord = item as unknown as Record<string, unknown>;
  return {
    tenantId,
    customerId,
    subscriptionId: subscription.id,
    productId,
    priceId: price.id,
    plan: configured.plan,
    interval: configured.interval,
    currency: configured.currency,
    status: subscription.status,
    quantity: item.quantity ?? 1,
    periodStart: iso((record.current_period_start ?? itemRecord.current_period_start) as number | undefined),
    periodEnd: iso((record.current_period_end ?? itemRecord.current_period_end) as number | undefined),
    cancelAtPeriodEnd: subscription.cancel_at_period_end,
    canceledAt: iso(subscription.canceled_at),
  };
}

async function subscriptionFromEvent(stripe: Stripe, event: Stripe.Event): Promise<Stripe.Subscription | null> {
  if (event.type.startsWith("customer.subscription.")) {
    const delivered = event.data.object as Stripe.Subscription;
    try { return await stripe.subscriptions.retrieve(delivered.id); }
    catch { return event.type === "customer.subscription.deleted" ? delivered : null; }
  }
  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const id = stripeId(session.subscription);
    return id ? await stripe.subscriptions.retrieve(id) : null;
  }
  if (event.type === "invoice.paid" || event.type === "invoice.payment_failed") {
    const invoice = event.data.object as unknown as Record<string, unknown>;
    const parent = invoice.parent as { subscription_details?: { subscription?: string | { id: string } } } | undefined;
    const id = stripeId((invoice.subscription ?? parent?.subscription_details?.subscription) as string | { id: string } | undefined);
    return id ? await stripe.subscriptions.retrieve(id) : null;
  }
  return null;
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");
  if (!signature) return json(request, 400, { error: "invalid_signature" });

  let event: Stripe.Event | null = null;
  try {
    const stripe = stripeClient();
    event = await stripe.webhooks.constructEventAsync(
      rawBody,
      signature,
      required("STRIPE_WEBHOOK_SECRET"),
      undefined,
      Stripe.createSubtleCryptoProvider(),
    );
    if (event.livemode !== expectedStripeLivemode()) throw new Error("mode_mismatch");

    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody)));
    const subscription = await subscriptionFromEvent(stripe, event);
    const state = subscription ? await snapshot(subscription) : null;
    let tenantId = state?.tenantId ?? null;
    let customerId = state?.customerId ?? null;

    if (!state && event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      tenantId = session.metadata?.passkey_x_tenant_id ?? session.client_reference_id ?? null;
      customerId = stripeId(session.customer);
    }

    const admin = adminSupabase();
    const { error } = await admin.rpc("apply_stripe_billing_event_checked", {
      p_event_id: event.id,
      p_event_type: event.type,
      p_api_version: event.api_version,
      p_payload_sha256: `\\x${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`,
      p_livemode: event.livemode,
      p_tenant_id: tenantId,
      p_customer_id: customerId,
      p_subscription_id: state?.subscriptionId ?? null,
      p_product_id: state?.productId ?? null,
      p_price_id: state?.priceId ?? null,
      p_plan_code: state?.plan ?? null,
      p_billing_interval: state?.interval ?? null,
      p_currency: state?.currency ?? null,
      p_status: state?.status ?? null,
      p_quantity: state?.quantity ?? 1,
      p_period_started_at: state?.periodStart ?? null,
      p_period_ends_at: state?.periodEnd ?? null,
      p_cancel_at_period_end: state?.cancelAtPeriodEnd ?? false,
      p_canceled_at: state?.canceledAt ?? null,
    });
    if (error) {
      // A workspace can disappear while Stripe still holds its subscription (for example after the
      // account was deleted). Acknowledge those events so Stripe stops retrying and never disables
      // the endpoint; every other failure is still rejected and retried.
      if (error.code === "23503" && tenantId) {
        const { data: tenant, error: tenantError } = await admin.from("tenants").select("id").eq("id", tenantId).maybeSingle();
        if (!tenantError && !tenant) {
          console.warn(JSON.stringify({ function: "stripe-webhook", eventId: event.id, code: "unknown_tenant_ignored" }));
          return json(request, 200, { received: true, ignored: "unknown_tenant" });
        }
      }
      throw error;
    }
    return json(request, 200, { received: true });
  } catch (reason) {
    const code = safeCode(reason);
    console.error(JSON.stringify({ function: "stripe-webhook", eventId: event?.id ?? null, code }));
    return json(request, 400, { error: code === "billing_unavailable" ? "webhook_rejected" : code });
  }
});
