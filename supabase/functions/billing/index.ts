import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import {
  adminSupabase, appOrigins, checkoutQuantity, corsHeaders, expectedStripeLivemode,
  findPrice, json, requireCompletePriceCatalog, requireTenantManager,
  safeCode, stripeClient, validateStripePrice,
} from "../_shared/billing.ts";

const INTEGRATION_IDENTIFIER = "passkey_x_qrltmzpn";
const PLANS_FOR_TENANT_KIND: Record<string, string[]> = {
  personal: ["personal", "professional"],
  family: ["family"],
  organization: ["team", "business"],
};

type BillingRequest = {
  action?: "catalog" | "checkout" | "portal";
  tenantId?: string;
  plan?: string;
  interval?: string;
  currency?: string;
  quantity?: number;
  requestId?: string;
};

function returnOrigin(request: Request): string {
  const origin = request.headers.get("origin");
  const allowed = appOrigins();
  return origin && allowed.includes(origin) ? origin : allowed[0];
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });

  // A client flag or deployed endpoint cannot authorize commercial activation.
  if (Deno.env.get("BILLING_ENABLED") !== "true") return json(request, 503, { error: "billing_disabled" });

  try {
    const body = await request.json() as BillingRequest;
    if (!body.action) throw new Error("invalid_request");
    const stripe = stripeClient();
    const expectedLivemode = expectedStripeLivemode();

    if (body.action === "catalog") {
      await requireTenantManager(request, body.tenantId ?? "");
      const catalog = await Promise.all(requireCompletePriceCatalog().map(async (choice) => {
        const price = await validateStripePrice(stripe, choice, expectedLivemode);
        return {
          plan: choice.plan,
          interval: choice.interval,
          currency: choice.currency,
          unitAmount: price.unit_amount,
        };
      }));
      return json(request, 200, { prices: catalog });
    }

    const tenantId = body.tenantId ?? "";
    const manager = await requireTenantManager(request, tenantId);
    const admin = adminSupabase();
    const { data: mapping, error: mappingError } = await admin.from("billing_customers")
      .select("stripe_customer_id,livemode")
      .eq("tenant_id", tenantId)
      .maybeSingle();
    if (mappingError) throw mappingError;
    if (mapping && mapping.livemode !== expectedLivemode) throw new Error("billing_unavailable");
    const origin = returnOrigin(request);

    if (body.action === "portal") {
      if (!mapping?.stripe_customer_id) throw new Error("customer_missing");
      const portal = await stripe.billingPortal.sessions.create({
        customer: mapping.stripe_customer_id,
        return_url: `${origin}/?billing=portal-return`,
      });
      return json(request, 200, { url: portal.url });
    }

    if (body.action !== "checkout") throw new Error("invalid_request");
    const choice = findPrice(body.plan, body.interval, body.currency);
    if (!choice) throw new Error("billing_not_configured");
    requireCompletePriceCatalog();
    await validateStripePrice(stripe, choice, expectedLivemode);
    const { data: catalogPlan, error: catalogError } = await admin.from("plan_catalog")
      .select("billing_model,min_seats,max_seats,trial_days")
      .eq("plan_code", choice.plan)
      .eq("status", "published")
      .order("catalog_version", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (catalogError || !catalogPlan) throw new Error("billing_not_configured");
    const minimumQuantity = catalogPlan.billing_model === "per_seat" ? catalogPlan.min_seats : 1;
    const maximumQuantity = catalogPlan.billing_model === "per_seat" ? catalogPlan.max_seats : 1;
    if (!minimumQuantity || !maximumQuantity) throw new Error("billing_not_configured");
    const quantity = checkoutQuantity(body.quantity ?? 1, minimumQuantity, maximumQuantity);
    // Each plan only works on one kind of tenant (Business features need an organization).
    const { data: tenant, error: tenantError } = await admin.from("tenants").select("kind").eq("id", tenantId).maybeSingle();
    if (tenantError || !tenant) throw new Error("invalid_tenant");
    if (!PLANS_FOR_TENANT_KIND[tenant.kind as string]?.includes(choice.plan)) throw new Error("plan_not_available_for_workspace");
    if (!body.requestId || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(body.requestId)) throw new Error("invalid_request");

    const { data: existing, error: existingError } = await admin.from("billing_subscriptions")
      .select("status")
      .eq("tenant_id", tenantId)
      .maybeSingle();
    if (existingError) throw existingError;
    if (existing && ["trialing", "active", "past_due", "unpaid", "incomplete", "paused"].includes(existing.status)) throw new Error("subscription_exists");
    const trialDays = existing ? 0 : catalogPlan.trial_days;

    let customerId = mapping?.stripe_customer_id as string | undefined;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: manager.email ?? undefined,
        metadata: { passkey_x_tenant_id: tenantId },
      }, { idempotencyKey: `passkey-x-customer-${tenantId}` });
      if (customer.livemode !== expectedLivemode) throw new Error("billing_unavailable");
      customerId = customer.id;
      const { error } = await admin.from("billing_customers").insert({
        tenant_id: tenantId,
        stripe_customer_id: customerId,
        livemode: customer.livemode,
      });
      if (error?.code === "23505") {
        const { data: raced } = await admin.from("billing_customers")
          .select("stripe_customer_id")
          .eq("tenant_id", tenantId)
          .single();
        customerId = raced?.stripe_customer_id;
      } else if (error) throw error;
    }
    if (!customerId) throw new Error("customer_missing");

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: choice.priceId, quantity }],
      allow_promotion_codes: true,
      client_reference_id: tenantId,
      success_url: `${origin}/?billing=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/?billing=cancelled`,
      integration_identifier: INTEGRATION_IDENTIFIER,
      metadata: {
        passkey_x_tenant_id: tenantId,
        passkey_x_plan: choice.plan,
        passkey_x_quantity: String(quantity),
      },
      subscription_data: {
        ...(trialDays > 0 ? { trial_period_days: trialDays } : {}),
        metadata: {
          passkey_x_tenant_id: tenantId,
          passkey_x_plan: choice.plan,
        },
      },
    }, { idempotencyKey: `passkey-x-checkout-${tenantId}-${body.requestId}` });
    if (!session.url) throw new Error("billing_unavailable");
    return json(request, 200, { url: session.url });
  } catch (reason) {
    const code = safeCode(reason);
    const status = code === "unauthorized" ? 401 : code === "forbidden" ? 403 : code === "subscription_exists" || code === "plan_not_available_for_workspace" ? 409 : code === "invalid_request" || code === "invalid_tenant" || code === "invalid_quantity" ? 400 : code === "billing_not_configured" ? 503 : 500;
    console.error(JSON.stringify({ function: "billing", code }));
    return json(request, status, { error: code });
  }
});
