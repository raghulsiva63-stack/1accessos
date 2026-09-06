import { supabase } from "@/lib/supabase/client";

export type PlanCode = "free" | "personal" | "family" | "professional" | "team" | "business";
export type PublicPlanCode = PlanCode | "professional" | "enterprise";
export type SubscriptionStatus = "none" | "trialing" | "active" | "past_due" | "unpaid" | "canceled" | "incomplete" | "incomplete_expired" | "paused";
export type BillingInterval = "month" | "year";
export type BillingCurrency = "inr" | "usd";

export type TenantEntitlement = {
  plan_code: PlanCode;
  subscription_status: SubscriptionStatus;
  source: "free" | "stripe" | "manual";
  max_members: number;
  max_workspaces: number;
  max_devices: number | null;
  ai_credits_remaining: number;
  automation_runs_remaining: number;
  valid_until: string | null;
};

export type BillingPrice = {
  plan: Exclude<PlanCode, "free">;
  interval: BillingInterval;
  currency: BillingCurrency;
  unitAmount: number;
};

export type PublicPlanPrice = {
  currency: BillingCurrency;
  interval: BillingInterval;
  unitAmount: number;
  scope: "plan" | "seat";
};

export type PublicCatalogPlan = {
  catalogVersion: string;
  code: PublicPlanCode;
  name: string;
  audience: string;
  summary: string;
  billingModel: "free" | "flat" | "per_seat" | "contract";
  minSeats: number | null;
  maxSeats: number | null;
  trialDays: number;
  featured: boolean;
  commercialStatus: "proposed" | "active" | "retired";
  features: string[];
  prices: PublicPlanPrice[];
};

export const publicCatalogEnabled = process.env.NEXT_PUBLIC_PLAN_CATALOG_ENABLED === "true";

export const billingEnabled = process.env.NEXT_PUBLIC_BILLING_ENABLED === "true";
export const stripeTestMode = process.env.NEXT_PUBLIC_STRIPE_TEST_MODE === "true";

const PENDING_PLAN_KEY = "passkey-x:pending-plan";
const SELF_SERVE_PLANS = new Set<Exclude<PlanCode, "free">>([
  "personal", "family", "professional", "team", "business",
]);

export function rememberPlanSelection(plan: PublicPlanCode) {
  if (typeof window === "undefined" || plan === "free" || plan === "enterprise") return;
  if (SELF_SERVE_PLANS.has(plan)) window.localStorage.setItem(PENDING_PLAN_KEY, plan);
}

export function readPlanSelection(): Exclude<PlanCode, "free"> | null {
  if (typeof window === "undefined") return null;
  const plan = window.localStorage.getItem(PENDING_PLAN_KEY);
  return plan && SELF_SERVE_PLANS.has(plan as Exclude<PlanCode, "free">)
    ? plan as Exclude<PlanCode, "free">
    : null;
}

export function clearPlanSelection() {
  if (typeof window !== "undefined") window.localStorage.removeItem(PENDING_PLAN_KEY);
}

export const FREE_ENTITLEMENT: TenantEntitlement = {
  plan_code: "free",
  subscription_status: "none",
  source: "free",
  max_members: 1,
  max_workspaces: 1,
  max_devices: 2,
  ai_credits_remaining: 20,
  automation_runs_remaining: 50,
  valid_until: null,
};

export async function loadTenantEntitlement(tenantId: string): Promise<TenantEntitlement> {
  if (!supabase) return FREE_ENTITLEMENT;
  const { data, error } = await supabase.from("tenant_entitlements")
    .select("plan_code,subscription_status,source,max_members,max_workspaces,max_devices,ai_credits_remaining,automation_runs_remaining,valid_until")
    .eq("tenant_id", tenantId)
    .maybeSingle();
  if (error) throw error;
  return data ? data as TenantEntitlement : FREE_ENTITLEMENT;
}

export async function loadPublicPlanCatalog(): Promise<PublicCatalogPlan[]> {
  if (!publicCatalogEnabled || !supabase) return [];
  const { data: planRows, error: planError } = await supabase.from("plan_catalog")
    .select("catalog_version,plan_code,display_name,audience,summary,billing_model,min_seats,max_seats,trial_days,is_featured,sort_order,commercial_status")
    .eq("status", "published")
    .order("catalog_version", { ascending: false })
    .order("sort_order");
  if (planError) throw planError;
  const catalogVersion = planRows?.[0]?.catalog_version;
  if (!catalogVersion) return [];

  const [priceResult, entitlementResult] = await Promise.all([
    supabase.from("plan_prices")
      .select("plan_code,currency,billing_interval,unit_amount_minor,price_scope")
      .eq("catalog_version", catalogVersion),
    supabase.from("plan_entitlements")
      .select("plan_code,display_text,display_order")
      .eq("catalog_version", catalogVersion)
      .order("display_order"),
  ]);
  if (priceResult.error) throw priceResult.error;
  if (entitlementResult.error) throw entitlementResult.error;

  return planRows
    .filter((row) => row.catalog_version === catalogVersion)
    .map((row) => ({
      catalogVersion,
      code: row.plan_code as PublicPlanCode,
      name: row.display_name,
      audience: row.audience,
      summary: row.summary,
      billingModel: row.billing_model as PublicCatalogPlan["billingModel"],
      minSeats: row.min_seats,
      maxSeats: row.max_seats,
      trialDays: row.trial_days,
      featured: row.is_featured,
      commercialStatus: row.commercial_status as PublicCatalogPlan["commercialStatus"],
      features: (entitlementResult.data ?? [])
        .filter((entry) => entry.plan_code === row.plan_code)
        .map((entry) => entry.display_text),
      prices: (priceResult.data ?? [])
        .filter((entry) => entry.plan_code === row.plan_code)
        .map((entry) => ({
          currency: entry.currency as BillingCurrency,
          interval: entry.billing_interval as BillingInterval,
          unitAmount: entry.unit_amount_minor,
          scope: entry.price_scope as PublicPlanPrice["scope"],
        })),
    }));
}

async function invokeBilling<T>(body: Record<string, unknown>): Promise<T> {
  if (!supabase || !billingEnabled) throw new Error("billing_not_configured");
  const { data, error } = await supabase.functions.invoke("billing", { body });
  if (error) throw new Error("billing_unavailable");
  if (data?.error) throw new Error(String(data.error));
  return data as T;
}

export async function loadBillingCatalog(tenantId: string): Promise<BillingPrice[]> {
  const response = await invokeBilling<{ prices: BillingPrice[] }>({ action: "catalog", tenantId });
  return response.prices;
}

export async function beginCheckout(
  tenantId: string,
  plan: Exclude<PlanCode, "free">,
  interval: BillingInterval,
  currency: BillingCurrency,
  quantity = 1,
): Promise<string> {
  const response = await invokeBilling<{ url: string }>({
    action: "checkout",
    tenantId,
    plan,
    interval,
    currency,
    quantity,
    requestId: crypto.randomUUID(),
  });
  return response.url;
}

export async function openCustomerPortal(tenantId: string): Promise<string> {
  const response = await invokeBilling<{ url: string }>({ action: "portal", tenantId });
  return response.url;
}
