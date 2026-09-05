import { supabase } from "@/lib/supabase/client";

export type PlanCode = "free" | "personal" | "family" | "team";
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

export const billingEnabled = process.env.NEXT_PUBLIC_BILLING_ENABLED === "true";

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
): Promise<string> {
  const response = await invokeBilling<{ url: string }>({ action: "checkout", tenantId, plan, interval, currency });
  return response.url;
}

export async function openCustomerPortal(tenantId: string): Promise<string> {
  const response = await invokeBilling<{ url: string }>({ action: "portal", tenantId });
  return response.url;
}
