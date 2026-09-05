import Stripe from "npm:stripe@22.4.0";
import { createClient } from "npm:@supabase/supabase-js@2.115.0";

export type BillingPlan = "personal" | "family" | "team";
export type BillingInterval = "month" | "year";
export type BillingCurrency = "inr" | "usd";

export type PriceChoice = {
  plan: BillingPlan;
  interval: BillingInterval;
  currency: BillingCurrency;
  priceId: string;
};

const PLANS: BillingPlan[] = ["personal", "family", "team"];
const INTERVALS: BillingInterval[] = ["month", "year"];
const CURRENCIES: BillingCurrency[] = ["inr", "usd"];

export function required(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`missing:${name}`);
  return value;
}

export function optional(name: string): string | null {
  return Deno.env.get(name)?.trim() || null;
}

export function appOrigins(): string[] {
  const configured = optional("APP_ORIGINS") ?? "https://passkey-x.com";
  return configured.split(",").map((value) => value.trim()).filter(Boolean);
}

export function corsHeaders(request: Request): HeadersInit {
  const origin = request.headers.get("origin");
  const allowed = appOrigins();
  return {
    "Access-Control-Allow-Origin": origin && allowed.includes(origin) ? origin : allowed[0],
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Vary": "Origin",
  };
}

export function json(request: Request, status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(request) });
}

function namedKey(sourceName: string, fallbackName: string): string {
  const source = optional(sourceName);
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required(fallbackName);
}

export function userSupabase(request: Request) {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) throw new Error("unauthorized");
  return createClient(
    required("SUPABASE_URL"),
    namedKey("SUPABASE_PUBLISHABLE_KEYS", "SUPABASE_ANON_KEY"),
    { global: { headers: { Authorization: authorization } }, auth: { persistSession: false } },
  );
}

export function adminSupabase() {
  return createClient(
    required("SUPABASE_URL"),
    namedKey("SUPABASE_SECRET_KEYS", "SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
}

export function stripeClient(): Stripe {
  return new Stripe(required("STRIPE_RESTRICTED_KEY"), {
    apiVersion: "2026-07-29.dahlia",
    httpClient: Stripe.createFetchHttpClient(),
  });
}

export function expectedStripeLivemode(): boolean {
  const configured = optional("STRIPE_LIVEMODE");
  if (configured !== "true" && configured !== "false") {
    throw new Error("billing_not_configured");
  }
  return configured === "true";
}

export function priceChoices(): PriceChoice[] {
  const result: PriceChoice[] = [];
  for (const plan of PLANS) {
    for (const interval of INTERVALS) {
      for (const currency of CURRENCIES) {
        const name = `STRIPE_PRICE_${plan.toUpperCase()}_${interval.toUpperCase()}_${currency.toUpperCase()}`;
        const priceId = optional(name);
        if (priceId) result.push({ plan, interval, currency, priceId });
      }
    }
  }
  return result;
}

export function findPrice(
  plan: unknown,
  interval: unknown,
  currency: unknown,
): PriceChoice | null {
  if (!PLANS.includes(plan as BillingPlan) || !INTERVALS.includes(interval as BillingInterval) || !CURRENCIES.includes(currency as BillingCurrency)) return null;
  return priceChoices().find((entry) => entry.plan === plan && entry.interval === interval && entry.currency === currency) ?? null;
}

export function priceMetadata(priceId: string): Omit<PriceChoice, "priceId"> | null {
  const match = priceChoices().find((entry) => entry.priceId === priceId);
  return match ? { plan: match.plan, interval: match.interval, currency: match.currency } : null;
}

export function stripeId(value: string | { id: string } | null | undefined): string | null {
  if (!value) return null;
  return typeof value === "string" ? value : value.id;
}

export async function requireTenantManager(request: Request, tenantId: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(tenantId)) throw new Error("invalid_tenant");
  const client = userSupabase(request);
  const token = request.headers.get("authorization")!.slice(7);
  const { data: userData, error: userError } = await client.auth.getUser(token);
  if (userError || !userData.user?.email_confirmed_at) throw new Error("unauthorized");
  const { data, error } = await client.from("tenant_memberships")
    .select("role,status")
    .eq("tenant_id", tenantId)
    .eq("status", "active")
    .in("role", ["owner", "admin"])
    .maybeSingle();
  if (error || !data) throw new Error("forbidden");
  return { email: userData.user.email ?? null, role: data.role };
}

export function safeCode(reason: unknown): string {
  const message = reason instanceof Error ? reason.message : String(reason ?? "unknown");
  if (/^(unauthorized|forbidden|invalid_tenant|invalid_request|billing_not_configured|subscription_exists|customer_missing)$/u.test(message)) return message;
  if (message.startsWith("missing:")) return "billing_not_configured";
  return "billing_unavailable";
}
