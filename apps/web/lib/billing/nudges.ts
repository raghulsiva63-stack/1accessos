import type { BillingCurrency, PlanCode, PublicCatalogPlan } from "@/lib/billing/client";

/** Whole-percent saving of paying yearly instead of 12 monthly payments, or null if unknown. */
export function yearlySavingsPercent(plan: Pick<PublicCatalogPlan, "prices"> | undefined, currency: BillingCurrency): number | null {
  const month = plan?.prices.find((price) => price.currency === currency && price.interval === "month")?.unitAmount;
  const year = plan?.prices.find((price) => price.currency === currency && price.interval === "year")?.unitAmount;
  if (!month || !year || month <= 0) return null;
  const percent = Math.round((1 - year / (month * 12)) * 100);
  return percent > 0 && percent < 100 ? percent : null;
}

/** The plan a Free workspace is invited to try, by workspace kind. */
export function upgradeTarget(tenantKind: string | null): Exclude<PlanCode, "free"> {
  if (tenantKind === "family") return "family";
  if (tenantKind === "organization") return "team";
  return "personal";
}

/** Guess the visitor's billing currency: INR in India, otherwise USD. */
export function preferredCurrency(locale: string | undefined, timeZone: string | undefined): BillingCurrency {
  if (timeZone === "Asia/Kolkata" || timeZone === "Asia/Calcutta" || /-IN$/iu.test(locale ?? "")) return "inr";
  return "usd";
}

export function formatPrice(amountMinor: number, currency: BillingCurrency) {
  return new Intl.NumberFormat(currency === "inr" ? "en-IN" : "en-US", {
    style: "currency", currency: currency.toUpperCase(), maximumFractionDigits: amountMinor % 100 === 0 ? 0 : 2,
  }).format(amountMinor / 100);
}
