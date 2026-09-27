"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Building2, Check, KeyRound, ShieldCheck, Sparkles, Users } from "lucide-react";
import { publicCatalogEnabled, loadPublicPlanCatalog, rememberPlanSelection, stripeTestMode, type BillingCurrency, type BillingInterval, type PublicCatalogPlan } from "@/lib/billing/client";

function money(amountMinor: number, currency: BillingCurrency) {
  return new Intl.NumberFormat(currency === "inr" ? "en-IN" : "en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    maximumFractionDigits: currency === "inr" ? 0 : 2,
  }).format(amountMinor / 100);
}

function PlanPrice({ plan, currency, interval }: { plan: PublicCatalogPlan; currency: BillingCurrency; interval: BillingInterval }) {
  if (plan.billingModel === "contract") return <div className="public-plan-price"><strong>Custom</strong><span>Contract pricing and controls</span></div>;
  const price = plan.prices.find((entry) => entry.currency === currency && entry.interval === interval);
  if (!price) return <div className="public-plan-price"><strong>Not available</strong><span>Pricing is not configured for this selection</span></div>;
  if (price.unitAmount === 0) return <div className="public-plan-price"><strong>{money(0, currency)}</strong><span>Free forever</span></div>;
  const perMonth = interval === "year" ? Math.round(price.unitAmount / 12) : price.unitAmount;
  const unit = price.scope === "seat" ? "per user / month" : "per month";
  return <div className="public-plan-price"><strong>{money(perMonth, currency)}</strong><span>{unit}</span>{interval === "year" && <small>{money(price.unitAmount, currency)} billed yearly{price.scope === "seat" ? " per user" : ""}</small>}</div>;
}

function PlanCard({ plan, currency, interval, office = false }: { plan: PublicCatalogPlan; currency: BillingCurrency; interval: BillingInterval; office?: boolean }) {
  const seats = plan.billingModel === "per_seat"
    ? `${plan.minSeats} user minimum${plan.maxSeats ? ` · up to ${plan.maxSeats}` : ""}`
    : plan.code === "family" ? "Up to 6 people" : plan.code === "enterprise" ? "Contracted users" : "1 user";
  return <article className={`public-plan-card ${plan.featured ? "featured" : ""} ${office ? "office" : ""}`}>
    {plan.featured && <span className="public-plan-badge">Best for offices</span>}
    <div className="public-plan-heading"><span className="public-plan-icon">{plan.code === "business" || plan.code === "enterprise" ? <Building2 /> : plan.code === "team" || plan.code === "family" ? <Users /> : <KeyRound />}</span><div><p>{plan.audience}</p><h3>{plan.name}</h3></div></div>
    <p className="public-plan-summary">{plan.summary}</p>
    <PlanPrice plan={plan} currency={currency} interval={interval} />
    <div className="public-plan-meta"><span><Users /> {seats}</span>{plan.trialDays > 0 && <span><Sparkles /> {plan.trialDays}-day trial policy</span>}</div>
    <a className={plan.featured ? "public-plan-action primary" : "public-plan-action"} href="/login" onClick={() => rememberPlanSelection(plan.code)}>{plan.code === "enterprise" ? "Request an enterprise pilot" : plan.code === "free" ? "Start free" : `Choose ${plan.name}`} <ArrowRight /></a>
    <ul>{plan.features.map((feature) => <li key={feature}><Check /> <span>{feature}</span></li>)}</ul>
    {plan.commercialStatus !== "active" && <p className="public-plan-status">Sales-assisted plan · self-service checkout is unavailable for this package</p>}
  </article>;
}

export function PricingSection() {
  const [plans, setPlans] = useState<PublicCatalogPlan[]>([]);
  const [currency, setCurrency] = useState<BillingCurrency>("inr");
  const [interval, setInterval] = useState<BillingInterval>("year");
  const [catalogState, setCatalogState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    if (!publicCatalogEnabled) return;
    let active = true;
    loadPublicPlanCatalog()
      .then((catalog) => { if (active) { setPlans(catalog); setCatalogState(catalog.length ? "ready" : "error"); } })
      .catch(() => { if (active) setCatalogState("error"); });
    return () => { active = false; };
  }, []);

  const individualPlans = useMemo(() => plans.filter((plan) => ["free", "personal", "family", "professional"].includes(plan.code)), [plans]);
  const officePlans = useMemo(() => plans.filter((plan) => ["team", "business"].includes(plan.code)), [plans]);
  const enterprise = plans.find((plan) => plan.code === "enterprise");

  return <section className="public-pricing" id="pricing">
      {!publicCatalogEnabled ? <div className="public-catalog-state" role="status"><h2>Paid plans are not available yet</h2><p>Commercial terms are awaiting approval. Paid checkout is disabled.</p></div> : <>
      <div className="public-section-heading"><div><span className="public-kicker"><Sparkles /> Versioned launch catalog</span><h2>A clear plan for every way you work.</h2><p>Prices and package capabilities come from the server-managed 2026-09-v2.2 catalog—not from hard-coded page copy.</p></div><div className="public-pricing-controls" aria-label="Pricing options"><div><button className={currency === "inr" ? "active" : ""} onClick={() => setCurrency("inr")}>INR</button><button className={currency === "usd" ? "active" : ""} onClick={() => setCurrency("usd")}>USD</button></div><div><button className={interval === "month" ? "active" : ""} onClick={() => setInterval("month")}>Monthly</button><button className={interval === "year" ? "active" : ""} onClick={() => setInterval("year")}>Yearly</button></div></div></div>

      {catalogState === "loading" && <div className="public-catalog-state" role="status">Loading the verified plan catalog…</div>}
      {catalogState === "error" && <div className="public-catalog-state error" role="status">Plan pricing is temporarily unavailable. You can still create a Free account, and no paid change will be made.</div>}
      {catalogState === "ready" && <>
        <div className="public-plan-grid individual">{individualPlans.map((plan) => <PlanCard key={plan.code} plan={plan} currency={currency} interval={interval} />)}</div>
        <div className="public-office-heading" id="teams"><div><span className="public-kicker"><Users /> Teams and offices</span><h2>Choose Team for one workgroup. Choose Business for an organization.</h2></div><p id="business">Business is the package for departments, multiple teams, delegated administrators, employee lifecycle controls, policies, and organization-wide access intelligence.</p></div>
        <div className="public-plan-grid office">{officePlans.map((plan) => <PlanCard key={plan.code} plan={plan} currency={currency} interval={interval} office />)}</div>
        {enterprise && <PlanCard plan={enterprise} currency={currency} interval={interval} office />}
      </>}
      <p className="public-pricing-note"><ShieldCheck /> {stripeTestMode ? "Checkout uses Stripe sandbox only: test cards, no real charges. Displayed amounts are the v2.2 test catalog." : "Displayed amounts are the active server-managed catalog. Tax is collected only where configured and registered."}</p>
      </>}
    </section>;
}
