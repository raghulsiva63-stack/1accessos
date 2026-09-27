"use client";

import Image from "next/image";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ArrowRight, Building2, Check, Code2, FileClock, Fingerprint, FolderLock, KeyRound, LayoutDashboard, Link2, Menu,
  Send, ShieldCheck, SlidersHorizontal, Sparkles, TimerOff, UserX, Users,
} from "lucide-react";
import { CtaBand, MarketingFooter } from "@/components/marketing/marketing-shell";
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

const ORG_FEATURES = [
  { icon: LayoutDashboard, title: "Admin console", body: "Organization health, members at risk and 2-step coverage at a glance, with a one-click security baseline." },
  { icon: SlidersHorizontal, title: "Enforced policies", body: "Require passkeys or 2-step sign-in, vault password strength, auto-lock, clipboard clearing and export control." },
  { icon: FileClock, title: "Tamper-evident audit", body: "Hash-chained activity log with one-click integrity verification and CSV or JSON evidence export." },
  { icon: FolderLock, title: "Access reviews", body: "Who can open each shared vault, with just-in-time expiry and quarterly certification evidence." },
  { icon: UserX, title: "Offboarding in seconds", body: "Suspend or offboard a member, revoke their keys and flag affected vaults for rotation." },
  { icon: Fingerprint, title: "Phishing-resistant sign-in", body: "Passkeys and authenticator apps protect the account; a separate vault password protects the data." },
];

const HOME_FAQ: [string, string][] = [
  ["Is Passkey-X really zero-knowledge?", "Yes. Your vault is encrypted on your device with a key derived from a vault password we never receive. We store ciphertext only."],
  ["What is the difference between Team and Business?", "Team fits one workgroup sharing vaults with roles. Business adds departments, delegated admins, enforced policies, access reviews, lifecycle controls and the tamper-evident audit trail."],
  ["Can I import from my current password manager?", "Yes. Export a CSV from your browser or password manager and import it in Settings. The file is parsed on your device and each entry is encrypted before upload."],
  ["Which devices are supported?", "Passkey-X runs in any modern browser and has desktop, mobile and browser-extension clients. See the Apps page for downloads."],
  ["What happens if I forget my vault password?", "Use the recovery key you saved at setup. Without it, nobody — including Passkey-X — can decrypt your vault."],
];

export function PublicSite({ children }: { children: ReactNode }) {
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

  const links = <><a href="#product">Product</a><a href="/enterprise">Enterprise</a>{publicCatalogEnabled && <><a href="#teams">Teams</a><a href="#business">Business</a></>}<a href="#security">Security</a><a href="#pricing">Pricing</a><a href="/compare">Compare</a><a href="/download">Apps</a><a href="/api-docs">API</a></>;

  return <main className="public-site">
    <header className="public-header">
      <a className="public-brand" href="#product" aria-label="Passkey-X home"><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={230} height={66} priority /></a>
      <nav aria-label="Main navigation">{links}</nav>
      <div className="public-header-actions"><a className="public-signin" href="/contact">Talk to sales</a><a className="public-signin" href="/login">Sign in</a><a className="public-primary-link compact" href="/login">Start free <ArrowRight /></a></div>
      <details className="public-mobile-menu"><summary aria-label="Open navigation"><Menu /></summary><nav>{links}<a href="/contact">Talk to sales</a><a href="/login">Sign in</a></nav></details>
    </header>

    <section className="public-hero" id="product">
      <div className="public-hero-copy">
        <span className="public-kicker"><ShieldCheck /> Client-side encrypted access</span>
        <h1>Passwords are only the beginning.</h1>
        <p>Passkey-X protects passwords, passkeys, developer secrets, recovery codes, and team access in one zero-knowledge workspace—without giving the service your vault password.</p>
        <div className="public-hero-actions"><a className="public-primary-link" href="/login">Create your vault <ArrowRight /></a><a className="public-secondary-link" href="#pricing">Compare plans</a></div>
        <div className="public-assurance"><span><Fingerprint /> Separate vault unlock</span><span><ShieldCheck /> Tamper detection</span><span><KeyRound /> Recovery key</span></div>
      </div>
      <div className="public-access" id="access">{children}</div>
    </section>

    <section className="public-value-strip" aria-label="Passkey-X capabilities">
      <span><ShieldCheck /><strong>Zero-knowledge boundary</strong><small>Encryption before sync</small></span>
      <span><Users /><strong>Personal to Business</strong><small>Isolated workspace keys</small></span>
      <span><Code2 /><strong>Developer ready</strong><small>API and CLI foundation</small></span>
      <span><Fingerprint /><strong>Passkey ready</strong><small>Domain-bound sign-in</small></span>
    </section>

    <section className="public-security" id="security">
      <div><span className="public-kicker"><ShieldCheck /> Designed around the breach</span><h2>Your service provider should not become your master key.</h2></div>
      <div className="public-security-grid"><article><span>01</span><h3>Encrypt locally</h3><p>Vault content and workspace keys are encrypted in the trusted client before they reach storage.</p></article><article><span>02</span><h3>Authorize every row</h3><p>Tenant and workspace membership checks protect every accessible object, including negative cross-tenant paths.</p></article><article><span>03</span><h3>Revoke deliberately</h3><p>Device and employee revocation remove key envelopes and force affected workspaces into key rotation.</p></article></div>
    </section>

    <section className="mk-section mk-home-features" id="organizations">
      <div className="mk-section-heading"><span className="public-kicker"><Building2 /> For organizations</span><h2>Govern every credential in your company — without seeing any of them.</h2><p>Admin console, enforced policies, access reviews and a tamper-evident audit trail, on top of client-side encryption.</p></div>
      <div className="mk-card-grid three">{ORG_FEATURES.map((item) => { const Icon = item.icon; return <article key={item.title} className="mk-card"><span className="mk-card-icon"><Icon /></span><h3>{item.title}</h3><p>{item.body}</p></article>; })}</div>
      <a className="mk-text-link" href="/enterprise">Explore Passkey-X for Enterprise <ArrowRight /></a>
    </section>

    <section className="mk-section mk-highlight" id="secure-send">
      <div><span className="public-kicker"><Send /> Secure Send</span><h2>Stop pasting passwords into chat.</h2><p>Send a password, note or file to anyone as an end-to-end encrypted link. It opens once — or a few times — then destroys itself.</p>
        <ul className="mk-checklist"><li><Check /> The decryption key lives only in the link, never on our servers</li><li><Check /> Optional passphrase, sent through a different channel</li><li><Check /> Expiry from one hour to 30 days, and revoke any time</li><li><Check /> Recipients do not need a Passkey-X account</li></ul>
      </div>
      <div className="mk-highlight-visual" aria-hidden><span><Link2 /> passkey-x.com/send#…</span><code>AES-256-GCM · key in URL fragment · 1 view left</code><span><TimerOff /> Burns after reading</span></div>
    </section>

    <section className="public-pricing" id="pricing">
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
    </section>

    <section className="mk-section" id="faq">
      <div className="mk-section-heading"><span className="public-kicker"><Sparkles /> Questions</span><h2>Frequently asked questions</h2></div>
      <div className="mk-faq">{HOME_FAQ.map(([question, answer]) => <details key={question}><summary>{question}</summary><p>{answer}</p></details>)}</div>
    </section>

    <CtaBand title="Ready to protect your whole organization?" body="Book a walkthrough, or start free and invite your team when you are ready." />
    <MarketingFooter />
  </main>;
}
