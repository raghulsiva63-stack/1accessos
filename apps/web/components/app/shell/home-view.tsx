"use client";

import { useEffect, useState } from "react";
import {
  ArrowRight, Bot, CalendarClock, ChevronRight, CreditCard, KeyRound, Laptop, Plus, Search,
  ShieldAlert, ShieldCheck, Sparkles, Vault,
} from "lucide-react";
import { OnboardingChecklist } from "@/components/app/onboarding-checklist";
import { BreachWatchCard } from "@/components/app/breach-watch";
import { ReferralCard } from "@/components/app/referral-card";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { Button } from "@/components/ui/button";
import { loadPublicPlanCatalog, type PublicCatalogPlan } from "@/lib/billing/client";
import { formatPrice, preferredCurrency, upgradeTarget, yearlySavingsPercent } from "@/lib/billing/nudges";
import type { VaultItem } from "@/lib/vault/items";
import { passwordHealth } from "@/lib/vault/tools";
import { type VaultFilter, type Entitlement, ITEM_TYPES } from "@/components/app/shell/shared";

function greeting(hour: number) {
  return hour < 5 ? "Working late" : hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";
}

/** Home: a guided overview — one clear next step, protection status, and what changed recently. */
export function Dashboard({ items, trash, health, entitlement, identityId, tenantId, workspaceCount, onNavigate, onOpenVault, onNew }: { items: VaultItem[]; trash: VaultItem[]; health: ReturnType<typeof passwordHealth>; entitlement: Entitlement; identityId: string; tenantId: string | null; workspaceCount: number; onNavigate: (view: string) => void; onOpenVault: (filter?: VaultFilter) => void; onNew: () => void }) {
  const [hour] = useState(() => new Date().getHours());
  const recent = items.slice(0, 5);
  const issues = health.findings.filter((finding) => finding.severity !== "good");
  const critical = health.findings.filter((finding) => finding.severity === "critical");
  const scoreTone = health.score >= 80 ? "good" : health.score >= 60 ? "fair" : "poor";
  const kinds = Object.entries(items.reduce<Record<string, number>>((counts, item) => ({ ...counts, [item.contentType]: (counts[item.contentType] ?? 0) + 1 }), {}))
    .sort((a, b) => b[1] - a[1]).slice(0, 3) as [keyof typeof ITEM_TYPES, number][];

  const summary = items.length === 0
    ? "Your vault is ready. Add your first password — it is encrypted on this device before it is saved."
    : issues.length === 0
      ? `${items.length} item${items.length === 1 ? "" : "s"} protected and nothing needs your attention.`
      : `${items.length} item${items.length === 1 ? "" : "s"} protected. ${issues.length} thing${issues.length === 1 ? "" : "s"} to improve — start with the step below.`;

  return <div className="dashboard home-v3">
    <section className="home-hero">
      <div className="home-hero-text">
        <span className="status-pill"><ShieldCheck /> Encrypted on this device</span>
        <h2>{greeting(hour)}.</h2>
        <p>{summary}</p>
        <div className="home-actions">
          <Button onClick={onNew}><Plus /> Add item</Button>
          <Button variant="outline" onClick={() => onOpenVault()}><Search /> Find an item</Button>
        </div>
      </div>
      <button type="button" className={`home-score score-${scoreTone}`} onClick={() => onNavigate("security")} aria-label={`Security score ${health.score} out of 100. Open Security.`}>
        <span className="home-score-ring" style={{ "--score": `${health.score * 3.6}deg` } as React.CSSProperties}><strong>{health.score}</strong></span>
        <span className="home-score-label">Security score<small>{issues.length ? `${issues.length} to fix` : "All clear"} <ChevronRight /></small></span>
      </button>
    </section>

    {items.length > 0 && (critical.length > 0 || issues.length > 0) && <section className="home-next" aria-labelledby="next-title">
      <span className={`home-next-icon ${critical.length ? "critical" : ""}`}>{critical.length ? <ShieldAlert /> : <KeyRound />}</span>
      <div>
        <small>Your next step</small>
        <h3 id="next-title">{critical.length ? `Change ${critical.reduce((total, finding) => total + finding.itemIds.length, 0)} reused passwords` : issues[0].title}</h3>
        <p>{critical.length ? "When one site leaks a reused password, attackers try it everywhere else. Security walks you through each one." : issues[0].detail}</p>
      </div>
      <Button onClick={() => onNavigate("security")}>Fix now <ArrowRight /></Button>
    </section>}

    <OnboardingChecklist identityId={identityId} itemCount={items.length} workspaceCount={workspaceCount} planCode={entitlement.plan_code} onNavigate={onNavigate} onNewItem={onNew} />
    <BreachWatchCard key={tenantId ?? "none"} identityId={identityId} tenantId={tenantId} items={items} onReview={() => onNavigate("security")} />

    <div className="home-tiles">
      <button type="button" className="home-tile" onClick={() => onOpenVault()}>
        <span className="home-tile-icon"><Vault /></span>
        <span><small>In your vault</small><strong>{items.length}</strong><em>{kinds.length ? kinds.map(([kind, count]) => `${count} ${ITEM_TYPES[kind].plural.toLowerCase()}`).join(" · ") : `${trash.length} in trash`}</em></span>
      </button>
      <button type="button" className="home-tile" onClick={() => onNavigate("security")}>
        <span className="home-tile-icon"><Sparkles /></span>
        <span><small>AI Security Coach</small><strong>{entitlement.ai_credits_remaining}</strong><em>credits left this month</em></span>
      </button>
      <button type="button" className="home-tile" onClick={() => onNavigate("automations")}>
        <span className="home-tile-icon"><Bot /></span>
        <span><small>Automations</small><strong>{entitlement.automation_runs_remaining}</strong><em>runs left this month</em></span>
      </button>
      <button type="button" className="home-tile" onClick={() => onNavigate("devices")}>
        <span className="home-tile-icon"><Laptop /></span>
        <span><small>Devices</small><strong>{entitlement.max_devices ?? "Unlimited"}</strong><em>{entitlement.max_devices ? "allowed on your plan" : "on your plan"}</em></span>
      </button>
    </div>

    <ReferralCard />

    <div className="home-columns">
      <section className="home-panel" aria-labelledby="recent-title">
        <div className="home-panel-head"><h3 id="recent-title">Recently updated</h3><Button variant="ghost" onClick={() => onOpenVault()}>View all <ChevronRight /></Button></div>
        {recent.length ? <ul className="home-recent">{recent.map((item) => { const Icon = ITEM_TYPES[item.contentType].icon; return <li key={item.id}><button type="button" onClick={() => onOpenVault(item.contentType)}><span className="item-kind-icon"><Icon /></span><span><strong>{item.payload.title}</strong><small>{ITEM_TYPES[item.contentType].label} · {new Date(item.payload.updatedAt).toLocaleDateString()}</small></span><ChevronRight /></button></li>; })}</ul>
          : <div className="home-empty"><Vault /><strong>Nothing here yet</strong><span>Add a password, card or note — or import from another password manager in Settings.</span><Button variant="outline" onClick={onNew}><Plus /> Add your first item</Button></div>}
      </section>
      <PlanPanel entitlement={entitlement} onNavigate={onNavigate} />
    </div>
  </div>;
}

/** Plan panel: Free workspaces see what an upgrade adds; paid workspaces see their plan and the yearly saving. */
export function PlanPanel({ entitlement, onNavigate }: { entitlement: Entitlement; onNavigate: (view: string) => void }) {
  const { tenantKind } = useEnterprise();
  const [catalog, setCatalog] = useState<PublicCatalogPlan[]>([]);
  const [currency] = useState(() => typeof window === "undefined" ? "usd" as const : preferredCurrency(navigator.language, Intl.DateTimeFormat().resolvedOptions().timeZone));
  useEffect(() => {
    let active = true;
    loadPublicPlanCatalog().then((plans) => { if (active) setCatalog(plans); }).catch(() => undefined);
    return () => { active = false; };
  }, []);

  const free = entitlement.plan_code === "free";
  const target = catalog.find((plan) => plan.code === (free ? upgradeTarget(tenantKind) : entitlement.plan_code));
  const monthly = target?.prices.find((price) => price.currency === currency && price.interval === "month");
  const saving = yearlySavingsPercent(target, currency);
  const planName = entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1);

  if (free) {
    return <section className="home-panel home-plan upgrade" aria-labelledby="plan-title">
      <small className="home-plan-kicker">You are on Free</small>
      <h3 id="plan-title">{target ? `Get more with ${target.name}` : "Get more with a paid plan"}</h3>
      <ul>{(target?.features.length ? target.features.slice(0, 4) : ["Unlimited devices", "More monthly AI Security Coach credits", "Priority support"]).map((feature) => <li key={feature}><ShieldCheck /> {feature}</li>)}</ul>
      <p className="home-plan-price">{monthly ? <>From <strong>{formatPrice(monthly.unitAmount, currency)}</strong> a month{monthly.scope === "seat" ? " per person" : ""}{target?.trialDays ? ` · ${target.trialDays}-day free trial` : ""}</> : "Free trial on every paid plan"}</p>
      <Button onClick={() => onNavigate("billing")}>See plans <ArrowRight /></Button>
      <small className="field-hint">Cancel any time · 30-day money-back guarantee</small>
    </section>;
  }

  return <section className="home-panel home-plan" aria-labelledby="plan-title">
    <small className="home-plan-kicker">Your plan</small>
    <h3 id="plan-title">{target?.name ?? planName}</h3>
    <div className="home-plan-row"><CreditCard /><span>{entitlement.subscription_status.replaceAll("_", " ")}</span></div>
    {entitlement.valid_until && <div className="home-plan-row"><CalendarClock /><span>Current period ends {new Date(entitlement.valid_until).toLocaleDateString()}</span></div>}
    {saving && <p className="home-plan-save">Paying monthly? Switch to yearly billing and save {saving}%.</p>}
    <Button variant="outline" onClick={() => onNavigate("billing")}>Manage plan <ArrowRight /></Button>
  </section>;
}
