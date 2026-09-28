"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft, ArrowRight, Building2, Check, CircleHelp, CreditCard, HeartHandshake, LoaderCircle, PartyPopper,
  Plus, RefreshCw, ShieldCheck, Sparkles, UserRound, Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import {
  beginCheckout, billingEnabled, clearPlanSelection, loadPublicPlanCatalog, loadTenantEntitlement, openCustomerPortal,
  readPlanSelection, stripeTestMode, type BillingCurrency, type BillingInterval, type PlanCode, type PublicCatalogPlan,
  type TenantEntitlement,
} from "@/lib/billing/client";
import { createSharedWorkspace } from "@/lib/collaboration/phase2";
import type { WorkspaceVault } from "@/lib/vault/items";

type Audience = "me" | "family" | "team";
type PaidPlan = Exclude<PlanCode, "free">;
type Step = "overview" | "audience" | "plan" | "place" | "review" | "activating";
type Place =
  | { kind: "existing"; tenantId: string; workspaceId: string; name: string }
  | { kind: "new"; name: string };
type ReturnInfo = { workspaceId: string; tenantId: string; plan: PaidPlan; name: string };
type Activation = { state: "waiting" | "active" | "slow"; plan: string; name: string };

const AUDIENCE_PLANS: Record<Audience, PaidPlan[]> = {
  me: ["personal", "professional"],
  family: ["family"],
  team: ["team", "business"],
};
const PLAN_AUDIENCE: Record<PaidPlan, Audience> = {
  personal: "me", professional: "me", family: "family", team: "team", business: "team",
};
const PLAN_LABEL: Record<PlanCode, string> = {
  free: "Free", personal: "Personal", family: "Family", professional: "Professional", team: "Team", business: "Business",
};
const STATUS_LABEL: Record<string, string> = {
  none: "Free plan", trialing: "Free trial", active: "Active", past_due: "Payment due", unpaid: "Payment failed",
  canceled: "Cancelled", incomplete: "Waiting for payment", incomplete_expired: "Payment not completed", paused: "Paused",
};
const RETURN_KEY = "passkey-x:billing-return";
const ACTIVATED_KEY = "passkey-x:billing-activated";
const STEPS: { id: Step; label: string }[] = [
  { id: "audience", label: "Who is it for" },
  { id: "plan", label: "Choose a plan" },
  { id: "place", label: "Where it applies" },
  { id: "review", label: "Review and pay" },
];

function workspaceAudience(workspace: WorkspaceVault): Audience {
  return workspace.suite === "personal" ? "me" : workspace.suite === "family" ? "family" : "team";
}

function workspaceKindLabel(workspace: WorkspaceVault) {
  if (workspace.suite === "personal") return "Your personal vault";
  if (workspace.suite === "family") return "Family vault";
  return "Organisation";
}

function money(amountMinor: number, currency: BillingCurrency) {
  return new Intl.NumberFormat(currency === "inr" ? "en-IN" : "en-US", {
    style: "currency", currency: currency.toUpperCase(), maximumFractionDigits: currency === "inr" ? 0 : 2,
  }).format(amountMinor / 100);
}

/** Plain-language message for every error the billing service can return. */
export function billingMessage(reason: unknown, fallback: string) {
  const detail = reason instanceof Error ? reason.message : String((reason as { message?: string } | null)?.message ?? reason ?? "");
  const messages: [string, string][] = [
    ["plan_not_available_for_workspace", "That plan belongs to a different kind of vault. Choose Change plan and follow the steps: Passkey-X picks or creates the right place for it."],
    ["subscription_exists", "This vault or organisation already has a subscription. Use Manage billing to change the plan, seats or card."],
    ["forbidden", "Only the owner or an admin of this vault or organisation can change its plan."],
    ["mfa_required", "Confirm your two-step verification first: sign out, sign in again and enter your code, then try once more."],
    ["unauthorized", "Your session has expired. Sign in again, then try once more."],
    ["billing_disabled", "Payments are not switched on yet. Nothing was charged."],
    ["billing_not_configured", "Payments are not switched on yet. Nothing was charged."],
    ["invalid_quantity", "Choose a number of seats within the plan's range."],
    ["customer_missing", "There is no billing account for this vault yet. Choose Change plan to start a subscription."],
    ["invalid_tenant", "That vault or organisation could not be found. Refresh the page and try again."],
    ["collaboration entitlement", "Your account cannot create shared vaults right now. Contact support."],
    ["billing_unavailable", "The payment service did not respond. Nothing was charged. Try again in a minute."],
  ];
  const match = messages.find(([code]) => detail.includes(code));
  return match ? match[1] : fallback;
}

function readReturnInfo(): ReturnInfo | null {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(RETURN_KEY) ?? "null") as ReturnInfo | null;
    return parsed && typeof parsed.tenantId === "string" && typeof parsed.workspaceId === "string" ? parsed : null;
  } catch { return null; }
}

function readActivated(): Activation | null {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(ACTIVATED_KEY) ?? "null") as Activation | null;
    window.sessionStorage.removeItem(ACTIVATED_KEY);
    return parsed && parsed.state === "active" ? parsed : null;
  } catch { return null; }
}

function initialState(): { step: Step; audience: Audience | null; plan: PaidPlan | null; message: string; activation: Activation | null } {
  if (typeof window === "undefined") return { step: "overview", audience: null, plan: null, message: "", activation: null };
  const activated = readActivated();
  if (activated) return { step: "activating", audience: null, plan: null, message: "", activation: activated };
  const result = new URLSearchParams(window.location.search).get("billing");
  if (result === "success") return { step: "activating", audience: null, plan: null, message: "", activation: null };
  if (result === "cancelled") return { step: "overview", audience: null, plan: null, message: "Checkout was cancelled. Nothing was charged and your plan is unchanged.", activation: null };
  if (result === "portal-return") return { step: "overview", audience: null, plan: null, message: "Welcome back. Changes you made in the billing portal appear here within a minute.", activation: null };
  const selected = readPlanSelection();
  if (selected) return { step: "plan", audience: PLAN_AUDIENCE[selected], plan: selected, message: "", activation: null };
  return { step: "overview", audience: null, plan: null, message: "", activation: null };
}

export function PlansView({
  vault, workspaces, entitlement, identityId, rootKey, onSelectWorkspace, onRefresh, onOpenHelp, onOpenAdmin,
}: {
  vault: WorkspaceVault;
  workspaces: WorkspaceVault[];
  entitlement: TenantEntitlement;
  identityId: string;
  rootKey: Uint8Array;
  onSelectWorkspace: (workspaceId: string) => Promise<void>;
  onRefresh: () => Promise<void>;
  onOpenHelp: () => void;
  onOpenAdmin: () => void;
}) {
  const { isTenantAdmin } = useEnterprise();
  const [start] = useState(initialState);
  const [step, setStep] = useState<Step>(start.step);
  const [audience, setAudience] = useState<Audience | null>(start.audience);
  const [plan, setPlan] = useState<PaidPlan | null>(start.plan);
  const [message, setMessage] = useState(start.message);
  const [catalog, setCatalog] = useState<PublicCatalogPlan[]>([]);
  const [catalogState, setCatalogState] = useState<"loading" | "ready" | "error">("loading");
  const [currency, setCurrency] = useState<BillingCurrency>("inr");
  const [interval, setInterval] = useState<BillingInterval>("month");
  const [seats, setSeats] = useState({ team: 3, business: 5 });
  const [place, setPlace] = useState<Place | null>(null);
  const [newName, setNewName] = useState("");
  const [busy, setBusy] = useState("");
  const [plans, setPlans] = useState<Record<string, TenantEntitlement>>({});
  const [activation, setActivation] = useState<Activation | null>(start.activation);

  const canManage = vault.role === "owner" || isTenantAdmin;
  const ownedPlaces = useMemo(() => {
    const byTenant = new Map<string, WorkspaceVault>();
    for (const workspace of workspaces) if (workspace.role === "owner" && !byTenant.has(workspace.tenantId)) byTenant.set(workspace.tenantId, workspace);
    return [...byTenant.values()];
  }, [workspaces]);
  const ownedTenantKey = ownedPlaces.map((workspace) => workspace.tenantId).join(",");

  useEffect(() => {
    let active = true;
    loadPublicPlanCatalog()
      .then((rows) => { if (active) { setCatalog(rows); setCatalogState(rows.length ? "ready" : "error"); } })
      .catch(() => { if (active) setCatalogState("error"); });
    return () => { active = false; };
  }, []);

  // The plan of every vault and organisation you own, so you can see where each plan lives.
  useEffect(() => {
    let active = true;
    const tenantIds = ownedTenantKey ? ownedTenantKey.split(",") : [];
    Promise.all(tenantIds.map(async (tenantId) => [tenantId, await loadTenantEntitlement(tenantId)] as const))
      .then((rows) => { if (active) setPlans(Object.fromEntries(rows)); })
      .catch(() => undefined);
    return () => { active = false; };
  }, [ownedTenantKey, entitlement]);

  // Back from Stripe: open the vault that was upgraded and wait for the verified payment.
  useEffect(() => {
    if (start.step !== "activating" || start.activation) return;
    let active = true;
    let attempts = 0;
    let timer: number | undefined;
    const info = readReturnInfo();
    try { window.history.replaceState(null, "", window.location.pathname + window.location.hash); } catch { /* ignore */ }
    const tenantId = info?.tenantId ?? vault.tenantId;
    const label = info ? PLAN_LABEL[info.plan] : "Your plan";
    const name = info?.name ?? vault.name;
    const poll = async () => {
      attempts += 1;
      try {
        const next = await loadTenantEntitlement(tenantId);
        if (!active) return;
        if (next.plan_code !== "free" && ["trialing", "active"].includes(next.subscription_status)) {
          const done: Activation = { state: "active", plan: PLAN_LABEL[next.plan_code], name };
          setActivation(done);
          try { window.localStorage.removeItem(RETURN_KEY); } catch { /* ignore */ }
          if (info && info.workspaceId !== vault.workspaceId && workspaces.some((entry) => entry.workspaceId === info.workspaceId)) {
            // Switching workspace reloads this screen; keep the confirmation for the reloaded view.
            try { window.sessionStorage.setItem(ACTIVATED_KEY, JSON.stringify(done)); } catch { /* ignore */ }
            await onSelectWorkspace(info.workspaceId);
          } else await onRefresh();
          return;
        }
      } catch { /* keep waiting */ }
      if (!active) return;
      if (attempts >= 20) { setActivation({ state: "slow", plan: label, name }); return; }
      timer = window.setTimeout(() => { void poll(); }, 3000);
    };
    void Promise.resolve().then(() => { if (active) setActivation({ state: "waiting", plan: label, name }); }).then(poll);
    return () => { active = false; if (timer) window.clearTimeout(timer); };
    // Runs once for this return from Stripe.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const catalogPlan = (code: PlanCode | null) => catalog.find((entry) => entry.code === code);
  const priceFor = (code: PaidPlan) => catalogPlan(code)?.prices.find((entry) => entry.currency === currency && entry.interval === interval);
  const seatCount = plan === "team" || plan === "business" ? seats[plan] : 1;
  const candidates = audience === "family"
    ? ownedPlaces.filter((workspace) => workspace.suite === "family")
    : audience === "team" ? ownedPlaces.filter((workspace) => workspace.suite === "team" || workspace.suite === "business") : [];
  const personalVault = ownedPlaces.find((workspace) => workspace.suite === "personal");
  const placeTenantId = place?.kind === "existing" ? place.tenantId : null;
  const placeEntitlement = placeTenantId ? plans[placeTenantId] : undefined;
  const placeHasSubscription = Boolean(placeEntitlement && placeEntitlement.source === "stripe" && ["trialing", "active", "past_due", "unpaid", "paused"].includes(placeEntitlement.subscription_status));

  function adjustSeats(code: "team" | "business", next: number, limits: { min: number; max: number }) {
    if (!Number.isSafeInteger(next)) return;
    setSeats((current) => ({ ...current, [code]: Math.min(limits.max, Math.max(limits.min, next)) }));
  }

  const reviewDetails = plan ? catalogPlan(plan) : undefined;
  const reviewPrice = plan ? priceFor(plan) : undefined;
  const reviewTotal = reviewPrice ? reviewPrice.unitAmount * (reviewPrice.scope === "seat" ? seatCount : 1) : null;
  const reviewPlaceName = place?.kind === "existing" ? place.name : place?.kind === "new" ? newName.trim() || "New" : "Your personal vault";

  function startChange() { setMessage(""); setActivation(null); setStep("audience"); }

  function chooseAudience(next: Audience) {
    setAudience(next);
    if (!plan || PLAN_AUDIENCE[plan] !== next) setPlan(null);
    setStep("plan");
  }

  function choosePlan(next: PaidPlan) {
    setPlan(next); setMessage("");
    const who = PLAN_AUDIENCE[next];
    setAudience(who);
    if (who === "me") {
      setPlace(personalVault ? { kind: "existing", tenantId: personalVault.tenantId, workspaceId: personalVault.workspaceId, name: personalVault.name } : null);
      setStep("review");
      return;
    }
    const matches = who === "family"
      ? ownedPlaces.filter((workspace) => workspace.suite === "family")
      : ownedPlaces.filter((workspace) => workspace.suite === "team" || workspace.suite === "business");
    const current = matches.find((workspace) => workspace.tenantId === vault.tenantId) ?? matches[0];
    setPlace(current ? { kind: "existing", tenantId: current.tenantId, workspaceId: current.workspaceId, name: current.name } : { kind: "new", name: "" });
    setNewName(who === "family" ? "Our family" : "");
    setStep("place");
  }

  function back() {
    setMessage("");
    if (step === "review") setStep(audience === "me" ? "plan" : "place");
    else if (step === "place") setStep("plan");
    else if (step === "plan") setStep("audience");
    else setStep("overview");
  }

  async function checkout() {
    if (!plan || !place) return;
    setBusy("checkout"); setMessage("");
    try {
      let target = place;
      if (target.kind === "new") {
        const name = newName.trim();
        if (name.length < 2) throw new Error("name_required");
        const created = await createSharedWorkspace(identityId, rootKey, name, audience === "family" ? "family" : plan === "business" ? "business" : "team");
        created.key.fill(0);
        target = { kind: "existing", tenantId: created.tenantId, workspaceId: created.workspaceId, name: created.name };
        // Keep this screen open: the new place appears in the workspace list after checkout.
        setPlace(target);
      }
      try { window.localStorage.setItem(RETURN_KEY, JSON.stringify({ workspaceId: target.workspaceId, tenantId: target.tenantId, plan, name: target.name } satisfies ReturnInfo)); } catch { /* ignore */ }
      const url = await beginCheckout(target.tenantId, plan, interval, currency, seatCount);
      clearPlanSelection();
      window.location.assign(url);
    } catch (reason) {
      setMessage(reason instanceof Error && reason.message === "name_required"
        ? "Give it a name of at least 2 characters."
        : billingMessage(reason, "Checkout could not be started. Nothing was charged. Try again in a minute."));
      setBusy("");
    }
  }

  async function portal(tenantId: string) {
    setBusy("portal"); setMessage("");
    try { window.location.assign(await openCustomerPortal(tenantId)); }
    catch (reason) { setMessage(billingMessage(reason, "The billing portal could not be opened. Try again in a minute.")); setBusy(""); }
  }

  async function refresh() {
    setBusy("refresh"); setMessage("");
    try { await onRefresh(); setMessage("Plan details refreshed."); }
    catch { setMessage("The plan could not be refreshed. Try again in a minute."); }
    finally { setBusy(""); }
  }

  const toggles = <div className="pv-toggles">
    <div className="billing-segment" role="group" aria-label="Billing period"><button type="button" className={interval === "month" ? "active" : ""} onClick={() => setInterval("month")}>Monthly</button><button type="button" className={interval === "year" ? "active" : ""} onClick={() => setInterval("year")}>Yearly <small>save ~17%</small></button></div>
    <div className="billing-segment" role="group" aria-label="Currency"><button type="button" className={currency === "inr" ? "active" : ""} onClick={() => setCurrency("inr")}>₹ INR</button><button type="button" className={currency === "usd" ? "active" : ""} onClick={() => setCurrency("usd")}>$ USD</button></div>
  </div>;

  const stepIndex = STEPS.findIndex((entry) => entry.id === step);
  const visibleSteps = audience === "me" ? STEPS.filter((entry) => entry.id !== "place") : STEPS;

  return <div className="feature-page plans-view">
    <div className="pv-header">
      <div><span className="status-pill"><CreditCard /> Plans &amp; billing</span><h2>{step === "overview" ? "Your plan" : step === "activating" ? "Activating your plan" : "Change your plan"}</h2>
        <p>{step === "overview" ? "See what you have, change plan in a few guided steps, or manage payments." : step === "activating" ? "Stripe confirmed the payment. Passkey-X is switching on your plan." : "Answer a few questions. You can go back at any time, and nothing is charged until you pay on Stripe's secure page."}</p></div>
      <Button variant="ghost" onClick={onOpenHelp}><CircleHelp /> Help</Button>
    </div>

    {stepIndex >= 0 && <ol className="pv-steps" aria-label="Progress">{visibleSteps.map((entry, index) => {
      const position = STEPS.findIndex((candidate) => candidate.id === entry.id);
      return <li key={entry.id} className={position === stepIndex ? "current" : position < stepIndex ? "done" : ""}><span>{position < stepIndex ? <Check /> : index + 1}</span>{entry.label}</li>;
    })}</ol>}

    {message && <p className="pv-message" role="status">{message}</p>}
    {stripeTestMode && step !== "overview" && step !== "activating" && <div className="pv-note"><ShieldCheck /><p><strong>Test mode.</strong> No real money is taken. On the Stripe page use card number <code>4242 4242 4242 4242</code>, any future date and any 3-digit code.</p></div>}

    {step === "overview" && <>
      <section className="pv-current">
        <div className="pv-current-main">
          <small>{workspaceKindLabel(vault)} · {vault.name}</small>
          <strong>{PLAN_LABEL[entitlement.plan_code] ?? entitlement.plan_code}</strong>
          <span className={`pv-status ${entitlement.subscription_status}`}>{STATUS_LABEL[entitlement.subscription_status] ?? entitlement.subscription_status}</span>
        </div>
        <dl className="pv-facts">
          <div><dt>People</dt><dd>{entitlement.max_members === 1 ? "Just you" : `Up to ${entitlement.max_members}`}</dd></div>
          <div><dt>Devices</dt><dd>{entitlement.max_devices === null ? "Unlimited" : entitlement.max_devices}</dd></div>
          <div><dt>{entitlement.subscription_status === "canceled" ? "Ended" : "Renews"}</dt><dd>{entitlement.valid_until ? new Date(entitlement.valid_until).toLocaleDateString() : "—"}</dd></div>
        </dl>
        <div className="pv-actions">
          <Button onClick={startChange} disabled={!billingEnabled}><Sparkles /> {entitlement.plan_code === "free" ? "Upgrade" : "Change plan"}</Button>
          {entitlement.source === "stripe" && canManage && <Button variant="outline" disabled={busy !== ""} onClick={() => void portal(vault.tenantId)}>{busy === "portal" ? <LoaderCircle className="spin" /> : <CreditCard />} Manage billing</Button>}
          <Button variant="ghost" disabled={busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button>
        </div>
        {entitlement.source === "stripe" && <p className="pv-hint">Manage billing opens Stripe&apos;s secure portal, where you can update your card, change seats, download invoices or cancel.</p>}
        {!canManage && <p className="pv-hint">Only the owner or an admin of this {vault.suite === "personal" ? "vault" : "organisation"} can change its plan.</p>}
        {!billingEnabled && <p className="pv-hint">Payments are not switched on yet, so plans cannot be changed. Nothing will be charged.</p>}
      </section>

      {ownedPlaces.length > 1 && <section className="pv-card">
        <h3>All your plans</h3>
        <p className="pv-hint">Each plan belongs to one vault or organisation. Switch to one to manage it.</p>
        <ul className="pv-places">{ownedPlaces.map((workspace) => { const current = plans[workspace.tenantId]; return <li key={workspace.tenantId} className={workspace.tenantId === vault.tenantId ? "current" : ""}>
          <span className="pv-place-icon">{workspace.suite === "personal" ? <UserRound /> : workspace.suite === "family" ? <HeartHandshake /> : <Building2 />}</span>
          <span><strong>{workspace.name}</strong><small>{workspaceKindLabel(workspace)}</small></span>
          <em>{current ? `${PLAN_LABEL[current.plan_code] ?? current.plan_code} · ${STATUS_LABEL[current.subscription_status] ?? current.subscription_status}` : "…"}</em>
          {workspace.tenantId !== vault.tenantId && <Button size="sm" variant="outline" onClick={() => void onSelectWorkspace(workspace.workspaceId)}>Switch</Button>}
        </li>; })}</ul>
      </section>}

      <p className="pv-hint"><ShieldCheck /> For your security, a plan only changes after Passkey-X receives a signed Stripe webhook confirming the payment. A web address alone can never unlock a paid plan.</p>

      <section className="pv-explain">
        <div><UserRound /><strong>Personal and Professional</strong><p>For one person. Applies to your personal vault.</p></div>
        <div><HeartHandshake /><strong>Family</strong><p>Up to 6 people. Applies to a family vault that you share.</p></div>
        <div><Building2 /><strong>Team and Business</strong><p>For companies. Applies to an organisation with admin controls. We create it for you if you don&apos;t have one.</p></div>
      </section>
    </>}

    {step === "audience" && <section className="pv-card">
      <h3>Who is this plan for?</h3>
      <div className="pv-choices">
        <button type="button" className={audience === "me" ? "selected" : ""} onClick={() => chooseAudience("me")}><UserRound /><strong>Just me</strong><span>Personal or Professional, on your personal vault.</span></button>
        <button type="button" className={audience === "family" ? "selected" : ""} onClick={() => chooseAudience("family")}><HeartHandshake /><strong>My family</strong><span>Up to 6 people, each with a private vault plus shared family vaults.</span></button>
        <button type="button" className={audience === "team" ? "selected" : ""} onClick={() => chooseAudience("team")}><Building2 /><strong>My team or company</strong><span>Team (3–50 people) or Business (5–500 people), with admin controls.</span></button>
      </div>
      <p className="pv-hint">More than 500 people, or need a contract and invoicing? <Link href="/contact?interest=demo">Talk to our team</Link>.</p>
      <div className="pv-nav"><Button variant="ghost" onClick={back}><ArrowLeft /> Back</Button></div>
    </section>}

    {step === "plan" && audience && <section className="pv-card">
      <div className="pv-card-head"><h3>Choose a plan</h3>{toggles}</div>
      {catalogState === "loading" && <p className="pv-hint"><LoaderCircle className="spin" /> Loading plans…</p>}
      {catalogState === "error" && <p className="pv-message">Plans could not be loaded. Check your connection and try again.</p>}
      <div className="pv-plans">{AUDIENCE_PLANS[audience].map((code) => {
        const details = catalogPlan(code);
        if (!details) return null;
        const price = priceFor(code);
        const perMonth = price ? (interval === "year" ? Math.round(price.unitAmount / 12) : price.unitAmount) : null;
        const seatCode = code === "team" || code === "business" ? code : null;
        const seatPlan = seatCode !== null;
        const count = seatCode ? seats[seatCode] : 1;
        const limits = { min: details.minSeats ?? 1, max: details.maxSeats ?? 500 };
        const isCurrent = entitlement.plan_code === code && workspaceAudience(vault) === PLAN_AUDIENCE[code];
        return <article key={code} className={`pv-plan ${plan === code ? "selected" : ""} ${code === "business" ? "featured" : ""}`}>
          {code === "business" && <span className="pv-badge">Most complete</span>}
          <h4>{details.name}</h4>
          <p>{details.summary}</p>
          <div className="pv-price">{perMonth !== null ? <><strong>{money(perMonth, currency)}</strong><span>{seatPlan ? "per person / month" : "per month"}</span></> : <strong>—</strong>}</div>
          {price && interval === "year" && <small className="pv-billed">Billed {money(price.unitAmount * count, currency)} per year{seatPlan ? ` for ${count} people` : ""}</small>}
          {seatCode && <div className="pv-seats"><Label htmlFor={`seats-${code}`}>How many people?</Label>
            <div className="pv-stepper"><Button type="button" size="icon-sm" variant="outline" aria-label="Fewer people" onClick={() => adjustSeats(seatCode, count - 1, limits)}>−</Button>
              <Input id={`seats-${code}`} type="number" inputMode="numeric" min={limits.min} max={limits.max} value={count} onChange={(event) => adjustSeats(seatCode, Number(event.target.value), limits)} />
              <Button type="button" size="icon-sm" variant="outline" aria-label="More people" onClick={() => adjustSeats(seatCode, count + 1, limits)}>+</Button></div>
            <small>{limits.min}–{limits.max} people. You can change this later.</small></div>}
          <ul>{details.features.slice(0, 6).map((feature) => <li key={feature}><Check /> {feature}</li>)}</ul>
          {details.trialDays > 0 && <p className="pv-trial">{details.trialDays}-day free trial for new subscriptions</p>}
          <Button onClick={() => choosePlan(code)} disabled={isCurrent || !billingEnabled}>{isCurrent ? "Your current plan" : <>Choose {details.name} <ArrowRight /></>}</Button>
        </article>;
      })}</div>
      <div className="pv-nav"><Button variant="ghost" onClick={back}><ArrowLeft /> Back</Button></div>
    </section>}

    {step === "place" && plan && <section className="pv-card">
      <h3>{audience === "family" ? "Which family vault should get the Family plan?" : `Which organisation should get ${PLAN_LABEL[plan]}?`}</h3>
      <p className="pv-hint">{audience === "family" ? "The Family plan covers one shared family vault and everyone you invite to it." : `${PLAN_LABEL[plan]} covers one organisation: its members, shared vaults and admin console. Your personal vault stays private and separate.`}</p>
      <div className="pv-options" role="radiogroup">
        {candidates.map((workspace) => { const current = plans[workspace.tenantId]; const selected = place?.kind === "existing" && place.tenantId === workspace.tenantId; return <label key={workspace.tenantId} className={selected ? "selected" : ""}>
          <input type="radio" name="pv-place" checked={selected} onChange={() => setPlace({ kind: "existing", tenantId: workspace.tenantId, workspaceId: workspace.workspaceId, name: workspace.name })} />
          <span className="pv-place-icon">{audience === "family" ? <HeartHandshake /> : <Building2 />}</span>
          <span><strong>{workspace.name}</strong><small>{current ? `Now on ${PLAN_LABEL[current.plan_code] ?? current.plan_code}` : workspaceKindLabel(workspace)}</small></span>
        </label>; })}
        <label className={place?.kind === "new" ? "selected" : ""}>
          <input type="radio" name="pv-place" checked={place?.kind === "new"} onChange={() => setPlace({ kind: "new", name: newName })} />
          <span className="pv-place-icon"><Plus /></span>
          <span><strong>{audience === "family" ? "Create a new family vault" : "Create a new organisation"}</strong><small>{audience === "family" ? "You become its owner and can invite your family afterwards." : "You become its owner. Invite your team from the Admin console after paying."}</small></span>
        </label>
        {place?.kind === "new" && <div className="pv-new-name"><Label htmlFor="pv-new-name">{audience === "family" ? "Family vault name" : "Organisation name"}</Label><Input id="pv-new-name" value={newName} maxLength={80} placeholder={audience === "family" ? "Our family" : "Your company name"} onChange={(event) => setNewName(event.target.value)} /><small>Only people you invite can see this name. It is encrypted on your device.</small></div>}
      </div>
      <div className="pv-nav"><Button variant="ghost" onClick={back}><ArrowLeft /> Back</Button><Button disabled={!place || (place.kind === "new" && newName.trim().length < 2)} onClick={() => { setMessage(""); setStep("review"); }}>Continue <ArrowRight /></Button></div>
    </section>}

    {step === "review" && plan && <section className="pv-card">
      <h3>Review and pay</h3>
      <dl className="pv-summary">
        <div><dt>Plan</dt><dd>{reviewDetails?.name ?? PLAN_LABEL[plan]}</dd></div>
        <div><dt>Applies to</dt><dd>{reviewPlaceName}{place?.kind === "new" ? audience === "family" ? " (new family vault)" : " (new organisation)" : ""}</dd></div>
        {(plan === "team" || plan === "business") && <div><dt>People</dt><dd>{seatCount}</dd></div>}
        <div><dt>Billing</dt><dd>{interval === "month" ? "Every month" : "Every year"} in {currency.toUpperCase()}</dd></div>
        <div className="total"><dt>You pay</dt><dd>{reviewTotal !== null ? `${money(reviewTotal, currency)} ${interval === "month" ? "per month" : "per year"}` : "—"}</dd></div>
      </dl>
      {reviewDetails && reviewDetails.trialDays > 0 && <p className="pv-trial">If this is the first subscription for {reviewPlaceName}, it starts with a {reviewDetails.trialDays}-day free trial. You are charged when the trial ends.</p>}
      {placeHasSubscription && placeTenantId ? <div className="pv-note warn"><CreditCard /><div><p><strong>{reviewPlaceName} already has a subscription.</strong> To switch plan or change seats, use Manage billing instead.</p><Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void portal(placeTenantId)}>Manage billing</Button></div></div> : <>
        <h4 className="pv-next-title">What happens next</h4>
        <ol className="pv-next">
          {place?.kind === "new" && <li>Passkey-X creates {audience === "family" ? "your family vault" : "your organisation"} and makes you the owner.</li>}
          <li>You go to Stripe&apos;s secure checkout. Passkey-X never sees your card.</li>
          <li>After paying you come straight back here, and the plan switches on within a minute.</li>
          {audience === "team" && <li>Then open the Admin console to invite your team.</li>}
        </ol>
        <div className="pv-nav"><Button variant="ghost" onClick={back} disabled={busy !== ""}><ArrowLeft /> Back</Button><Button onClick={() => void checkout()} disabled={busy !== "" || !billingEnabled || !reviewPrice}>{busy === "checkout" ? <><LoaderCircle className="spin" /> Opening secure checkout…</> : <>Continue to secure checkout <ArrowRight /></>}</Button></div>
      </>}
    </section>}

    {step === "activating" && <section className="pv-card pv-activation">
      {activation?.state === "active" ? <>
        <span className="pv-activation-icon good"><PartyPopper /></span>
        <h3>{activation.plan} is active on {activation.name}</h3>
        <p>Thank you. Your receipt is on its way from Stripe.</p>
        <div className="pv-nav">{["Team", "Business"].includes(activation.plan) && <Button onClick={onOpenAdmin}><Users /> Invite your team</Button>}<Button variant="outline" onClick={() => setStep("overview")}>See my plan</Button></div>
      </> : activation?.state === "slow" ? <>
        <span className="pv-activation-icon"><RefreshCw /></span>
        <h3>Almost there</h3>
        <p>Your payment went through, but activation is taking longer than usual. It usually finishes within a few minutes. You can keep using Passkey-X.</p>
        <div className="pv-nav"><Button variant="outline" onClick={() => { setStep("overview"); void refresh(); }}>Check again</Button><Button variant="ghost" onClick={onOpenHelp}><CircleHelp /> Get help</Button></div>
      </> : <>
        <span className="pv-activation-icon"><LoaderCircle className="spin" /></span>
        <h3>Switching on {activation?.plan ?? "your plan"}…</h3>
        <p>This takes a few seconds. Please keep this page open.</p>
      </>}
    </section>}
  </div>;
}
