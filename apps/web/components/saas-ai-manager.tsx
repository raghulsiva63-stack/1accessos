"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AppWindow, BadgeDollarSign, Bot, Cable, Check, CircleAlert, CloudCog,
  Gauge, Network, RefreshCw, Search, ShieldCheck, Sparkles, UsersRound,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { TenantEntitlement } from "@/lib/billing/client";
import {
  approveMspTenantAccess, createDraftConnector, createManualSaasApplication,
  createSpendBudget, createWorkflowPreset, loadPhase5Snapshot, refreshSaasRecommendations,
  requestMspTenantAccess, reviewRecommendation, type ConnectorCatalogEntry,
  type Phase5Snapshot,
} from "@/lib/saas-ai/phase5";
import type { WorkspaceVault } from "@/lib/vault/items";

const EMPTY: Phase5Snapshot = {
  dashboard: { applications: 0,unsanctioned_apps: 0,ghost_accounts: 0,active_connectors: 0,open_recommendations: 0,estimated_savings: {},realized_savings: {} },
  catalog: [],connectors: [],applications: [],contracts: [],accounts: [],budgets: [],recommendations: [],workflows: [],savings: [],mspAccess: [],
};

function friendlyError(reason: unknown) {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  if (/entitlement|required/iu.test(message)) return "The Business package is required for this SaaS & AI control.";
  if (/row-level security|permission|42501/iu.test(message)) return "Your tenant role does not allow this action.";
  if (/duplicate|23505/iu.test(message)) return "That record already exists in this tenant.";
  return "The SaaS & AI change could not be completed. Try again.";
}

function currency(amountMinor: number, code: string) {
  return new Intl.NumberFormat(code === "inr" ? "en-IN" : "en-US",{
    style: "currency",currency: code.toUpperCase(),maximumFractionDigits: code === "inr" ? 0 : 2,
  }).format(amountMinor / 100);
}

function totalMoney(values: Record<string,number>) {
  const entries = Object.entries(values);
  return entries.length ? entries.map(([code,amount]) => currency(amount,code)).join(" + ") : "—";
}

export function SaasAiManager({ vault,entitlement,onOpenBilling }: {
  vault: WorkspaceVault; entitlement: TenantEntitlement; onOpenBilling: () => void;
}) {
  const [snapshot,setSnapshot] = useState<Phase5Snapshot>(EMPTY);
  const [activeTenant,setActiveTenant] = useState(vault.tenantId);
  const [loading,setLoading] = useState(true);
  const [busy,setBusy] = useState("");
  const [message,setMessage] = useState("");
  const [applicationName,setApplicationName] = useState("");
  const [applicationCategory,setApplicationCategory] = useState("productivity");
  const [sanctionedState,setSanctionedState] = useState<"unknown" | "sanctioned" | "unsanctioned" | "under_review">("under_review");
  const [connectorQuery,setConnectorQuery] = useState("");
  const [budgetCurrency,setBudgetCurrency] = useState<"inr" | "usd">("usd");
  const [budgetSoft,setBudgetSoft] = useState("500");
  const [budgetHard,setBudgetHard] = useState("750");
  const [chargebackTag,setChargebackTag] = useState("");
  const [mspCustomer,setMspCustomer] = useState("");

  const businessActive = entitlement.plan_code === "business"
    && (entitlement.source === "manual" || ["trialing","active","past_due"].includes(entitlement.subscription_status));
  const viewingManagedTenant = activeTenant !== vault.tenantId;

  const requestVersion = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    if (!businessActive) { setSnapshot(EMPTY); setLoading(false); return; }
    setLoading(true);
    try {
      const result = await loadPhase5Snapshot(activeTenant);
      if (version === requestVersion.current) { setSnapshot(result); setMessage(""); }
    } catch (reason) {
      if (version === requestVersion.current) setMessage(friendlyError(reason));
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }, [activeTenant,businessActive]);

  useEffect(() => {
    const version = ++requestVersion.current;
    if (businessActive) {
      void loadPhase5Snapshot(activeTenant).then((result) => {
        if (version === requestVersion.current) { setSnapshot(result); setLoading(false); }
      }, (reason: unknown) => {
        if (version === requestVersion.current) { setMessage(friendlyError(reason)); setLoading(false); }
      });
    }
    return () => { requestVersion.current += 1; };
  }, [activeTenant,businessActive]);

  async function run(label: string,action: () => Promise<unknown>,success: string) {
    setBusy(label); setMessage("");
    try { await action(); setMessage(success); await refresh(); }
    catch (reason) { setMessage(friendlyError(reason)); }
    finally { setBusy(""); }
  }

  const connectorKeys = useMemo(() => new Set(snapshot.connectors.map((entry) => entry.connector_key)),[snapshot.connectors]);
  const catalog = useMemo(() => {
    const query = connectorQuery.trim().toLowerCase();
    return snapshot.catalog.filter((entry) => !query || `${entry.display_name} ${entry.category}`.toLowerCase().includes(query));
  },[connectorQuery,snapshot.catalog]);
  const managedTenants = snapshot.mspAccess.filter((entry) => entry.provider_tenant_id === vault.tenantId && entry.status === "active");

  if (!businessActive) return <div className="feature-page saas-manager-page">
    <div className="feature-intro"><div><span className="status-pill"><Sparkles /> SaaS & AI Manager</span><h2>Govern applications, AI spend, and renewals</h2><p>Business includes the Phase 5 control plane for approved enterprise discovery signals, license optimization, budget enforcement, connector governance, and proposal-first workflows.</p></div><Button onClick={onOpenBilling}>Review Business package</Button></div>
    <div className="privacy-note"><ShieldCheck /><span>Discovery accepts identity, license, expense, and managed-domain metadata only. It never receives page content, form fields, decrypted vault content, passwords, or raw prompts.</span></div>
  </div>;

  return <div className="feature-page saas-manager-page">
    <div className="feature-intro"><div><span className="status-pill"><Sparkles /> Phase 5 control plane</span><h2>SaaS & AI Manager</h2><p>Explain spend, ownership, utilization, renewal risk, and connector health from privacy-minimized tenant metadata.</p></div><Button variant="outline" disabled={loading || busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button></div>

    <div className="phase5-context-bar">
      <div><Network /><span><strong>{viewingManagedTenant ? "Managed customer context" : "Current organization"}</strong><small>{activeTenant.slice(0,8)}… · derived metadata only</small></span></div>
      <select aria-label="SaaS manager tenant context" value={activeTenant} disabled={busy !== ""} onChange={(event) => { requestVersion.current += 1; setSnapshot(EMPTY); setLoading(true); setMessage(""); setActiveTenant(event.target.value); }}>
        <option value={vault.tenantId}>Current organization</option>
        {managedTenants.map((entry) => <option key={entry.id} value={entry.customer_tenant_id}>Managed tenant {entry.customer_tenant_id.slice(0,8)}…</option>)}
      </select>
    </div>

    {message && <p className="settings-message" role="status">{message}</p>}
    {loading ? <div className="vault-loading"><div className="loading-ring" /><p>Loading privacy-minimized SaaS metadata…</p></div> : <>
      <div className="phase5-metrics">
        <article><AppWindow /><span><strong>{snapshot.dashboard.applications}</strong>Applications</span></article>
        <article><CircleAlert /><span><strong>{snapshot.dashboard.unsanctioned_apps}</strong>Unsanctioned</span></article>
        <article><UsersRound /><span><strong>{snapshot.dashboard.ghost_accounts}</strong>Ghost accounts</span></article>
        <article><Cable /><span><strong>{snapshot.dashboard.active_connectors}</strong>Healthy connectors</span></article>
        <article><BadgeDollarSign /><span><strong>{totalMoney(snapshot.dashboard.estimated_savings)}</strong>Proposed savings</span></article>
      </div>

      <div className="phase5-grid">
        <Card className="phase5-recommendations"><CardHeader><CardTitle><Gauge /> Waste Autopilot</CardTitle><CardDescription>Deterministic proposals from license, owner, renewal, and budget metadata. Nothing is deprovisioned automatically.</CardDescription></CardHeader><CardContent>
          <div className="phase5-card-actions"><Button disabled={busy !== "" || viewingManagedTenant} onClick={() => void run("recommend",() => refreshSaasRecommendations(activeTenant),"Recommendations refreshed from current tenant metadata.")}><RefreshCw /> {busy === "recommend" ? "Analyzing…" : "Refresh proposals"}</Button><span>{snapshot.dashboard.open_recommendations} open</span></div>
          <div className="recommendation-list">{snapshot.recommendations.filter((entry) => entry.action_state === "proposed").slice(0,8).map((entry) => <article key={entry.id}><span className={`recommendation-severity ${entry.severity}`}>{entry.severity}</span><div><strong>{entry.title}</strong><p>{entry.explanation}</p>{entry.estimated_savings_minor !== null && entry.currency && <small>Estimated: {currency(entry.estimated_savings_minor,entry.currency)} per contract interval</small>}</div>{!viewingManagedTenant && <div className="recommendation-actions"><Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`approve-${entry.id}`,() => reviewRecommendation(entry.id,vault.identityId,"approved"),"Proposal approved for a separate controlled execution step.")}><Check /> Approve proposal</Button><Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`dismiss-${entry.id}`,() => reviewRecommendation(entry.id,vault.identityId,"dismissed"),"Proposal dismissed.")}>Dismiss</Button></div>}</article>)}{!snapshot.recommendations.some((entry) => entry.action_state === "proposed") && <div className="small-empty"><Gauge /><strong>No open optimization proposals</strong><span>Add inventory or refresh the deterministic analysis.</span></div>}</div>
        </CardContent></Card>

        <Card><CardHeader><CardTitle><BadgeDollarSign /> AI Spend Governor</CardTitle><CardDescription>Monthly tenant cap with soft alert and hard approval/block behavior.</CardDescription></CardHeader><CardContent>
          {!viewingManagedTenant && <form className="phase5-form" onSubmit={(event) => { event.preventDefault(); const soft = Math.round(Number(budgetSoft) * 100); const hard = Math.round(Number(budgetHard) * 100); void run("budget",() => createSpendBudget(activeTenant,vault.identityId,{ metric: "ai_cost_minor",currency: budgetCurrency,softLimit: soft,hardLimit: hard,enforcement: "block",chargebackTag }),"AI spend budget created."); }}><div><Label htmlFor="budget-currency">Currency</Label><select id="budget-currency" value={budgetCurrency} onChange={(event) => setBudgetCurrency(event.target.value as "inr" | "usd")}><option value="usd">USD</option><option value="inr">INR</option></select></div><div><Label htmlFor="budget-soft">Soft limit</Label><Input id="budget-soft" type="number" min="0" step="1" required value={budgetSoft} onChange={(event) => setBudgetSoft(event.target.value)} /></div><div><Label htmlFor="budget-hard">Hard limit</Label><Input id="budget-hard" type="number" min={budgetSoft || "0"} step="1" required value={budgetHard} onChange={(event) => setBudgetHard(event.target.value)} /></div><div><Label htmlFor="budget-tag">Chargeback tag</Label><Input id="budget-tag" maxLength={80} value={chargebackTag} onChange={(event) => setChargebackTag(event.target.value)} placeholder="Engineering" /></div><Button disabled={busy !== ""}>{busy === "budget" ? "Saving…" : "Create monthly cap"}</Button></form>}
          <div className="budget-list">{snapshot.budgets.map((budget) => { const percent = budget.hard_limit ? Math.min(100,Math.round(budget.consumed / budget.hard_limit * 100)) : 0; return <article key={budget.id}><div><strong>{budget.metric.replaceAll("_"," ")}</strong><small>{budget.chargeback_tag || budget.scope_type} · {budget.enforcement}</small></div><span>{budget.currency ? currency(budget.consumed,budget.currency) : budget.consumed} / {budget.currency ? currency(budget.hard_limit,budget.currency) : budget.hard_limit}</span><div className="budget-track"><i style={{ width: `${percent}%` }} /></div></article>; })}{!snapshot.budgets.length && <p className="field-hint">No active spend budget yet.</p>}</div>
        </CardContent></Card>

        <Card><CardHeader><CardTitle><AppWindow /> Application inventory</CardTitle><CardDescription>Manual baseline plus approved IdP, SSO, SCIM, expense, license, or managed-domain signals.</CardDescription></CardHeader><CardContent>
          {!viewingManagedTenant && <form className="phase5-form app-form" onSubmit={(event) => { event.preventDefault(); void run("application",() => createManualSaasApplication(activeTenant,applicationName,applicationCategory,sanctionedState),"Application added to the review inventory.").then(() => setApplicationName("")); }}><div><Label htmlFor="saas-app-name">Application</Label><Input id="saas-app-name" required minLength={2} maxLength={160} value={applicationName} onChange={(event) => setApplicationName(event.target.value)} placeholder="Figma" /></div><div><Label htmlFor="saas-app-category">Category</Label><Input id="saas-app-category" required minLength={2} maxLength={80} value={applicationCategory} onChange={(event) => setApplicationCategory(event.target.value)} /></div><div><Label htmlFor="saas-app-state">Governance state</Label><select id="saas-app-state" value={sanctionedState} onChange={(event) => setSanctionedState(event.target.value as typeof sanctionedState)}><option value="under_review">Under review</option><option value="sanctioned">Sanctioned</option><option value="unsanctioned">Unsanctioned</option><option value="unknown">Unknown</option></select></div><Button disabled={busy !== ""}>{busy === "application" ? "Adding…" : "Add inventory item"}</Button></form>}
          <div className="application-list">{snapshot.applications.slice(0,10).map((app) => <article key={app.id}><span className="app-mark">{app.display_name.slice(0,2).toUpperCase()}</span><div><strong>{app.display_name}</strong><small>{app.category} · {app.discovery_source.replaceAll("_"," ")} · risk {app.data_risk}</small></div><span className={`governance-state ${app.sanctioned_state === "unsanctioned" ? "revoked" : app.sanctioned_state === "under_review" ? "pending" : ""}`}>{app.sanctioned_state.replaceAll("_"," ")}</span></article>)}{!snapshot.applications.length && <p className="field-hint">No applications discovered or added yet.</p>}</div>
        </CardContent></Card>

        <Card><CardHeader><CardTitle><Bot /> No-code workflows</CardTitle><CardDescription>Joiner, leaver, reclaim, and renewal presets begin disabled and proposal-first.</CardDescription></CardHeader><CardContent>
          {!viewingManagedTenant && <div className="workflow-presets">{(["joiner","leaver","license_reclaim","renewal_notice"] as const).map((preset) => <Button key={preset} variant="outline" disabled={busy !== ""} onClick={() => void run(`workflow-${preset}`,() => createWorkflowPreset(activeTenant,vault.identityId,preset),"Disabled workflow preset created for review.")}>{preset.replaceAll("_"," ")}</Button>)}</div>}
          <div className="workflow-list">{snapshot.workflows.map((workflow) => <article key={workflow.id}><CloudCog /><div><strong>{workflow.display_name}</strong><small>{workflow.trigger_type.replaceAll("_"," ")} → {workflow.action_type.replaceAll("_"," ")}</small></div><span className={`governance-state ${workflow.enabled ? "" : "pending"}`}>{workflow.enabled ? workflow.execution_mode : "disabled"}</span></article>)}{!snapshot.workflows.length && <p className="field-hint">No workflow definitions yet.</p>}</div>
        </CardContent></Card>
      </div>

      <Card className="connector-hub"><CardHeader><CardTitle><Cable /> Integration Hub</CardTitle><CardDescription>{snapshot.catalog.length} Phase 5 target manifests with declared minimum scopes and honest maturity labels. “Contract validated” does not mean vendor-certified or production-connected.</CardDescription></CardHeader><CardContent>
        <div className="connector-toolbar"><div className="search-field"><Search /><Input aria-label="Search connector catalog" value={connectorQuery} onChange={(event) => setConnectorQuery(event.target.value)} placeholder="Search identity, HRIS, cloud…" /></div><span>{snapshot.connectors.length} tenant drafts/connections</span></div>
        <div className="connector-grid">{catalog.map((entry) => <ConnectorCard key={entry.connector_key} entry={entry} connected={connectorKeys.has(entry.connector_key)} disabled={busy !== "" || viewingManagedTenant} onAdd={() => void run(`connector-${entry.connector_key}`,() => createDraftConnector(activeTenant,vault.identityId,entry),`${entry.display_name} draft created. Credentials and vendor authorization are still required.`)} />)}</div>
      </CardContent></Card>

      <Card className="msp-console"><CardHeader><CardTitle><Network /> MSP tenant console</CardTitle><CardDescription>Explicit customer approval exposes aggregate SaaS/security metadata only. It never grants tenant membership, vault access, workspace keys, or a decrypt capability.</CardDescription></CardHeader><CardContent>
        {!viewingManagedTenant && <form className="msp-request" onSubmit={(event) => { event.preventDefault(); void run("msp-request",() => requestMspTenantAccess(vault.tenantId,mspCustomer,vault.identityId),"MSP metadata-access request created. A customer owner must approve it.").then(() => setMspCustomer("")); }}><div><Label htmlFor="msp-customer">Customer tenant ID</Label><Input id="msp-customer" required pattern="[0-9a-fA-F-]{36}" value={mspCustomer} onChange={(event) => setMspCustomer(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" /></div><Button disabled={busy !== ""}>Request metadata access</Button></form>}
        <div className="msp-list">{snapshot.mspAccess.map((entry) => <article key={entry.id}><Network /><div><strong>{entry.provider_tenant_id === vault.tenantId ? `Customer ${entry.customer_tenant_id.slice(0,8)}…` : `Provider ${entry.provider_tenant_id.slice(0,8)}…`}</strong><small>{entry.permission} metadata access · {entry.status}</small></div>{entry.customer_tenant_id === vault.tenantId && entry.status === "pending" && <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`msp-approve-${entry.id}`,() => approveMspTenantAccess(entry.id,vault.identityId),"MSP metadata access approved.")}>Approve</Button>}</article>)}{!snapshot.mspAccess.length && <p className="field-hint">No MSP tenant relationships.</p>}</div>
      </CardContent></Card>

      <div className="privacy-note"><ShieldCheck /><span>Connector authorization is server-side. The browser cannot read connector credential references; telemetry rejects token-, secret-, page-, form-, DOM-, vault-, and raw-prompt-shaped fields.</span></div>
    </>}
  </div>;
}

function ConnectorCard({ entry,connected,disabled,onAdd }: { entry: ConnectorCatalogEntry; connected: boolean; disabled: boolean; onAdd: () => void }) {
  return <article className="connector-card"><div><span className="connector-logo">{entry.display_name.slice(0,2).toUpperCase()}</span><span><strong>{entry.display_name}</strong><small>{entry.category.replaceAll("_"," ")} · {entry.auth_scheme}</small></span></div><p>{entry.minimum_scopes.join(" · ")}</p><div><span className={`connector-stage ${entry.adapter_stage}`}>{entry.quality_label.replaceAll("_"," ")}</span><Button size="sm" variant="outline" disabled={disabled || connected} onClick={onAdd}>{connected ? "Added" : "Create draft"}</Button></div></article>;
}
