import type { Json, Database } from "@/lib/supabase/database.types";
import { supabase } from "@/lib/supabase/client";

type Tables = Database["public"]["Tables"];
export type ConnectorCatalogEntry = Tables["connector_catalog"]["Row"];
export type TenantConnector = Tables["tenant_connectors"]["Row"];
export type SaasApplication = Tables["saas_applications"]["Row"];
export type SaasContract = Tables["saas_contracts"]["Row"];
export type SaasAccount = Tables["saas_identity_accounts"]["Row"];
export type SpendBudget = Tables["spend_budgets"]["Row"];
export type SaasRecommendation = Tables["saas_recommendations"]["Row"];
export type LifecycleWorkflow = Tables["lifecycle_workflows"]["Row"];
export type SavingsEntry = Tables["saas_savings_ledger"]["Row"];
export type MspTenantAccess = Tables["msp_tenant_access"]["Row"];

export type Phase5Dashboard = {
  applications: number;
  unsanctioned_apps: number;
  ghost_accounts: number;
  active_connectors: number;
  open_recommendations: number;
  estimated_savings: Record<string,number>;
  realized_savings: Record<string,number>;
};

export type Phase5Snapshot = {
  dashboard: Phase5Dashboard;
  catalog: ConnectorCatalogEntry[];
  connectors: TenantConnector[];
  applications: SaasApplication[];
  contracts: SaasContract[];
  accounts: SaasAccount[];
  budgets: SpendBudget[];
  recommendations: SaasRecommendation[];
  workflows: LifecycleWorkflow[];
  savings: SavingsEntry[];
  mspAccess: MspTenantAccess[];
};

const EMPTY_DASHBOARD: Phase5Dashboard = {
  applications: 0,unsanctioned_apps: 0,ghost_accounts: 0,active_connectors: 0,
  open_recommendations: 0,estimated_savings: {},realized_savings: {},
};

function client() {
  if (!supabase) throw new Error("SaaS manager is unavailable");
  return supabase;
}

function dataOrThrow<T>(result: { data: T | null; error: { message: string } | null }) {
  if (result.error) throw new Error(result.error.message);
  return result.data;
}

function dashboardFromJson(value: Json | null): Phase5Dashboard {
  if (!value || Array.isArray(value) || typeof value !== "object") return EMPTY_DASHBOARD;
  const numeric = (key: string) => typeof value[key] === "number" ? value[key] : 0;
  const money = (key: string) => {
    const entry = value[key];
    if (!entry || Array.isArray(entry) || typeof entry !== "object") return {};
    return Object.fromEntries(Object.entries(entry).filter((pair): pair is [string,number] => typeof pair[1] === "number"));
  };
  return {
    applications: numeric("applications"),unsanctioned_apps: numeric("unsanctioned_apps"),
    ghost_accounts: numeric("ghost_accounts"),active_connectors: numeric("active_connectors"),
    open_recommendations: numeric("open_recommendations"),estimated_savings: money("estimated_savings"),
    realized_savings: money("realized_savings"),
  };
}

export async function loadPhase5Snapshot(tenantId: string): Promise<Phase5Snapshot> {
  const db = client();
  const [dashboard,catalog,connectors,applications,contracts,accounts,budgets,recommendations,workflows,savings,mspAccess] = await Promise.all([
    db.rpc("phase5_saas_dashboard",{ p_tenant_id: tenantId }),
    db.from("connector_catalog").select("*").eq("phase5_target",true).order("category").order("display_name"),
    db.from("tenant_connectors").select("*").eq("tenant_id",tenantId).order("display_name"),
    db.from("saas_applications").select("*").eq("tenant_id",tenantId).order("last_seen_at",{ ascending: false }),
    db.from("saas_contracts").select("*").eq("tenant_id",tenantId).order("renewal_at"),
    db.from("saas_identity_accounts").select("*").eq("tenant_id",tenantId).order("last_seen_at",{ ascending: false }),
    db.from("spend_budgets").select("*").eq("tenant_id",tenantId).order("period_end"),
    db.from("saas_recommendations").select("*").eq("tenant_id",tenantId).order("generated_at",{ ascending: false }),
    db.from("lifecycle_workflows").select("*").eq("tenant_id",tenantId).order("created_at",{ ascending: false }),
    db.from("saas_savings_ledger").select("*").eq("tenant_id",tenantId).order("recorded_at",{ ascending: false }),
    db.from("msp_tenant_access").select("*").or(`provider_tenant_id.eq.${tenantId},customer_tenant_id.eq.${tenantId}`).order("created_at",{ ascending: false }),
  ]);
  return {
    dashboard: dashboardFromJson(dataOrThrow(dashboard)),
    catalog: dataOrThrow(catalog) ?? [],connectors: dataOrThrow(connectors) ?? [],
    applications: dataOrThrow(applications) ?? [],contracts: dataOrThrow(contracts) ?? [],
    accounts: dataOrThrow(accounts) ?? [],budgets: dataOrThrow(budgets) ?? [],
    recommendations: dataOrThrow(recommendations) ?? [],workflows: dataOrThrow(workflows) ?? [],
    savings: dataOrThrow(savings) ?? [],mspAccess: dataOrThrow(mspAccess) ?? [],
  };
}

export async function createManualSaasApplication(tenantId: string, name: string, category: string, sanctionedState: SaasApplication["sanctioned_state"]) {
  const appKey = `${name.toLowerCase().trim().replace(/[^a-z0-9]+/gu,"-").replace(/^-|-$/gu,"").slice(0,80) || "application"}-${crypto.randomUUID().slice(0,8)}`;
  const result = await client().from("saas_applications").insert({
    tenant_id: tenantId,app_key: appKey,display_name: name.trim(),category: category.trim(),
    sanctioned_state: sanctionedState,data_risk: "unknown",discovery_source: "manual",
  });
  dataOrThrow(result);
}

export async function createDraftConnector(tenantId: string, identityId: string, entry: ConnectorCatalogEntry) {
  const result = await client().from("tenant_connectors").insert({
    tenant_id: tenantId,connector_key: entry.connector_key,display_name: entry.display_name,
    status: "draft",granted_scopes: [],configuration_summary: { source: "catalog",credential_state: "not_configured" },
    token_rotation_state: "not_configured",created_by: identityId,
  });
  dataOrThrow(result);
}

export async function createSpendBudget(tenantId: string, identityId: string, values: {
  metric: SpendBudget["metric"]; currency: SpendBudget["currency"]; softLimit: number; hardLimit: number;
  enforcement: SpendBudget["enforcement"]; chargebackTag?: string;
}) {
  const start = new Date();
  const end = new Date(Date.UTC(start.getUTCFullYear(),start.getUTCMonth() + 1,1));
  const result = await client().from("spend_budgets").insert({
    tenant_id: tenantId,scope_type: "tenant",scope_id: null,metric: values.metric,currency: values.currency,
    soft_limit: values.softLimit,hard_limit: values.hardLimit,period_start: start.toISOString().slice(0,10),
    period_end: end.toISOString().slice(0,10),enforcement: values.enforcement,
    chargeback_tag: values.chargebackTag?.trim() || null,created_by: identityId,
  });
  dataOrThrow(result);
}

export async function createWorkflowPreset(tenantId: string, identityId: string, preset: "joiner" | "leaver" | "license_reclaim" | "renewal_notice") {
  const presets = {
    joiner: { name: "Joiner access review",action: "create_review",destructive: false },
    leaver: { name: "Leaver deprovision proposal",action: "propose_deprovision",destructive: true },
    license_reclaim: { name: "Unused license review",action: "propose_reclaim",destructive: true },
    renewal_notice: { name: "Renewal owner notice",action: "notify",destructive: false },
  } as const;
  const selected = presets[preset];
  const result = await client().from("lifecycle_workflows").insert({
    tenant_id: tenantId,display_name: selected.name,trigger_type: preset,action_type: selected.action,
    execution_mode: "proposal",destructive_action: selected.destructive,approval_required: true,
    definition: { source: "phase5_preset",approval: "required" },enabled: false,created_by: identityId,
  });
  dataOrThrow(result);
}

export async function refreshSaasRecommendations(tenantId: string) {
  const result = await client().rpc("refresh_saas_recommendations",{ p_tenant_id: tenantId });
  return dataOrThrow(result) ?? 0;
}

export async function reviewRecommendation(id: string, identityId: string, decision: "approved" | "dismissed") {
  const result = await client().from("saas_recommendations").update({ action_state: decision,reviewed_by: identityId,reviewed_at: new Date().toISOString() }).eq("id",id);
  dataOrThrow(result);
}

export async function requestMspTenantAccess(providerTenantId: string, customerTenantId: string, identityId: string) {
  const result = await client().from("msp_tenant_access").insert({
    provider_tenant_id: providerTenantId,customer_tenant_id: customerTenantId,
    permission: "view",status: "pending",created_by: identityId,
  });
  dataOrThrow(result);
}

export async function approveMspTenantAccess(id: string, identityId: string) {
  const result = await client().from("msp_tenant_access").update({ status: "active",approved_by: identityId,approved_at: new Date().toISOString() }).eq("id",id);
  dataOrThrow(result);
}
