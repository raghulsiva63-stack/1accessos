"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity, BellRing, Building2, FileCheck2, FileClock, FolderLock, KeyRound, LayoutDashboard, Lock, Rocket, ShieldCheck, SlidersHorizontal, Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AdminOverview } from "@/components/admin/overview-panel";
import { PeoplePanel } from "@/components/admin/people-panel";
import { PoliciesPanel } from "@/components/admin/policies-panel";
import { AuditPanel } from "@/components/admin/audit-panel";
import { AccessReviewPanel } from "@/components/admin/access-review-panel";
import { IntegrationsPanel } from "@/components/admin/integrations-panel";
import { AlertsPanel } from "@/components/admin/alerts-panel";
import { ReportsPanel } from "@/components/admin/reports-panel";
import { IdentityPanel } from "@/components/admin/identity-panel";
import { RolloutPanel } from "@/components/admin/rollout-panel";
import { OrganizationView } from "@/components/organization-view";
import { useEnterprise } from "@/components/enterprise/policy-context";
import type { TenantEntitlement } from "@/lib/billing/client";
import { loadMemberOverview, type MemberOverview } from "@/lib/enterprise/admin";
import { loadTenantPolicies, type StoredPolicy } from "@/lib/enterprise/policies";
import type { WorkspaceVault } from "@/lib/vault/items";

export type AdminTab = "overview" | "rollout" | "alerts" | "people" | "identity" | "policies" | "access" | "audit" | "reports" | "integrations" | "directory";

const TABS: { id: AdminTab; label: string; icon: typeof Users }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "rollout", label: "Team rollout", icon: Rocket },
  { id: "alerts", label: "Alerts", icon: BellRing },
  { id: "people", label: "People", icon: Users },
  { id: "identity", label: "Identity & SSO", icon: KeyRound },
  { id: "policies", label: "Policies", icon: SlidersHorizontal },
  { id: "access", label: "Access review", icon: FolderLock },
  { id: "audit", label: "Audit log", icon: FileClock },
  { id: "reports", label: "Reports", icon: FileCheck2 },
  { id: "integrations", label: "Integrations", icon: Activity },
  { id: "directory", label: "Directory", icon: Building2 },
];

export function adminErrorMessage(reason: unknown, fallback = "The change could not be completed. Try again.") {
  const detail = typeof reason === "object" && reason !== null
    ? `${"code" in reason ? String(reason.code) : ""} ${"message" in reason ? String(reason.message) : ""}`
    : String(reason ?? "");
  if (/42501|denied|row-level security/iu.test(detail)) return "Your organization role does not allow this action.";
  if (/business organization entitlement/iu.test(detail)) return "The Business plan is required for organization controls.";
  if (/PGRST202|42883|does not exist/iu.test(detail)) return "This feature is being enabled for your organization. Please try again shortly.";
  if (/at least one owner/iu.test(detail)) return "An organization needs at least one owner.";
  if (/40001|changed/iu.test(detail)) return "Someone else changed this at the same time. Refresh and try again.";
  if (/invalid configuration/iu.test(detail)) return "That policy value is outside the supported range.";
  return fallback;
}

export function AdminConsole({
  vault, entitlement, workspaceNames, onOpenBilling,
}: {
  vault: WorkspaceVault;
  entitlement: TenantEntitlement;
  workspaceNames: Map<string, string>;
  onOpenBilling: () => void;
}) {
  const { isOrganization, tenantRole, refresh: refreshPolicy } = useEnterprise();
  const [tab, setTab] = useState<AdminTab>("overview");
  const [members, setMembers] = useState<MemberOverview[]>([]);
  const [policies, setPolicies] = useState<StoredPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  const businessActive = (entitlement.plan_code === "business" || (entitlement.plan_code as string) === "enterprise")
    && (entitlement.source === "manual" || ["trialing", "active", "past_due"].includes(entitlement.subscription_status));

  useEffect(() => {
    let current = true;
    if (!isOrganization) return () => { current = false; };
    void Promise.resolve().then(() => { if (current) setLoading(true); })
      .then(() => Promise.allSettled([loadMemberOverview(vault.tenantId), loadTenantPolicies(vault.tenantId)]))
      .then(([memberResult, policyResult]) => {
        if (!current) return;
        if (memberResult.status === "fulfilled") setMembers(memberResult.value);
        if (policyResult.status === "fulfilled") setPolicies(policyResult.value);
        const failure = [memberResult, policyResult].find((result) => result.status === "rejected");
        setMessage(failure && failure.status === "rejected" ? adminErrorMessage(failure.reason, "Some admin data could not be loaded.") : "");
      })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [isOrganization, vault.tenantId, version]);

  const reload = useCallback(() => { setVersion((value) => value + 1); refreshPolicy(); }, [refreshPolicy]);

  if (!isOrganization) {
    return <div className="feature-page"><Card className="admin-upsell"><CardHeader><span className="feature-icon"><Building2 /></span><CardTitle>Admin console is for organizations</CardTitle><CardDescription>Switch to an organization workspace, or create one on the Business plan, to manage people, enforce security policies and review a tamper-evident audit log.</CardDescription></CardHeader><CardContent><Button onClick={onOpenBilling}>View Business plan</Button></CardContent></Card></div>;
  }

  return <div className="feature-page admin-console">
    <div className="admin-hero">
      <div><span className="status-pill"><ShieldCheck /> Zero-knowledge administration</span><h2>Run Passkey-X for your organization</h2><p>Invite people, set security rules and see who is protected — without ever seeing anyone&apos;s passwords. Every change here is written to a tamper-evident audit log.</p></div>
      <div className="admin-hero-meta"><span><Lock /> Your role: <strong>{tenantRole ?? "member"}</strong></span><span><Activity /> {members.filter((member) => member.membership_status === "active").length} active members</span></div>
    </div>
    {!businessActive && <div className="billing-notice admin-plan-notice"><strong>Business plan required for changes.</strong> You can review your organization, but creating policies and directory changes need an active Business plan. <Button size="sm" variant="outline" onClick={onOpenBilling}>Upgrade</Button></div>}
    {message && <p className="form-message" role="alert">{message}</p>}
    <nav className="admin-tabs" role="tablist" aria-label="Admin sections">
      {TABS.map((entry) => { const Icon = entry.icon; return <button key={entry.id} role="tab" aria-selected={tab === entry.id} className={tab === entry.id ? "active" : ""} onClick={() => setTab(entry.id)}><Icon /> {entry.label}</button>; })}
    </nav>
    <div role="tabpanel">
      {tab === "overview" && <AdminOverview vault={vault} members={members} policies={policies} loading={loading} onNavigate={setTab} onChanged={reload} canEdit={businessActive} />}
      {tab === "rollout" && <RolloutPanel vault={vault} members={members} policies={policies} loading={loading} onNavigate={setTab} />}
      {tab === "alerts" && <AlertsPanel vault={vault} members={members} />}
      {tab === "identity" && <IdentityPanel vault={vault} canEdit={businessActive} />}
      {tab === "reports" && (businessActive ? <ReportsPanel vault={vault} organizationName={vault.name} /> : <BusinessOnly feature="Compliance reports" onOpenBilling={onOpenBilling} />)}
      {tab === "people" && <PeoplePanel vault={vault} members={members} loading={loading} onChanged={reload} onOpenDirectory={() => setTab("directory")} />}
      {tab === "policies" && <PoliciesPanel vault={vault} policies={policies} loading={loading} onChanged={reload} canEdit={businessActive} />}
      {tab === "access" && (businessActive ? <AccessReviewPanel vault={vault} workspaceNames={workspaceNames} /> : <BusinessOnly feature="Access reviews" onOpenBilling={onOpenBilling} />)}
      {tab === "audit" && <AuditPanel vault={vault} members={members} />}
      {tab === "integrations" && (businessActive ? <IntegrationsPanel vault={vault} /> : <BusinessOnly feature="Audit streaming to SIEM and webhooks" onOpenBilling={onOpenBilling} />)}
      {tab === "directory" && <OrganizationView key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={onOpenBilling} />}
    </div>
  </div>;
}

function BusinessOnly({ feature, onOpenBilling }: { feature: string; onOpenBilling: () => void }) {
  return <Card className="admin-upsell"><CardHeader><span className="feature-icon"><Building2 /></span><CardTitle>{feature} are part of Business</CardTitle><CardDescription>Upgrade this organization to the Business plan to use this. Nothing in your organization changes until you do.</CardDescription></CardHeader><CardContent><Button onClick={onOpenBilling}>View Business plan</Button></CardContent></Card>;
}
