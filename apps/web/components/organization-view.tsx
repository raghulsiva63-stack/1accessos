"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Building2, Check, Network, RefreshCw, ShieldCheck, UserCog, Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { OrganizationGovernance } from "@/components/organization-governance";
import type { TenantEntitlement } from "@/lib/billing/client";
import {
  createOrganizationDepartment, createOrganizationGroup, createOrganizationPolicy,
  createOrganizationTeam, hasOrganizationCapability, loadOrganization, manageOrganizationMember,
  onboardOrganizationMember, organizationScopeAllows, type OrganizationAdminRole,
  type OrganizationSnapshot,
} from "@/lib/organization/phase5";
import type { WorkspaceVault } from "@/lib/vault/items";

const EMPTY: OrganizationSnapshot = {
  departments: [], teams: [], groups: [], profiles: [], admins: [], policies: [], members: [],
  teamMemberships: [], invitations: [], currentTenantRole: null,
};

function friendlyError(reason: unknown) {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  if (message.includes("business organization entitlement required")) return "The Business package is required for office controls.";
  if (message.includes("row-level security") || message.includes("42501")) return "Your organization role does not allow this action.";
  if (message.includes("duplicate") || message.includes("23505")) return "That organization record already exists.";
  return "The organization change could not be completed. Try again.";
}

export function OrganizationView({
  vault, entitlement, onOpenBilling,
}: {
  vault: WorkspaceVault;
  entitlement: TenantEntitlement;
  onOpenBilling: () => void;
}) {
  const [data, setData] = useState<OrganizationSnapshot>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [departmentName, setDepartmentName] = useState("");
  const [departmentParent, setDepartmentParent] = useState("");
  const [teamName, setTeamName] = useState("");
  const [teamDepartment, setTeamDepartment] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupDescription, setGroupDescription] = useState("");
  const [memberIdentity, setMemberIdentity] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberTitle, setMemberTitle] = useState("");
  const [memberDepartment, setMemberDepartment] = useState("");

  const businessActive = entitlement.plan_code === "business"
    && (entitlement.source === "manual" || ["trialing","active","past_due"].includes(entitlement.subscription_status));

  const requestVersion = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    if (!businessActive) { setData(EMPTY); setLoading(false); return; }
    setLoading(true);
    try {
      const result = await loadOrganization(vault.tenantId,vault.identityId);
      if (version === requestVersion.current) { setData(result); setMessage(""); }
    } catch (reason) {
      if (version === requestVersion.current) setMessage(friendlyError(reason));
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }, [businessActive,vault.identityId,vault.tenantId]);

  useEffect(() => {
    const version = ++requestVersion.current;
    if (businessActive) {
      void loadOrganization(vault.tenantId,vault.identityId).then((result) => {
        if (version === requestVersion.current) { setData(result); setLoading(false); }
      }, (reason: unknown) => {
        if (version === requestVersion.current) { setMessage(friendlyError(reason)); setLoading(false); }
      });
    }
    return () => { requestVersion.current += 1; };
  }, [businessActive,vault.identityId,vault.tenantId]);

  const canManageStructure = data.currentTenantRole === "owner" || data.currentTenantRole === "admin"
    || data.admins.some((assignment) => assignment.identity_id === vault.identityId
      && assignment.status === "active" && assignment.role === "organization_admin"
      && assignment.scope_type !== "team");
  const canOnboardPeople = hasOrganizationCapability(data,vault.identityId,["organization_admin","helpdesk_admin"]);
  const canManageLifecycle = hasOrganizationCapability(data,vault.identityId,["organization_admin","helpdesk_admin","security_admin"]);
  const canManagePolicy = hasOrganizationCapability(data,vault.identityId,["organization_admin","security_admin"]);
  const structureRoles: OrganizationAdminRole[] = ["organization_admin"];
  const peopleRoles: OrganizationAdminRole[] = ["organization_admin","helpdesk_admin"];
  const lifecycleRoles: OrganizationAdminRole[] = ["organization_admin","helpdesk_admin","security_admin"];
  const activeDepartments = data.departments.filter((entry) => entry.status === "active");
  const structureDepartments = activeDepartments.filter((department) =>
    organizationScopeAllows(data,vault.identityId,structureRoles,department.id));
  const peopleDepartments = activeDepartments.filter((department) =>
    organizationScopeAllows(data,vault.identityId,peopleRoles,department.id));
  const canCreateTopLevelStructure = data.currentTenantRole === "owner" || data.currentTenantRole === "admin"
    || data.admins.some((assignment) => assignment.identity_id === vault.identityId
      && assignment.status === "active" && assignment.role === "organization_admin" && assignment.scope_type === "tenant");
  const canTenantPeople = data.currentTenantRole === "owner" || data.currentTenantRole === "admin"
    || data.admins.some((assignment) => assignment.identity_id === vault.identityId
      && assignment.status === "active" && ["organization_admin","helpdesk_admin"].includes(assignment.role)
      && assignment.scope_type === "tenant");
  const canDirectOnboard = canOnboardPeople && (canTenantPeople || data.admins.some((assignment) =>
    assignment.identity_id === vault.identityId && assignment.status === "active"
      && ["organization_admin","helpdesk_admin"].includes(assignment.role)
      && assignment.scope_type === "department"));
  const canManageTenantPolicy = data.currentTenantRole === "owner" || data.currentTenantRole === "admin"
    || data.admins.some((assignment) => assignment.identity_id === vault.identityId
      && assignment.status === "active" && ["organization_admin","security_admin"].includes(assignment.role)
      && assignment.scope_type === "tenant");
  const canManageGroups = data.currentTenantRole === "owner" || data.currentTenantRole === "admin"
    || data.admins.some((assignment) => assignment.identity_id === vault.identityId
      && assignment.status === "active" && assignment.role === "organization_admin" && assignment.scope_type === "tenant");
  const availableMembers = useMemo(() => {
    const profiled = new Set(data.profiles.map((profile) => profile.identity_id));
    return data.members.filter((member) => member.status === "active" && !profiled.has(member.identity_id));
  }, [data.members,data.profiles]);
  const departmentNames = useMemo(() => new Map(data.departments.map((entry) => [entry.id,entry.display_name])), [data.departments]);
  function canManageProfile(identityId: string, departmentId: string | null) {
    const teams = data.teamMemberships.filter((membership) =>
      membership.identity_id === identityId && membership.status === "active");
    return organizationScopeAllows(data,vault.identityId,lifecycleRoles,departmentId)
      || teams.some((membership) => organizationScopeAllows(data,vault.identityId,lifecycleRoles,departmentId,membership.team_id));
  }

  async function run(label: string, action: () => Promise<void>, success: string) {
    setBusy(label); setMessage("");
    try { await action(); setMessage(success); await refresh(); }
    catch (reason) { setMessage(friendlyError(reason)); }
    finally { setBusy(""); }
  }

  if (!businessActive) return <div className="feature-page organization-page">
    <div className="feature-intro"><div><span className="status-pill"><Building2 /> Office controls</span><h2>Choose Business for a multi-department office</h2><p>Team protects one workgroup. Business adds an organization directory, departments, multiple teams, groups, delegated administrators, policy inheritance, and joiner/mover/leaver controls.</p></div></div>
    <div className="office-package-grid">
      <Card><CardHeader><CardTitle>Team</CardTitle><CardDescription>One small workgroup with shared workspaces.</CardDescription></CardHeader><CardContent><ul><li><Check /> Up to 50 members</li><li><Check /> Workspace roles and sharing</li><li><Check /> Missions and approvals</li></ul></CardContent></Card>
      <Card className="business-package"><CardHeader><span className="business-pill">For offices</span><CardTitle>Business</CardTitle><CardDescription>Company-wide control across departments and teams.</CardDescription></CardHeader><CardContent><ul><li><Check /> Up to 500 members and 500 workspaces</li><li><Check /> Departments, teams, groups and directory</li><li><Check /> Scoped organization, security, billing and helpdesk admins</li><li><Check /> Policy inheritance and employee lifecycle controls</li></ul><Button onClick={onOpenBilling}>Review Business package</Button></CardContent></Card>
    </div>
    <div className="privacy-note"><ShieldCheck /><span>Office names and job titles are visible administrative metadata. Passwords, keys, recovery material, vault item names, and vault contents remain client-encrypted.</span></div>
  </div>;

  return <div className="feature-page organization-page">
    <div className="feature-intro"><div><span className="status-pill"><Building2 /> Business organization</span><h2>Your office control plane</h2><p>Model departments and teams, assign employees, apply inherited policy, and remove access safely from one tenant-scoped console.</p></div><Button variant="outline" disabled={loading || busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button></div>
    <div className="org-metrics">
      <article><Building2 /><span><strong>{data.departments.filter((entry) => entry.status === "active").length}</strong>Departments</span></article>
      <article><Network /><span><strong>{data.teams.filter((entry) => entry.status === "active").length}</strong>Teams</span></article>
      <article><Users /><span><strong>{data.profiles.filter((entry) => entry.lifecycle_status === "active").length}</strong>People</span></article>
      <article><UserCog /><span><strong>{data.admins.length}</strong>Delegated admins</span></article>
    </div>
    {message && <p className="settings-message" role="status">{message}</p>}
    {loading ? <div className="vault-loading"><div className="loading-ring" /><p>Loading tenant-scoped office controls…</p></div> : <>
      {canManageStructure ? <div className="org-builder-grid">
        <Card><CardHeader><CardTitle>Add department</CardTitle><CardDescription>Top-level or nested office unit.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("department",() => createOrganizationDepartment(vault.tenantId,vault.identityId,departmentName,departmentParent),"Department created.").then(() => { setDepartmentName(""); setDepartmentParent(""); }); }}><div><Label htmlFor="org-department">Department name</Label><Input id="org-department" required maxLength={120} value={departmentName} onChange={(event) => setDepartmentName(event.target.value)} placeholder="Engineering" /></div><div><Label htmlFor="org-department-parent">Parent department</Label><select id="org-department-parent" required={!canCreateTopLevelStructure} value={departmentParent} onChange={(event) => setDepartmentParent(event.target.value)}>{canCreateTopLevelStructure && <option value="">Top level</option>}{structureDepartments.map((entry) => <option key={entry.id} value={entry.id}>{entry.display_name}</option>)}</select></div><Button disabled={busy !== ""}>{busy === "department" ? "Creating…" : "Create department"}</Button></form></CardContent></Card>
        <Card><CardHeader><CardTitle>Add team</CardTitle><CardDescription>Place a workgroup inside a department.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("team",() => createOrganizationTeam(vault.tenantId,vault.identityId,teamName,teamDepartment),"Team created.").then(() => setTeamName("")); }}><div><Label htmlFor="org-team">Team name</Label><Input id="org-team" required maxLength={120} value={teamName} onChange={(event) => setTeamName(event.target.value)} placeholder="Platform" /></div><div><Label htmlFor="team-department">Department</Label><select id="team-department" required={!canCreateTopLevelStructure} value={teamDepartment} onChange={(event) => setTeamDepartment(event.target.value)}>{canCreateTopLevelStructure && <option value="">Unassigned</option>}{structureDepartments.map((entry) => <option key={entry.id} value={entry.id}>{entry.display_name}</option>)}</select></div><Button disabled={busy !== ""}>{busy === "team" ? "Creating…" : "Create team"}</Button></form></CardContent></Card>
        {canManageGroups && <Card><CardHeader><CardTitle>Add access group</CardTitle><CardDescription>Reusable tenant-wide administrative classification.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("group",() => createOrganizationGroup(vault.tenantId,vault.identityId,groupName,groupDescription),"Group created.").then(() => { setGroupName(""); setGroupDescription(""); }); }}><div><Label htmlFor="org-group">Group name</Label><Input id="org-group" required maxLength={120} value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="Production access" /></div><div><Label htmlFor="group-description">Description</Label><Input id="group-description" maxLength={500} value={groupDescription} onChange={(event) => setGroupDescription(event.target.value)} placeholder="Non-secret administrative purpose" /></div><Button disabled={busy !== ""}>{busy === "group" ? "Creating…" : "Create group"}</Button></form></CardContent></Card>}
      </div> : <div className="billing-notice"><ShieldCheck /><div><strong>Directory view</strong><p>Your role can read this office structure. An organization owner or administrator manages changes.</p></div></div>}

      <div className="organization-columns">
        <Card><CardHeader><CardTitle>People directory</CardTitle><CardDescription>Lifecycle state is tenant-wide; vault access still uses workspace memberships and key envelopes.</CardDescription></CardHeader><CardContent>
          {canDirectOnboard && availableMembers.length > 0 && <form className="org-onboard" onSubmit={(event) => { event.preventDefault(); void run("onboard",() => onboardOrganizationMember(vault.tenantId,memberIdentity,memberName,memberTitle,memberDepartment),"Employee added to the office directory.").then(() => { setMemberIdentity(""); setMemberName(""); setMemberTitle(""); }); }}><div><Label htmlFor="member-identity">Existing tenant member</Label><select id="member-identity" required value={memberIdentity} onChange={(event) => setMemberIdentity(event.target.value)}><option value="">Select member</option>{availableMembers.map((entry) => <option key={entry.identity_id} value={entry.identity_id}>{entry.identity_id.slice(0,8)}… · {entry.role}</option>)}</select></div><div><Label htmlFor="member-name">Display name</Label><Input id="member-name" required maxLength={120} value={memberName} onChange={(event) => setMemberName(event.target.value)} /></div><div><Label htmlFor="member-title">Job title</Label><Input id="member-title" maxLength={120} value={memberTitle} onChange={(event) => setMemberTitle(event.target.value)} /></div><div><Label htmlFor="member-department">Department</Label><select id="member-department" required={!canTenantPeople} value={memberDepartment} onChange={(event) => setMemberDepartment(event.target.value)}>{canTenantPeople && <option value="">Unassigned</option>}{peopleDepartments.map((entry) => <option key={entry.id} value={entry.id}>{entry.display_name}</option>)}</select></div><Button disabled={busy !== ""}>{busy === "onboard" ? "Adding…" : "Add employee"}</Button></form>}
          <div className="org-directory">{data.profiles.length ? data.profiles.map((profile) => <article key={profile.identity_id}><span className="avatar">{profile.display_name.split(/\s+/u).slice(0,2).map((part) => part[0]).join("").toUpperCase()}</span><div><strong>{profile.display_name}</strong><small>{profile.job_title || "No job title"} · {profile.department_id ? departmentNames.get(profile.department_id) ?? "Department" : "Unassigned"}</small></div><span className={`lifecycle-state ${profile.lifecycle_status}`}>{profile.lifecycle_status.replaceAll("_"," ")}</span>{canManageLifecycle && canManageProfile(profile.identity_id,profile.department_id) && profile.identity_id !== vault.identityId && profile.lifecycle_status === "active" && <div className="row-actions"><Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`suspend-${profile.identity_id}`,() => manageOrganizationMember(vault.tenantId,profile.identity_id,"suspended"),`${profile.display_name} suspended and old key access revoked.`)}>Suspend</Button><Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => { if (window.confirm(`Deprovision ${profile.display_name}? Existing vault keys will be revoked and affected workspaces will require rotation.`)) void run(`remove-${profile.identity_id}`,() => manageOrganizationMember(vault.tenantId,profile.identity_id,"deprovisioned"),`${profile.display_name} deprovisioned.`); }}>Deprovision</Button></div>}</article>) : <div className="small-empty"><Users /><strong>No directory profiles yet</strong><span>Use an organization invitation or add an existing tenant member.</span></div>}</div>
        </CardContent></Card>
        <div className="org-side-stack">
          <Card><CardHeader><CardTitle>Security policy</CardTitle><CardDescription>Tenant defaults are inherited by departments and teams unless a more specific policy is added.</CardDescription></CardHeader><CardContent><div className="policy-list">{data.policies.map((policy) => <span key={policy.id}><ShieldCheck /><strong>{policy.policy_type.replaceAll("_"," ")}</strong><small>{policy.scope_type} · priority {policy.priority} · v{policy.version}</small></span>)}{!data.policies.length && <p className="field-hint">No enforced tenant policy yet.</p>}</div>{canManagePolicy && canManageTenantPolicy && <div className="policy-actions"><Button variant="outline" disabled={busy !== ""} onClick={() => void run("policy-passkey",() => createOrganizationPolicy(vault.tenantId,vault.identityId,"passkey_required",{ required: true }),"Passkey policy enforced.")}>Require passkeys</Button><Button variant="outline" disabled={busy !== ""} onClick={() => void run("policy-device",() => createOrganizationPolicy(vault.tenantId,vault.identityId,"device_approval_required",{ required: true }),"Device approval policy recorded.")}>Require device approval</Button></div>}</CardContent></Card>
          <Card><CardHeader><CardTitle>Structure</CardTitle><CardDescription>Active teams and reusable groups.</CardDescription></CardHeader><CardContent><div className="structure-list">{data.teams.map((team) => <span key={team.id}><Network /><div><strong>{team.display_name}</strong><small>{team.department_id ? departmentNames.get(team.department_id) ?? "Department" : "No department"}</small></div></span>)}{data.groups.map((group) => <span key={group.id}><Users /><div><strong>{group.display_name}</strong><small>{group.description || "Access group"}</small></div></span>)}{!data.teams.length && !data.groups.length && <p className="field-hint">Create a department, team, or group to begin.</p>}</div></CardContent></Card>
        </div>
      </div>
      <OrganizationGovernance vault={vault} data={data} onRefresh={refresh} />
    </>}
    <div className="privacy-note"><ShieldCheck /><span>Suspension and deprovisioning revoke the employee&apos;s key envelopes and require affected workspaces to rotate keys. Reactivation never restores previous vault keys automatically.</span></div>
  </div>;
}
