"use client";

import { useMemo, useState } from "react";
import {
  CheckCircle2, ClipboardCopy, Download, FileCheck2, Laptop, ShieldCheck,
  Upload, UserCog, UserPlus, XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { downloadBlob } from "@/lib/browser/download";
import type { WorkspaceVault } from "@/lib/vault/items";
import {
  assignOrganizationAdministrator, createOrganizationInvitation, createOrganizationPolicy,
  evaluateOrganizationDeviceReadiness, exportOrganizationAudit, hasOrganizationCapability,
  loadOrganizationDevices, organizationScopeAllows, parseOrganizationInviteCsv, reportSelfDevicePosture,
  resolveOrganizationPolicies, revokeOrganizationAdministrator, revokeOrganizationInvitation,
  type DeviceReadiness, type EffectiveOrganizationPolicy, type OrganizationAdminRole,
  type OrganizationScopeType, type OrganizationSnapshot,
} from "@/lib/organization/phase5";
import { copySecret } from "@/components/enterprise/vault-guards";

type BulkResult = { email: string; status: "created" | "failed"; link?: string; detail?: string };

const ADMIN_ROLES: { value: OrganizationAdminRole; label: string }[] = [
  { value: "organization_admin",label: "Organization admin" },
  { value: "security_admin",label: "Security admin" },
  { value: "billing_admin",label: "Billing admin" },
  { value: "helpdesk_admin",label: "Helpdesk admin" },
  { value: "auditor",label: "Auditor" },
];

function safeMessage(reason: unknown) {
  const detail = reason instanceof Error ? reason.message : String(reason ?? "");
  if (/row-level security|42501|denied/iu.test(detail)) return "Your assigned organization scope does not allow that action.";
  if (/duplicate|23505/iu.test(detail)) return "That assignment or invitation already exists.";
  if (/csv/iu.test(detail)) return detail;
  return "The governance action could not be completed. Try again.";
}

function downloadText(filename: string, content: string, type: string) {
  downloadBlob(new Blob([content], { type }), filename);
}

// Called by invitation event handlers; every row in a bulk action shares its expiry.
function invitationExpiry() {
  return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
}

function csvCell(value: string) {
  return `"${value.replaceAll('"','""')}"`;
}

export function OrganizationGovernance({
  vault,data,onRefresh,
}: {
  vault: WorkspaceVault;
  data: OrganizationSnapshot;
  onRefresh: () => Promise<void>;
}) {
  const [busy,setBusy] = useState("");
  const [message,setMessage] = useState("");
  const [inviteEmail,setInviteEmail] = useState("");
  const [inviteName,setInviteName] = useState("");
  const [inviteTitle,setInviteTitle] = useState("");
  const [inviteDepartment,setInviteDepartment] = useState("");
  const [inviteTeam,setInviteTeam] = useState("");
  const [inviteLink,setInviteLink] = useState("");
  const [bulkResults,setBulkResults] = useState<BulkResult[]>([]);
  const [adminIdentity,setAdminIdentity] = useState("");
  const [adminRole,setAdminRole] = useState<OrganizationAdminRole>("organization_admin");
  const [adminScope,setAdminScope] = useState<OrganizationScopeType>("tenant");
  const [adminScopeId,setAdminScopeId] = useState("");
  const [policyIdentity,setPolicyIdentity] = useState("");
  const [effectivePolicies,setEffectivePolicies] = useState<EffectiveOrganizationPolicy[]>([]);
  const [policyScope,setPolicyScope] = useState<OrganizationScopeType>("tenant");
  const [policyScopeId,setPolicyScopeId] = useState("");
  const [deviceId,setDeviceId] = useState("");
  const [deviceReadiness,setDeviceReadiness] = useState<DeviceReadiness | null>(null);
  const [posture,setPosture] = useState({ osFamily: "unknown",screenLock: false,diskEncrypted: false,securityPatchCurrent: false,endpointProtection: false });

  const isTenantAdmin = data.currentTenantRole === "owner" || data.currentTenantRole === "admin";
  const canPeople = hasOrganizationCapability(data,vault.identityId,["organization_admin","helpdesk_admin"]);
  const canPolicy = hasOrganizationCapability(data,vault.identityId,["organization_admin","security_admin"]);
  const canAudit = isTenantAdmin || data.currentTenantRole === "auditor" || data.admins.some((assignment) =>
    assignment.identity_id === vault.identityId && assignment.status === "active"
      && assignment.scope_type === "tenant" && ["auditor","security_admin"].includes(assignment.role));

  const profileNames = useMemo(() => new Map(data.profiles.map((profile) => [profile.identity_id,profile.display_name])),[data.profiles]);
  const departmentNames = useMemo(() => new Map(data.departments.map((department) => [department.id,department.display_name])),[data.departments]);
  const teamNames = useMemo(() => new Map(data.teams.map((team) => [team.id,team.display_name])),[data.teams]);
  const activeProfiles = data.profiles.filter((profile) => profile.lifecycle_status === "active");
  const activeDepartments = data.departments.filter((department) => department.status === "active");
  const activeTeams = data.teams.filter((team) => team.status === "active");
  const peopleRoles: OrganizationAdminRole[] = ["organization_admin","helpdesk_admin"];
  const policyRoles: OrganizationAdminRole[] = ["organization_admin","security_admin"];
  const peopleDepartments = activeDepartments.filter((department) =>
    organizationScopeAllows(data,vault.identityId,peopleRoles,department.id));
  const peopleTeams = activeTeams.filter((team) =>
    organizationScopeAllows(data,vault.identityId,peopleRoles,team.department_id,team.id));
  const policyDepartments = activeDepartments.filter((department) =>
    organizationScopeAllows(data,vault.identityId,policyRoles,department.id));
  const policyTeams = activeTeams.filter((team) =>
    organizationScopeAllows(data,vault.identityId,policyRoles,team.department_id,team.id));
  const canTenantPolicy = isTenantAdmin || data.admins.some((assignment) =>
    assignment.identity_id === vault.identityId && assignment.status === "active"
      && assignment.scope_type === "tenant" && policyRoles.includes(assignment.role as OrganizationAdminRole));
  const canTenantPeople = isTenantAdmin || data.admins.some((assignment) =>
    assignment.identity_id === vault.identityId && assignment.status === "active"
      && assignment.scope_type === "tenant" && peopleRoles.includes(assignment.role as OrganizationAdminRole));
  const allowedPolicyScopes: OrganizationScopeType[] = [
    ...(canTenantPolicy ? ["tenant" as const] : []),
    ...(policyDepartments.length ? ["department" as const] : []),
    ...(policyTeams.length ? ["team" as const] : []),
  ];
  const effectivePolicyScope = allowedPolicyScopes.includes(policyScope) ? policyScope : allowedPolicyScopes[0] ?? "tenant";

  async function run(label: string, action: () => Promise<void>, success: string, refresh = true) {
    setBusy(label); setMessage("");
    try { await action(); if (refresh) await onRefresh(); setMessage(success); }
    catch (reason) { setMessage(safeMessage(reason)); }
    finally { setBusy(""); }
  }

  function scopeOptions(scope: OrganizationScopeType, purpose: "admin" | "policy" = "admin") {
    const departments = purpose === "policy" ? policyDepartments : activeDepartments;
    const teams = purpose === "policy" ? policyTeams : activeTeams;
    if (scope === "department") return departments.map((entry) => ({ id: entry.id,label: entry.display_name }));
    if (scope === "team") return teams.map((entry) => ({ id: entry.id,label: entry.display_name }));
    return [];
  }

  async function invite(event: React.FormEvent) {
    event.preventDefault();
    await run("invite",async () => {
      const link = await createOrganizationInvitation(
        vault.tenantId,vault.identityId,inviteEmail,inviteName,
        invitationExpiry(),window.location.origin,
        { jobTitle: inviteTitle,departmentId: inviteDepartment,teamId: inviteTeam },
      );
      setInviteLink(link); setInviteEmail(""); setInviteName(""); setInviteTitle("");
    },"Secure organization invitation created. Copy its one-time link now.");
  }

  async function bulkInvite(file: File, expiresAt: string) {
    setBusy("bulk"); setMessage(""); setBulkResults([]);
    try {
      const rows = parseOrganizationInviteCsv(await file.text());
      const results: BulkResult[] = [];
      for (const row of rows) {
        const department = row.departmentSlug
          ? peopleDepartments.find((entry) => entry.slug === row.departmentSlug || entry.display_name.toLowerCase() === row.departmentSlug)
          : undefined;
        const team = row.teamSlug
          ? peopleTeams.find((entry) => entry.slug === row.teamSlug || entry.display_name.toLowerCase() === row.teamSlug)
          : undefined;
        if (row.departmentSlug && !department) { results.push({ email: row.email,status: "failed",detail: "Unknown department" }); continue; }
        if (row.teamSlug && !team) { results.push({ email: row.email,status: "failed",detail: "Unknown team" }); continue; }
        try {
          const link = await createOrganizationInvitation(
            vault.tenantId,vault.identityId,row.email,row.displayName,
            expiresAt,window.location.origin,
            { jobTitle: row.jobTitle,departmentId: department?.id,teamId: team?.id,teamRole: row.teamRole },
          );
          results.push({ email: row.email,status: "created",link });
        } catch (reason) { results.push({ email: row.email,status: "failed",detail: safeMessage(reason) }); }
      }
      setBulkResults(results);
      await onRefresh();
      setMessage(`${results.filter((entry) => entry.status === "created").length} of ${results.length} secure invitations created.`);
    } catch (reason) { setMessage(safeMessage(reason)); }
    finally { setBusy(""); }
  }

  function downloadBulkResults() {
    const header = "email,status,one_time_link,detail";
    const rows = bulkResults.map((entry) => [entry.email,entry.status,entry.link ?? "",entry.detail ?? ""].map(csvCell).join(","));
    downloadText(`passkey-x-organization-invitations-${new Date().toISOString().slice(0,10)}.csv`,[header,...rows].join("\n"),"text/csv");
  }

  async function previewPolicies() {
    if (!policyIdentity) return;
    setBusy("resolve"); setMessage("");
    try { setEffectivePolicies(await resolveOrganizationPolicies(vault.tenantId,policyIdentity)); }
    catch (reason) { setMessage(safeMessage(reason)); }
    finally { setBusy(""); }
  }

  async function reportPosture() {
    if (!deviceId) return;
    await run("posture",async () => {
      await reportSelfDevicePosture(vault.tenantId,vault.identityId,deviceId,posture);
      setDeviceReadiness(await evaluateOrganizationDeviceReadiness(vault.tenantId,deviceId,vault.identityId));
    },"Self-reported posture recorded as advisory evidence.",false);
  }

  async function chooseDevice() {
    setBusy("devices"); setMessage("");
    try {
      const devices = await loadOrganizationDevices(vault.identityId);
      const trusted = devices.find((device) => device.status === "trusted");
      if (!trusted) throw new Error("No trusted device is available.");
      setDeviceId(trusted.id);
      setDeviceReadiness(await evaluateOrganizationDeviceReadiness(vault.tenantId,trusted.id,vault.identityId));
      setMessage("Current trusted device selected for policy readiness.");
    } catch (reason) { setMessage(safeMessage(reason)); }
    finally { setBusy(""); }
  }

  async function downloadAudit() {
    setBusy("audit"); setMessage("");
    try {
      const events = await exportOrganizationAudit(vault.tenantId);
      downloadText(`passkey-x-audit-${new Date().toISOString().slice(0,10)}.ndjson`,events.map((event) => JSON.stringify(event)).join("\n"),"application/x-ndjson");
      setMessage(`${events.length} tenant-authorized audit events exported.`);
    } catch (reason) { setMessage(safeMessage(reason)); }
    finally { setBusy(""); }
  }

  return <section className="governance-section">
    <div className="governance-heading"><div><span className="status-pill"><ShieldCheck /> Governance controls</span><h3>Delegation, onboarding and evidence</h3><p>Every administrative action is tenant-bound, scope-checked and recorded without vault plaintext.</p></div></div>
    {message && <p className="settings-message" role="status">{message}</p>}
    <div className="governance-grid">
      <Card><CardHeader><CardTitle><UserPlus /> Organization invitations</CardTitle><CardDescription>Email-bound, one-time directory onboarding. Vault access requires a separate encrypted workspace invitation.</CardDescription></CardHeader><CardContent>
        {canPeople ? <><form className="governance-form" onSubmit={invite}>
          <div><Label htmlFor="org-invite-email">Work email</Label><Input id="org-invite-email" type="email" required value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} /></div>
          <div><Label htmlFor="org-invite-name">Display name</Label><Input id="org-invite-name" required maxLength={120} value={inviteName} onChange={(event) => setInviteName(event.target.value)} /></div>
          <div><Label htmlFor="org-invite-title">Job title</Label><Input id="org-invite-title" maxLength={120} value={inviteTitle} onChange={(event) => setInviteTitle(event.target.value)} /></div>
          <div><Label htmlFor="org-invite-department">Department</Label><select id="org-invite-department" required={!canTenantPeople} value={inviteDepartment} onChange={(event) => { setInviteDepartment(event.target.value); setInviteTeam(""); }}>{canTenantPeople && <option value="">Tenant-wide / unassigned</option>}{peopleDepartments.map((entry) => <option key={entry.id} value={entry.id}>{entry.display_name}</option>)}</select></div>
          <div><Label htmlFor="org-invite-team">Team</Label><select id="org-invite-team" value={inviteTeam} onChange={(event) => setInviteTeam(event.target.value)}><option value="">No team</option>{peopleTeams.filter((entry) => !inviteDepartment || entry.department_id === inviteDepartment).map((entry) => <option key={entry.id} value={entry.id}>{entry.display_name}</option>)}</select></div>
          <Button disabled={busy !== ""}>{busy === "invite" ? "Creating…" : "Create invitation"}</Button>
        </form>
        {inviteLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{inviteLink}</code><Button size="sm" variant="outline" onClick={() => void copySecret(inviteLink, 120).catch(() => undefined)}><ClipboardCopy /> Copy</Button><small>Only its SHA-256 verifier is stored. The raw token remains in the URL fragment.</small></div>}
        <div className="bulk-onboarding"><label className="file-action"><Upload /><span>{busy === "bulk" ? "Preparing invitations…" : "Bulk invite CSV"}</span><input type="file" accept=".csv,text/csv" disabled={busy !== ""} onChange={(event) => { const file = event.target.files?.[0]; if (file) void bulkInvite(file, invitationExpiry()); event.target.value = ""; }} /></label><small>Columns: email, display_name, job_title, department, team, team_role. Maximum 200 rows; parsing stays in this browser.</small>{bulkResults.length > 0 && <Button size="sm" variant="outline" onClick={downloadBulkResults}><Download /> Download results</Button>}</div></> : <p className="field-hint">An authorized organization or helpdesk administrator creates invitations.</p>}
        <div className="governance-list">{data.invitations.slice(0,8).map((invitation) => <article key={invitation.id}><span className={`governance-state ${invitation.status}`}>{invitation.status}</span><div><strong>{invitation.display_name}</strong><small>{invitation.department_id ? departmentNames.get(invitation.department_id) ?? "Department" : "Unassigned"} · expires {new Date(invitation.expires_at).toLocaleDateString()}</small></div>{canPeople && invitation.status === "pending" && <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`revoke-invite-${invitation.id}`,() => revokeOrganizationInvitation(invitation.id),"Invitation revoked.")}>Revoke</Button>}</article>)}</div>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><UserCog /> Delegated administrators</CardTitle><CardDescription>Owners assign a least-privilege role at tenant, department or team scope.</CardDescription></CardHeader><CardContent>
        {isTenantAdmin && <form className="governance-form" onSubmit={(event) => { event.preventDefault(); void run("admin",() => assignOrganizationAdministrator(vault.tenantId,adminIdentity,vault.identityId,adminRole,adminScope,adminScopeId),"Administrator scope assigned."); }}>
          <div><Label htmlFor="admin-person">Employee</Label><select id="admin-person" required value={adminIdentity} onChange={(event) => setAdminIdentity(event.target.value)}><option value="">Select employee</option>{activeProfiles.map((profile) => <option key={profile.identity_id} value={profile.identity_id}>{profile.display_name}</option>)}</select></div>
          <div><Label htmlFor="admin-role">Role</Label><select id="admin-role" value={adminRole} onChange={(event) => setAdminRole(event.target.value as OrganizationAdminRole)}>{ADMIN_ROLES.map((role) => <option key={role.value} value={role.value}>{role.label}</option>)}</select></div>
          <div><Label htmlFor="admin-scope">Scope</Label><select id="admin-scope" value={adminScope} onChange={(event) => { const scope = event.target.value as OrganizationScopeType; setAdminScope(scope); setAdminScopeId(""); }}><option value="tenant">Entire tenant</option><option value="department">Department</option><option value="team">Team</option></select></div>
          {adminScope !== "tenant" && <div><Label htmlFor="admin-scope-id">Scope target</Label><select id="admin-scope-id" required value={adminScopeId} onChange={(event) => setAdminScopeId(event.target.value)}><option value="">Select scope</option>{scopeOptions(adminScope).map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}</select></div>}
          <Button disabled={busy !== ""}>{busy === "admin" ? "Assigning…" : "Assign role"}</Button>
        </form>}
        <div className="governance-list">{data.admins.map((assignment) => <article key={assignment.id}><span className="feature-icon"><UserCog /></span><div><strong>{profileNames.get(assignment.identity_id) ?? `Member ${assignment.identity_id.slice(0,8)}`}</strong><small>{assignment.role.replaceAll("_"," ")} · {assignment.scope_type}{assignment.scope_id ? `: ${departmentNames.get(assignment.scope_id) ?? teamNames.get(assignment.scope_id) ?? assignment.scope_id.slice(0,8)}` : ""}</small></div>{isTenantAdmin && <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`revoke-admin-${assignment.id}`,() => revokeOrganizationAdministrator(assignment.id),"Administrator assignment revoked.")}>Revoke</Button>}</article>)}</div>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><FileCheck2 /> Effective policy</CardTitle><CardDescription>Team policy overrides department policy, which overrides the tenant default.</CardDescription></CardHeader><CardContent>
        <div className="governance-inline"><select aria-label="Policy subject" value={policyIdentity} onChange={(event) => setPolicyIdentity(event.target.value)}><option value="">Select employee</option>{activeProfiles.map((profile) => <option key={profile.identity_id} value={profile.identity_id}>{profile.display_name}</option>)}</select><Button variant="outline" disabled={!policyIdentity || busy !== ""} onClick={() => void previewPolicies()}>{busy === "resolve" ? "Resolving…" : "Preview effective policy"}</Button></div>
        <div className="policy-list">{effectivePolicies.map((policy) => <span key={policy.policy_id}><ShieldCheck /><strong>{policy.policy_type.replaceAll("_"," ")}</strong><small>{policy.source_scope_type} · v{policy.version}</small></span>)}{policyIdentity && !effectivePolicies.length && <p className="field-hint">No enforced policy applies to this employee.</p>}</div>
        {canPolicy && <div className="scoped-policy-builder"><div><Label htmlFor="policy-scope">New policy scope</Label><select id="policy-scope" value={effectivePolicyScope} onChange={(event) => { setPolicyScope(event.target.value as OrganizationScopeType); setPolicyScopeId(""); }}>{allowedPolicyScopes.map((scope) => <option key={scope} value={scope}>{scope[0].toUpperCase() + scope.slice(1)}</option>)}</select></div>{effectivePolicyScope !== "tenant" && <div><Label htmlFor="policy-scope-target">Target</Label><select id="policy-scope-target" required value={policyScopeId} onChange={(event) => setPolicyScopeId(event.target.value)}><option value="">Select target</option>{scopeOptions(effectivePolicyScope,"policy").map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}</select></div>}<Button size="sm" variant="outline" disabled={busy !== "" || (effectivePolicyScope !== "tenant" && !policyScopeId)} onClick={() => void run("scoped-policy",() => createOrganizationPolicy(vault.tenantId,vault.identityId,"device_approval_required",{ required: true },effectivePolicyScope,policyScopeId),"Scoped device-approval policy saved.")}>Require approved devices</Button></div>}
      </CardContent></Card>

      <Card><CardHeader><CardTitle><Laptop /> Device-policy readiness</CardTitle><CardDescription>Self-reports are advisory. Strict policy requires a verified MDM, IdP or attested posture record.</CardDescription></CardHeader><CardContent>
        <div className="governance-inline"><Button variant="outline" disabled={busy !== ""} onClick={() => void chooseDevice()}>{busy === "devices" ? "Checking…" : "Select current trusted device"}</Button>{deviceReadiness && <span className={`readiness-result ${deviceReadiness.allowed ? "ready" : "blocked"}`}>{deviceReadiness.allowed ? <CheckCircle2 /> : <XCircle />}{deviceReadiness.reason.replaceAll("_"," ")}</span>}</div>
        {deviceId && <div className="posture-checks"><select aria-label="Operating system" value={posture.osFamily} onChange={(event) => setPosture({ ...posture,osFamily: event.target.value })}><option value="unknown">Unknown OS</option><option value="windows">Windows</option><option value="macos">macOS</option><option value="linux">Linux</option><option value="ios">iOS</option><option value="android">Android</option><option value="chromeos">ChromeOS</option></select>{([ ["screenLock","Screen lock"],["diskEncrypted","Disk encrypted"],["securityPatchCurrent","Security patches current"],["endpointProtection","Endpoint protection"] ] as const).map(([key,label]) => <label key={key}><input type="checkbox" checked={posture[key]} onChange={(event) => setPosture({ ...posture,[key]: event.target.checked })} /> {label}</label>)}<Button size="sm" disabled={busy !== ""} onClick={() => void reportPosture()}>{busy === "posture" ? "Recording…" : "Record advisory posture"}</Button></div>}
        <p className="governance-warning">Readiness is visible now, but global vault blocking remains disabled until a reviewed device-bound session claim is available.</p>
      </CardContent></Card>

      <Card className="audit-card"><CardHeader><CardTitle><Download /> Audit evidence</CardTitle><CardDescription>Download up to 1,000 authorized, hash-chained events as NDJSON.</CardDescription></CardHeader><CardContent>{canAudit ? <Button variant="outline" disabled={busy !== ""} onClick={() => void downloadAudit()}>{busy === "audit" ? "Preparing…" : "Export audit evidence"}</Button> : <p className="field-hint">Tenant owners, administrators and tenant-scoped auditors can export organization-wide evidence.</p>}<p className="governance-warning">Automatic SIEM delivery, retention and legal-hold rules remain an enterprise configuration gate.</p></CardContent></Card>
    </div>
  </section>;
}
