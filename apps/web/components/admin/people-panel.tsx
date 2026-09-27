"use client";

import { useMemo, useState } from "react";
import {
  Download, Fingerprint, Laptop, LoaderCircle, MoreHorizontal, Search, ShieldAlert, ShieldCheck, UserPlus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { downloadBlob } from "@/lib/browser/download";
import {
  relativeTime, ROLE_LABELS, setMemberRole, type MemberOverview, type TenantRole,
} from "@/lib/enterprise/admin";
import {
  assignOrganizationAdministrator, manageOrganizationMember, type OrganizationAdminRole,
} from "@/lib/organization/phase5";
import type { WorkspaceVault } from "@/lib/vault/items";

type Filter = "all" | "admins" | "risk" | "nomfa" | "inactive" | "suspended";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Everyone" },
  { id: "admins", label: "Admins" },
  { id: "risk", label: "At risk" },
  { id: "nomfa", label: "No 2-step" },
  { id: "inactive", label: "Inactive 30d" },
  { id: "suspended", label: "Suspended" },
];

const ADMIN_ROLES: OrganizationAdminRole[] = ["organization_admin", "security_admin", "helpdesk_admin", "billing_admin", "auditor"];
const DAY = 86_400_000;

function matches(member: MemberOverview, filter: Filter, now: number) {
  switch (filter) {
    case "admins": return ["owner", "admin"].includes(member.tenant_role) || member.admin_roles.length > 0;
    case "risk": return (member.health_score ?? 100) < 70 || (member.breached_count ?? 0) > 0;
    case "nomfa": return member.mfa_factors === 0;
    case "inactive": return !member.last_sign_in_at || now - Date.parse(member.last_sign_in_at) > 30 * DAY;
    case "suspended": return member.membership_status !== "active" || ["suspended", "deprovisioned", "leave"].includes(member.lifecycle_status);
    default: return true;
  }
}

function csvCell(value: unknown) {
  const text = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@\t\r]/u.test(text) ? `'${text}` : text;
  return /[",\n\r]/u.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function PeoplePanel({
  vault, members, loading, onChanged, onOpenDirectory,
}: {
  vault: WorkspaceVault;
  members: MemberOverview[];
  loading: boolean;
  onChanged: () => void;
  onOpenDirectory: () => void;
}) {
  const { tenantRole } = useEnterprise();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [now] = useState(() => Date.now());
  const canManageRoles = tenantRole === "owner" || tenantRole === "admin";
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return members.filter((member) => matches(member, filter, now) && (!needle
      || member.display_name.toLowerCase().includes(needle)
      || (member.email ?? "").toLowerCase().includes(needle)
      || (member.job_title ?? "").toLowerCase().includes(needle)));
  }, [filter, members, now, query]);

  async function run(key: string, action: () => Promise<void>, success: string) {
    setBusy(key); setMessage(""); setOpenMenu(null);
    try { await action(); setMessage(success); onChanged(); }
    catch (reason) { setMessage(adminErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  function changeRole(member: MemberOverview, role: TenantRole) {
    if (role === member.tenant_role) return;
    if (!window.confirm(`Change ${member.display_name} from ${ROLE_LABELS[member.tenant_role]} to ${ROLE_LABELS[role]}?`)) return;
    void run(`role:${member.identity_id}`, () => setMemberRole(vault.tenantId, member.identity_id, role), "Role updated.");
  }

  function lifecycle(member: MemberOverview, event: "suspended" | "reactivated" | "deprovisioned") {
    const verb = event === "suspended" ? "Suspend" : event === "reactivated" ? "Reactivate" : "Offboard";
    const warning = event === "deprovisioned" ? " Their workspace access and key envelopes are revoked and affected shared workspaces are marked for key rotation." : "";
    if (!window.confirm(`${verb} ${member.display_name}?${warning}`)) return;
    void run(`life:${member.identity_id}`, () => manageOrganizationMember(vault.tenantId, member.identity_id, event), `${member.display_name}: ${verb.toLowerCase()} complete.`);
  }

  function grantAdmin(member: MemberOverview, role: OrganizationAdminRole) {
    if (!window.confirm(`Grant ${ROLE_LABELS[role] ?? role} to ${member.display_name} for the whole organization?`)) return;
    void run(`grant:${member.identity_id}`, () => assignOrganizationAdministrator(vault.tenantId, member.identity_id, vault.identityId, role, "tenant"), "Admin role granted.");
  }

  function exportCsv() {
    const header = ["name", "email", "job_title", "role", "admin_roles", "status", "mfa_factors", "trusted_devices", "last_sign_in", "health_score", "weak", "reused", "breached"];
    const rows = members.map((member) => [member.display_name, member.email, member.job_title, member.tenant_role, member.admin_roles.join(" "), member.lifecycle_status, member.mfa_factors, member.trusted_devices, member.last_sign_in_at, member.health_score, member.weak_count, member.reused_count, member.breached_count].map(csvCell).join(","));
    downloadBlob(new Blob([[header.join(","), ...rows].join("\r\n")], { type: "text/csv" }), `passkey-x-members-${new Date().toISOString().slice(0, 10)}.csv`);
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle>People</CardTitle><CardDescription>Roles, sign-in security and vault health for every member.</CardDescription></div>
        <div className="inline-actions"><Button variant="outline" size="sm" onClick={exportCsv} disabled={!members.length}><Download /> Export CSV</Button><Button size="sm" onClick={onOpenDirectory}><UserPlus /> Invite people</Button></div></div>
    </CardHeader>
    <CardContent>
      <div className="people-toolbar">
        <label className="search-field"><Search /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search name, email or title" aria-label="Search people" /></label>
        <div className="chip-row" role="radiogroup" aria-label="Filter people">{FILTERS.map((entry) => <button key={entry.id} role="radio" aria-checked={filter === entry.id} className={filter === entry.id ? "active" : ""} onClick={() => setFilter(entry.id)}>{entry.label}<span>{members.filter((member) => matches(member, entry.id, now)).length}</span></button>)}</div>
      </div>
      {message && <p className="form-message" role="status">{message}</p>}
      {loading && !members.length ? <div className="vault-loading"><div className="loading-ring" /></div> : visible.length === 0 ? <div className="empty-state"><ShieldCheck /><p>No members match this view.</p></div> :
        <div className="people-table" role="table" aria-label="Organization members">
          <div className="people-row head" role="row"><span role="columnheader">Member</span><span role="columnheader">Role</span><span role="columnheader">Sign-in security</span><span role="columnheader">Vault health</span><span role="columnheader">Last active</span><span role="columnheader"><span className="sr-only">Actions</span></span></div>
          {visible.map((member) => {
            const self = member.identity_id === vault.identityId;
            const suspended = member.membership_status !== "active" || ["suspended", "deprovisioned"].includes(member.lifecycle_status);
            const score = member.health_score;
            return <div className={`people-row ${suspended ? "muted" : ""}`} role="row" key={member.identity_id}>
              <span role="cell" className="person"><span className="avatar">{member.display_name.slice(0, 2).toUpperCase()}</span><span><strong>{member.display_name}{self ? " (you)" : ""}</strong><small>{member.email ?? "—"}{member.job_title ? ` · ${member.job_title}` : ""}</small></span></span>
              <span role="cell">
                {canManageRoles && !self ? <select aria-label={`Role for ${member.display_name}`} value={member.tenant_role} disabled={busy !== ""} onChange={(event) => changeRole(member, event.target.value as TenantRole)}>
                  {(["owner", "admin", "member", "auditor"] as TenantRole[]).map((role) => <option key={role} value={role} disabled={role === "owner" && tenantRole !== "owner"}>{ROLE_LABELS[role]}</option>)}
                </select> : <span className="role-pill">{ROLE_LABELS[member.tenant_role] ?? member.tenant_role}</span>}
                {member.admin_roles.length > 0 && <span className="role-chips">{member.admin_roles.map((role) => <em key={role}>{ROLE_LABELS[role] ?? role}</em>)}</span>}
                {suspended && <span className="status-chip warn">{member.lifecycle_status}</span>}
              </span>
              <span role="cell" className="signal-cell">
                <span className={member.mfa_factors ? "signal good" : "signal bad"}><Fingerprint /> {member.mfa_factors ? "2-step on" : "No 2-step"}</span>
                <span className="signal"><Laptop /> {member.trusted_devices} device{member.trusted_devices === 1 ? "" : "s"}</span>
              </span>
              <span role="cell" className="health-cell">
                {score === null ? <span className="muted-text">Not reported</span> : <><span className={`score-badge ${score >= 80 ? "good" : score >= 60 ? "warn" : "bad"}`}>{score}</span><small>{(member.breached_count ?? 0) > 0 && <><ShieldAlert /> {member.breached_count} breached · </>}{member.reused_count ?? 0} reused · {member.weak_count ?? 0} weak</small></>}
              </span>
              <span role="cell" className="muted-text">{relativeTime(member.last_sign_in_at, now)}</span>
              <span role="cell" className="row-menu">
                {busy.endsWith(member.identity_id) ? <LoaderCircle className="spin" /> : !self && <>
                  <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${member.display_name}`} aria-expanded={openMenu === member.identity_id} onClick={() => setOpenMenu(openMenu === member.identity_id ? null : member.identity_id)}><MoreHorizontal /></Button>
                  {openMenu === member.identity_id && <div className="menu-popover" role="menu">
                    {suspended ? <button role="menuitem" onClick={() => lifecycle(member, "reactivated")}>Reactivate</button> : <button role="menuitem" onClick={() => lifecycle(member, "suspended")}>Suspend access</button>}
                    <button role="menuitem" className="danger" onClick={() => lifecycle(member, "deprovisioned")}>Offboard &amp; revoke keys</button>
                    <hr />
                    <span className="menu-label">Grant admin role</span>
                    {ADMIN_ROLES.filter((role) => !member.admin_roles.includes(role)).map((role) => <button role="menuitem" key={role} onClick={() => grantAdmin(member, role)}>{ROLE_LABELS[role] ?? role}</button>)}
                  </div>}
                </>}
              </span>
            </div>;
          })}
        </div>}
    </CardContent>
  </Card>;
}
