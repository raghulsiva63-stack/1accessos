import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import type { Json, Tables } from "@/lib/supabase/database.types";
import { fromBase64Url, randomBytes, toBase64Url, toPostgresBytea } from "@/lib/crypto/vault";
import { emailHash } from "@/lib/collaboration/phase2";

export type OrganizationDepartment = Pick<Tables<"organization_departments">,
  "id" | "tenant_id" | "parent_department_id" | "display_name" | "slug" | "status">;
export type OrganizationTeam = Pick<Tables<"organization_teams">,
  "id" | "tenant_id" | "department_id" | "display_name" | "slug" | "status">;
export type OrganizationGroup = Pick<Tables<"organization_groups">,
  "id" | "tenant_id" | "display_name" | "slug" | "description" | "status">;
export type OrganizationProfile = Pick<Tables<"organization_profiles">,
  "identity_id" | "department_id" | "manager_identity_id" | "display_name" | "job_title" | "lifecycle_status" | "joined_on">;
export type OrganizationAdmin = Pick<Tables<"organization_admin_assignments">,
  "id" | "identity_id" | "role" | "scope_type" | "scope_id" | "status">;
export type OrganizationPolicy = Pick<Tables<"organization_policies">,
  "id" | "scope_type" | "scope_id" | "policy_type" | "configuration" | "priority" | "enforced" | "version">;
export type TenantMember = Pick<Tables<"tenant_memberships">, "identity_id" | "role" | "status">;
export type OrganizationTeamMembership = {
  tenant_id: string;
  team_id: string;
  identity_id: string;
  role: "lead" | "member";
  status: string;
};
export type OrganizationInvitation = {
  id: string;
  display_name: string;
  job_title: string | null;
  department_id: string | null;
  team_id: string | null;
  team_role: "lead" | "member";
  status: string;
  expires_at: string;
  accepted_by: string | null;
  created_at: string;
};
export type OrganizationInvitationLink = { id: string; token: Uint8Array; kind: "org-invite" };
export type OrganizationAdminRole = "organization_admin" | "security_admin" | "billing_admin" | "helpdesk_admin" | "auditor";
export type OrganizationScopeType = "tenant" | "department" | "team";
export type OrganizationInviteCsvRow = {
  email: string;
  displayName: string;
  jobTitle?: string;
  departmentSlug?: string;
  teamSlug?: string;
  teamRole: "lead" | "member";
};
export type EffectiveOrganizationPolicy = {
  policy_id: string;
  policy_type: string;
  configuration: Json;
  source_scope_type: OrganizationScopeType;
  source_scope_id: string | null;
  priority: number;
  version: number;
};
export type DevicePostureReport = {
  id: string;
  device_id: string;
  identity_id: string;
  source: "self_reported" | "mdm" | "idp" | "attested";
  verification_status: "unverified" | "verified" | "rejected";
  evaluation: "unknown" | "compliant" | "non_compliant";
  os_family: string;
  observed_at: string;
  valid_until: string;
};
export type DeviceReadiness = {
  allowed: boolean;
  device_trusted: boolean;
  approval_required: boolean;
  posture: string;
  verified: boolean;
  valid_until: string | null;
  mode: "readiness_only";
  reason: string;
};
export type OrganizationAuditRow = {
  sequence: number;
  occurred_at: string;
  actor_identity_id: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  metadata: Json;
  previous_hash: string | null;
  event_hash: string;
};
export type OrganizationDevice = { id: string; status: string; created_at: string; last_seen_at: string | null };

export type OrganizationSnapshot = {
  departments: OrganizationDepartment[];
  teams: OrganizationTeam[];
  groups: OrganizationGroup[];
  profiles: OrganizationProfile[];
  admins: OrganizationAdmin[];
  policies: OrganizationPolicy[];
  members: TenantMember[];
  teamMemberships: OrganizationTeamMembership[];
  invitations: OrganizationInvitation[];
  currentTenantRole: string | null;
};

function client() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase;
}

function governanceClient() {
  return client() as unknown as SupabaseClient;
}

async function sha256(value: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256",Uint8Array.from(value).buffer));
}

export function organizationSlug(value: string) {
  return value.normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-|-$/gu, "").slice(0, 68);
}

export async function loadOrganization(tenantId: string, identityId: string): Promise<OrganizationSnapshot> {
  const db = client();
  const governance = governanceClient();
  const [departments, teams, groups, profiles, admins, policies, members, teamMemberships, invitations, current] = await Promise.all([
    db.from("organization_departments").select("id,tenant_id,parent_department_id,display_name,slug,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_teams").select("id,tenant_id,department_id,display_name,slug,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_groups").select("id,tenant_id,display_name,slug,description,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_profiles").select("identity_id,department_id,manager_identity_id,display_name,job_title,lifecycle_status,joined_on").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_admin_assignments").select("id,identity_id,role,scope_type,scope_id,status").eq("tenant_id",tenantId).eq("status","active"),
    db.from("organization_policies").select("id,scope_type,scope_id,policy_type,configuration,priority,enforced,version").eq("tenant_id",tenantId).order("priority",{ ascending: false }),
    db.from("tenant_memberships").select("identity_id,role,status").eq("tenant_id",tenantId),
    governance.from("organization_team_memberships").select("tenant_id,team_id,identity_id,role,status").eq("tenant_id",tenantId),
    governance.from("organization_invitations").select("id,display_name,job_title,department_id,team_id,team_role,status,expires_at,accepted_by,created_at").eq("tenant_id",tenantId).order("created_at",{ ascending: false }).limit(100),
    db.from("tenant_memberships").select("role").eq("tenant_id",tenantId).eq("identity_id",identityId).eq("status","active").maybeSingle(),
  ]);
  const failed = [departments,teams,groups,profiles,admins,policies,members,teamMemberships,invitations,current].find((result) => result.error);
  if (failed?.error) throw failed.error;
  return {
    departments: (departments.data ?? []) as OrganizationDepartment[],
    teams: (teams.data ?? []) as OrganizationTeam[],
    groups: (groups.data ?? []) as OrganizationGroup[],
    profiles: (profiles.data ?? []) as OrganizationProfile[],
    admins: (admins.data ?? []) as OrganizationAdmin[],
    policies: (policies.data ?? []) as OrganizationPolicy[],
    members: (members.data ?? []) as TenantMember[],
    teamMemberships: (teamMemberships.data ?? []) as OrganizationTeamMembership[],
    invitations: (invitations.data ?? []) as OrganizationInvitation[],
    currentTenantRole: current.data?.role ?? null,
  };
}

export function hasOrganizationCapability(
  snapshot: OrganizationSnapshot,
  identityId: string,
  roles: OrganizationAdminRole[],
) {
  return snapshot.currentTenantRole === "owner" || snapshot.currentTenantRole === "admin"
    || snapshot.admins.some((assignment) => assignment.identity_id === identityId
      && assignment.status === "active" && roles.includes(assignment.role as OrganizationAdminRole));
}

export function organizationScopeAllows(
  snapshot: OrganizationSnapshot,
  identityId: string,
  roles: OrganizationAdminRole[],
  departmentId?: string | null,
  teamId?: string | null,
) {
  if (snapshot.currentTenantRole === "owner" || snapshot.currentTenantRole === "admin") return true;
  const targetDepartment = departmentId
    ?? snapshot.teams.find((team) => team.id === teamId)?.department_id
    ?? null;
  const parents = new Map(snapshot.departments.map((department) => [department.id,department.parent_department_id]));
  function departmentContains(scopeId: string, targetId: string | null) {
    let current = targetId;
    const visited = new Set<string>();
    while (current && !visited.has(current)) {
      if (current === scopeId) return true;
      visited.add(current);
      current = parents.get(current) ?? null;
    }
    return false;
  }
  return snapshot.admins.some((assignment) => {
    if (assignment.identity_id !== identityId || assignment.status !== "active"
      || !roles.includes(assignment.role as OrganizationAdminRole)) return false;
    if (!departmentId && !teamId) return true;
    if (assignment.scope_type === "tenant") return true;
    if (assignment.scope_type === "team") return Boolean(teamId && assignment.scope_id === teamId);
    return Boolean(assignment.scope_id && departmentContains(assignment.scope_id,targetDepartment));
  });
}

export async function createOrganizationDepartment(tenantId: string, identityId: string, displayName: string, parentDepartmentId?: string) {
  const name = displayName.trim();
  const slug = `${organizationSlug(name)}-${crypto.randomUUID().slice(0,6)}`;
  const { error } = await client().from("organization_departments").insert({
    tenant_id: tenantId, created_by: identityId, display_name: name, slug,
    parent_department_id: parentDepartmentId || null,
  });
  if (error) throw error;
}

export async function createOrganizationTeam(tenantId: string, identityId: string, displayName: string, departmentId?: string) {
  const name = displayName.trim();
  const slug = `${organizationSlug(name)}-${crypto.randomUUID().slice(0,6)}`;
  const { error } = await client().from("organization_teams").insert({
    tenant_id: tenantId, created_by: identityId, display_name: name, slug,
    department_id: departmentId || null,
  });
  if (error) throw error;
}

export async function createOrganizationGroup(tenantId: string, identityId: string, displayName: string, description?: string) {
  const name = displayName.trim();
  const slug = `${organizationSlug(name)}-${crypto.randomUUID().slice(0,6)}`;
  const { error } = await client().from("organization_groups").insert({
    tenant_id: tenantId, created_by: identityId, display_name: name, slug,
    description: description?.trim() || null,
  });
  if (error) throw error;
}

export async function onboardOrganizationMember(
  tenantId: string,
  identityId: string,
  displayName: string,
  jobTitle?: string,
  departmentId?: string,
) {
  const { error } = await client().rpc("onboard_organization_member", {
    p_tenant_id: tenantId,
    p_identity_id: identityId,
    p_display_name: displayName.trim(),
    p_job_title: jobTitle?.trim() || undefined,
    p_department_id: departmentId || undefined,
  });
  if (error) throw error;
}

export async function createOrganizationPolicy(
  tenantId: string,
  identityId: string,
  policyType: OrganizationPolicy["policy_type"],
  configuration: Json,
  scopeType: OrganizationScopeType = "tenant",
  scopeId?: string,
) {
  const db = client();
  let existingQuery = db.from("organization_policies")
    .select("version").eq("tenant_id",tenantId).eq("scope_type",scopeType)
    .eq("policy_type",policyType);
  existingQuery = scopeId ? existingQuery.eq("scope_id",scopeId) : existingQuery.is("scope_id",null);
  const existing = await existingQuery.maybeSingle();
  if (existing.error) throw existing.error;
  const { error } = await db.from("organization_policies").upsert({
    tenant_id: tenantId,
    scope_type: scopeType,
    scope_id: scopeId || null,
    policy_type: policyType,
    configuration,
    created_by: identityId,
    version: (existing.data?.version ?? 0) + 1,
    enforced: true,
  }, { onConflict: "tenant_id,scope_type,scope_id,policy_type" });
  if (error) throw error;
}

export async function manageOrganizationMember(
  tenantId: string,
  identityId: string,
  eventType: "moved" | "leave_started" | "suspended" | "reactivated" | "deprovisioned",
  departmentId?: string,
) {
  const { error } = await client().rpc("manage_organization_member_lifecycle", {
    p_tenant_id: tenantId,
    p_identity_id: identityId,
    p_event_type: eventType,
    p_department_id: departmentId || undefined,
    p_reason_code: eventType === "deprovisioned" ? "termination" : eventType === "moved" ? "transfer" : "other",
  });
  if (error) throw error;
}

export async function assignOrganizationAdministrator(
  tenantId: string,
  identityId: string,
  assignedBy: string,
  role: OrganizationAdminRole,
  scopeType: OrganizationScopeType,
  scopeId?: string,
) {
  const { error } = await client().from("organization_admin_assignments").insert({
    tenant_id: tenantId,
    identity_id: identityId,
    assigned_by: assignedBy,
    role,
    scope_type: scopeType,
    scope_id: scopeType === "tenant" ? null : scopeId,
    status: "active",
  });
  if (error) throw error;
}

export async function revokeOrganizationAdministrator(assignmentId: string) {
  const { error } = await client().from("organization_admin_assignments")
    .update({ status: "revoked",updated_at: new Date().toISOString() }).eq("id",assignmentId);
  if (error) throw error;
}

export function parseOrganizationInvitationLink(hash: string): OrganizationInvitationLink | null {
  const match = hash.match(/^#org-invite=([0-9a-f-]{36})\.([A-Za-z0-9_-]+)$/iu);
  if (!match) return null;
  const token = fromBase64Url(match[2]);
  if (token.byteLength !== 32) return null;
  return { id: match[1],token,kind: "org-invite" };
}

export async function createOrganizationInvitation(
  tenantId: string,
  identityId: string,
  recipientEmail: string,
  displayName: string,
  expiresAt: string,
  origin: string,
  options: { jobTitle?: string; departmentId?: string; teamId?: string; teamRole?: "lead" | "member" } = {},
) {
  const id = crypto.randomUUID();
  const token = randomBytes(32);
  const tokenHash = await sha256(token);
  const { error } = await governanceClient().from("organization_invitations").insert({
    id,
    tenant_id: tenantId,
    created_by: identityId,
    recipient_email_hash: toPostgresBytea(await emailHash(recipientEmail)),
    token_hash: toPostgresBytea(tokenHash),
    display_name: displayName.trim(),
    job_title: options.jobTitle?.trim() || null,
    department_id: options.departmentId || null,
    team_id: options.teamId || null,
    team_role: options.teamRole ?? "member",
    status: "pending",
    expires_at: expiresAt,
  });
  tokenHash.fill(0);
  if (error) { token.fill(0); throw error; }
  const link = `${origin.replace(/\/$/u,"")}/#org-invite=${id}.${toBase64Url(token)}`;
  token.fill(0);
  return link;
}

export async function acceptOrganizationInvitation(link: OrganizationInvitationLink) {
  const tokenHash = await sha256(link.token);
  try {
    const { data,error } = await governanceClient().rpc("accept_organization_invitation",{
      p_invitation_id: link.id,
      p_token_hash: toPostgresBytea(tokenHash),
    });
    if (error) throw error;
    return data as { tenant_id: string; department_id: string | null; team_id: string | null };
  } finally {
    tokenHash.fill(0);
    link.token.fill(0);
  }
}

export async function revokeOrganizationInvitation(invitationId: string) {
  const { error } = await governanceClient().rpc("revoke_organization_invitation",{
    p_invitation_id: invitationId,
  });
  if (error) throw error;
}

function parseCsvCells(row: string) {
  const cells: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < row.length; index += 1) {
    const character = row[index];
    if (character === '"' && quoted && row[index + 1] === '"') { value += '"'; index += 1; }
    else if (character === '"') quoted = !quoted;
    else if (character === "," && !quoted) { cells.push(value.trim()); value = ""; }
    else value += character;
  }
  cells.push(value.trim());
  return cells;
}

export function parseOrganizationInviteCsv(csv: string): OrganizationInviteCsvRow[] {
  const rows = csv.replace(/^\uFEFF/u,"").split(/\r?\n/u).filter((row) => row.trim());
  if (rows.length < 2) throw new Error("The CSV does not contain any employee records.");
  const headers = parseCsvCells(rows[0]).map((header) => header.toLowerCase());
  const indexOf = (...names: string[]) => names.map((name) => headers.indexOf(name)).find((index) => index >= 0) ?? -1;
  const emailIndex = indexOf("email","work_email");
  const nameIndex = indexOf("display_name","name","employee_name");
  const titleIndex = indexOf("job_title","title");
  const departmentIndex = indexOf("department","department_slug");
  const teamIndex = indexOf("team","team_slug");
  const roleIndex = indexOf("team_role","role");
  if (emailIndex < 0 || nameIndex < 0) throw new Error("CSV must include email and display_name columns.");
  if (rows.length > 201) throw new Error("Bulk onboarding supports up to 200 employees per file.");
  const parsed = rows.slice(1).map(parseCsvCells).map((cells) => ({
    email: cells[emailIndex]?.trim().toLowerCase() ?? "",
    displayName: cells[nameIndex]?.trim() ?? "",
    jobTitle: titleIndex >= 0 ? cells[titleIndex]?.trim() || undefined : undefined,
    departmentSlug: departmentIndex >= 0 ? cells[departmentIndex]?.trim().toLowerCase() || undefined : undefined,
    teamSlug: teamIndex >= 0 ? cells[teamIndex]?.trim().toLowerCase() || undefined : undefined,
    teamRole: roleIndex >= 0 && cells[roleIndex]?.trim().toLowerCase() === "lead" ? "lead" as const : "member" as const,
  }));
  const seen = new Set<string>();
  for (const row of parsed) {
    if (!/^\S+@\S+\.\S+$/u.test(row.email) || !row.displayName) throw new Error("Every CSV row needs a valid email and display name.");
    if (seen.has(row.email)) throw new Error(`Duplicate email in CSV: ${row.email}`);
    seen.add(row.email);
  }
  return parsed;
}

export async function resolveOrganizationPolicies(tenantId: string, identityId: string) {
  const { data,error } = await governanceClient().rpc("resolve_organization_policies",{
    p_tenant_id: tenantId,p_identity_id: identityId,
  });
  if (error) throw error;
  return (data ?? []) as EffectiveOrganizationPolicy[];
}

export async function reportSelfDevicePosture(
  tenantId: string,
  identityId: string,
  deviceId: string,
  checks: { osFamily: string; screenLock: boolean; diskEncrypted: boolean; securityPatchCurrent: boolean; endpointProtection: boolean },
) {
  const now = new Date();
  const validUntil = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const { error } = await governanceClient().from("organization_device_posture_reports").insert({
    tenant_id: tenantId,device_id: deviceId,identity_id: identityId,
    source: "self_reported",verification_status: "unverified",evaluation: "unknown",
    os_family: checks.osFamily,screen_lock: checks.screenLock,disk_encrypted: checks.diskEncrypted,
    security_patch_current: checks.securityPatchCurrent,endpoint_protection: checks.endpointProtection,
    observed_at: now.toISOString(),valid_until: validUntil.toISOString(),created_by: identityId,
  });
  if (error) throw error;
}

export async function evaluateOrganizationDeviceReadiness(tenantId: string, deviceId: string, identityId: string) {
  const { data,error } = await governanceClient().rpc("evaluate_organization_device_readiness",{
    p_tenant_id: tenantId,p_device_id: deviceId,p_identity_id: identityId,
  });
  if (error) throw error;
  return data as DeviceReadiness;
}

export async function loadOrganizationDevicePosture(tenantId: string, identityId: string) {
  const { data,error } = await governanceClient().from("organization_device_posture_reports")
    .select("id,device_id,identity_id,source,verification_status,evaluation,os_family,observed_at,valid_until")
    .eq("tenant_id",tenantId).eq("identity_id",identityId).order("observed_at",{ ascending: false }).limit(50);
  if (error) throw error;
  return (data ?? []) as DevicePostureReport[];
}

export async function loadOrganizationDevices(identityId: string) {
  const { data,error } = await client().from("devices")
    .select("id,status,created_at,last_seen_at").eq("identity_id",identityId)
    .order("created_at",{ ascending: false });
  if (error) throw error;
  return (data ?? []) as OrganizationDevice[];
}

export async function exportOrganizationAudit(tenantId: string, afterSequence = 0) {
  const { data,error } = await governanceClient().rpc("export_organization_audit",{
    p_tenant_id: tenantId,p_after_sequence: afterSequence,p_limit: 1000,
  });
  if (error) throw error;
  return (data ?? []) as OrganizationAuditRow[];
}
