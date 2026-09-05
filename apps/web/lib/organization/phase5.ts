import { supabase } from "@/lib/supabase/client";
import type { Json, Tables } from "@/lib/supabase/database.types";

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

export type OrganizationSnapshot = {
  departments: OrganizationDepartment[];
  teams: OrganizationTeam[];
  groups: OrganizationGroup[];
  profiles: OrganizationProfile[];
  admins: OrganizationAdmin[];
  policies: OrganizationPolicy[];
  members: TenantMember[];
  currentTenantRole: string | null;
};

function client() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase;
}

export function organizationSlug(value: string) {
  return value.normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-|-$/gu, "").slice(0, 68);
}

export async function loadOrganization(tenantId: string, identityId: string): Promise<OrganizationSnapshot> {
  const db = client();
  const [departments, teams, groups, profiles, admins, policies, members, current] = await Promise.all([
    db.from("organization_departments").select("id,tenant_id,parent_department_id,display_name,slug,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_teams").select("id,tenant_id,department_id,display_name,slug,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_groups").select("id,tenant_id,display_name,slug,description,status").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_profiles").select("identity_id,department_id,manager_identity_id,display_name,job_title,lifecycle_status,joined_on").eq("tenant_id",tenantId).order("display_name"),
    db.from("organization_admin_assignments").select("id,identity_id,role,scope_type,scope_id,status").eq("tenant_id",tenantId).eq("status","active"),
    db.from("organization_policies").select("id,scope_type,scope_id,policy_type,configuration,priority,enforced,version").eq("tenant_id",tenantId).order("priority",{ ascending: false }),
    db.from("tenant_memberships").select("identity_id,role,status").eq("tenant_id",tenantId),
    db.from("tenant_memberships").select("role").eq("tenant_id",tenantId).eq("identity_id",identityId).eq("status","active").maybeSingle(),
  ]);
  const failed = [departments,teams,groups,profiles,admins,policies,members,current].find((result) => result.error);
  if (failed?.error) throw failed.error;
  return {
    departments: (departments.data ?? []) as OrganizationDepartment[],
    teams: (teams.data ?? []) as OrganizationTeam[],
    groups: (groups.data ?? []) as OrganizationGroup[],
    profiles: (profiles.data ?? []) as OrganizationProfile[],
    admins: (admins.data ?? []) as OrganizationAdmin[],
    policies: (policies.data ?? []) as OrganizationPolicy[],
    members: (members.data ?? []) as TenantMember[],
    currentTenantRole: current.data?.role ?? null,
  };
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
) {
  const { error } = await client().from("organization_policies").upsert({
    tenant_id: tenantId,
    scope_type: "tenant",
    scope_id: null,
    policy_type: policyType,
    configuration,
    created_by: identityId,
    version: 1,
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
