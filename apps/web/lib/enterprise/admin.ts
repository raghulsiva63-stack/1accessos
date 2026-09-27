import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type TenantRole = "owner" | "admin" | "member" | "auditor";

export type MemberOverview = {
  identity_id: string;
  email: string | null;
  display_name: string;
  job_title: string | null;
  department_id: string | null;
  tenant_role: TenantRole;
  membership_status: string;
  lifecycle_status: string;
  admin_roles: string[];
  mfa_factors: number;
  last_sign_in_at: string | null;
  joined_at: string;
  health_score: number | null;
  weak_count: number | null;
  reused_count: number | null;
  old_count: number | null;
  breached_count: number | null;
  login_count: number | null;
  passkey_count: number | null;
  health_reported_at: string | null;
  trusted_devices: number;
};

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export async function loadMemberOverview(tenantId: string) {
  const { data, error } = await db().rpc("organization_member_overview", { p_tenant_id: tenantId });
  if (error) throw error;
  return (data ?? []) as MemberOverview[];
}

export async function setMemberRole(tenantId: string, identityId: string, role: TenantRole) {
  const { error } = await db().rpc("set_organization_member_role", {
    p_tenant_id: tenantId, p_identity_id: identityId, p_role: role,
  });
  if (error) throw error;
}

export type OrganizationRiskSummary = {
  members: number;
  active: number;
  admins: number;
  withoutMfa: number;
  inactive30: number;
  neverReported: number;
  averageScore: number | null;
  atRisk: number;
  breached: number;
  reused: number;
  weak: number;
};

const DAY = 86_400_000;

/** Pure aggregation used by the dashboard and tests. */
export function summarizeOrganization(members: MemberOverview[], now = Date.now()): OrganizationRiskSummary {
  const active = members.filter((member) => member.membership_status === "active");
  const reported = active.filter((member) => member.health_score !== null);
  const sum = (key: keyof MemberOverview) => active.reduce((total, member) => total + (Number(member[key]) || 0), 0);
  return {
    members: members.length,
    active: active.length,
    admins: active.filter((member) => ["owner", "admin"].includes(member.tenant_role) || member.admin_roles.length > 0).length,
    withoutMfa: active.filter((member) => member.mfa_factors === 0).length,
    inactive30: active.filter((member) => !member.last_sign_in_at || now - Date.parse(member.last_sign_in_at) > 30 * DAY).length,
    neverReported: active.length - reported.length,
    averageScore: reported.length ? Math.round(reported.reduce((total, member) => total + (member.health_score ?? 0), 0) / reported.length) : null,
    atRisk: reported.filter((member) => (member.health_score ?? 100) < 70 || (member.breached_count ?? 0) > 0).length,
    breached: sum("breached_count"),
    reused: sum("reused_count"),
    weak: sum("weak_count"),
  };
}

export function relativeTime(value: string | null, now = Date.now()) {
  if (!value) return "Never";
  const diff = now - Date.parse(value);
  if (!Number.isFinite(diff)) return "Unknown";
  if (diff < 60_000) return "Just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)} min ago`;
  if (diff < DAY) return `${Math.round(diff / 3_600_000)} h ago`;
  if (diff < 30 * DAY) return `${Math.round(diff / DAY)} d ago`;
  return new Date(value).toLocaleDateString();
}

export const ROLE_LABELS: Record<string, string> = {
  owner: "Owner", admin: "Admin", member: "Member", auditor: "Auditor",
  organization_admin: "Org admin", security_admin: "Security admin",
  billing_admin: "Billing admin", helpdesk_admin: "Helpdesk", auditor_role: "Auditor",
};

// ---------------------------------------------------------------------------
// Access review
// ---------------------------------------------------------------------------
export type AccessReviewRow = {
  workspace_id: string;
  suite: string;
  workspace_status: string;
  workspace_created_at: string;
  key_rotation_required: boolean;
  identity_id: string;
  display_name: string;
  email: string | null;
  role: "owner" | "manager" | "editor" | "viewer";
  membership_status: string;
  expires_at: string | null;
  member_since: string;
  last_activity_at: string | null;
};

export type ReviewedWorkspace = {
  id: string;
  suite: string;
  status: string;
  createdAt: string;
  keyRotationRequired: boolean;
  members: AccessReviewRow[];
};

export async function loadAccessReview(tenantId: string) {
  const { data, error } = await db().rpc("organization_access_review", { p_tenant_id: tenantId });
  if (error) throw error;
  return (data ?? []) as AccessReviewRow[];
}

export function groupAccessReview(rows: AccessReviewRow[]): ReviewedWorkspace[] {
  const byWorkspace = new Map<string, ReviewedWorkspace>();
  for (const row of rows) {
    const existing = byWorkspace.get(row.workspace_id) ?? {
      id: row.workspace_id, suite: row.suite, status: row.workspace_status,
      createdAt: row.workspace_created_at, keyRotationRequired: row.key_rotation_required, members: [],
    };
    existing.members.push(row);
    byWorkspace.set(row.workspace_id, existing);
  }
  return [...byWorkspace.values()];
}

export async function adminRevokeWorkspaceMember(tenantId: string, workspaceId: string, identityId: string) {
  const { error } = await db().rpc("admin_revoke_workspace_member", {
    p_tenant_id: tenantId, p_workspace_id: workspaceId, p_identity_id: identityId,
  });
  if (error) throw error;
}

export async function setWorkspaceMemberExpiry(workspaceId: string, identityId: string, expiresAt: string | null) {
  const { error } = await db().rpc("set_workspace_member_expiry", {
    p_workspace_id: workspaceId, p_identity_id: identityId, p_expires_at: expiresAt,
  });
  if (error) throw error;
}
