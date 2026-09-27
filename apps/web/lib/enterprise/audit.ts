import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type VaultActivity =
  | "item.revealed" | "item.copied" | "item.autofilled" | "item.history_viewed"
  | "vault.unlocked" | "vault.locked" | "vault.exported" | "vault.imported" | "policy.blocked";

export type AuditEvent = {
  sequence: number;
  occurred_at: string;
  actor_identity_id: string | null;
  actor_name: string;
  action: string;
  target_type: string;
  target_id: string | null;
  metadata: Record<string, unknown>;
  hash_version: number;
  event_hash: string;
};

export type AuditQuery = {
  beforeSequence?: number | null;
  limit?: number;
  actionPrefix?: string | null;
  actorIdentityId?: string | null;
  since?: string | null;
  until?: string | null;
};

export type ChainVerification = {
  checked_events: number;
  v2_events: number;
  first_invalid_sequence: number | null;
  first_invalid_reason: string | null;
  head_sequence: number | null;
  head_hash: string | null;
  verified_at: string;
};

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

/**
 * Best-effort, metadata-only activity event. It never blocks or breaks the user's
 * action, and it never includes vault content.
 */
export function recordVaultActivity(
  tenantId: string, workspaceId: string, itemId: string | null, action: VaultActivity,
) {
  if (!supabase) return;
  void db().rpc("record_vault_activity", {
    p_tenant_id: tenantId, p_workspace_id: workspaceId, p_item_id: itemId, p_action: action,
  }).then(() => undefined, () => undefined);
}

export async function searchAudit(tenantId: string, query: AuditQuery = {}) {
  const { data, error } = await db().rpc("search_organization_audit", {
    p_tenant_id: tenantId,
    p_before_sequence: query.beforeSequence ?? null,
    p_limit: query.limit ?? 100,
    p_action_prefix: query.actionPrefix || null,
    p_actor_identity_id: query.actorIdentityId || null,
    p_since: query.since || null,
    p_until: query.until || null,
  });
  if (error) throw error;
  return (data ?? []) as AuditEvent[];
}

export async function verifyAuditChain(tenantId: string) {
  const { data, error } = await db().rpc("verify_organization_audit_chain", { p_tenant_id: tenantId });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as ChainVerification | undefined;
  if (!row) throw new Error("The audit chain could not be verified.");
  return row;
}

/** Fetches every matching event (newest first) up to `max` for export. */
export async function collectAudit(tenantId: string, query: AuditQuery = {}, max = 20_000) {
  const all: AuditEvent[] = [];
  let before = query.beforeSequence ?? null;
  while (all.length < max) {
    const page = await searchAudit(tenantId, { ...query, beforeSequence: before, limit: 500 });
    all.push(...page);
    if (page.length < 500) break;
    before = page[page.length - 1].sequence;
  }
  return all.slice(0, max);
}

function csvCell(value: unknown) {
  const text = value === null || value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value);
  // Neutralise spreadsheet formula injection.
  const safe = /^[=+\-@\t\r]/u.test(text) ? `'${text}` : text;
  return /[",\n\r]/u.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function auditToCsv(events: AuditEvent[]) {
  const header = ["sequence", "occurred_at", "actor", "actor_identity_id", "action", "target_type", "target_id", "metadata", "hash_version", "event_hash"];
  const rows = events.map((event) => [
    event.sequence, event.occurred_at, event.actor_name, event.actor_identity_id, event.action,
    event.target_type, event.target_id, event.metadata, event.hash_version, event.event_hash,
  ].map(csvCell).join(","));
  return [header.join(","), ...rows].join("\r\n");
}

const ACTION_LABELS: Record<string, string> = {
  "vault_item.created": "Created a vault item",
  "vault_item.updated": "Updated a vault item",
  "vault_item.deleted": "Moved a vault item to trash",
  "vault_item.restored": "Restored a vault item",
  "item.revealed": "Revealed a secret",
  "item.copied": "Copied a secret",
  "item.autofilled": "Autofilled a login",
  "item.history_viewed": "Viewed item history",
  "vault.unlocked": "Unlocked the vault",
  "vault.locked": "Locked the vault",
  "vault.exported": "Exported the vault",
  "vault.imported": "Imported items",
  "policy.blocked": "Blocked by policy",
  "tenant_memberships.role_changed": "Changed a member role",
  "organization_policies.insert": "Created a policy",
  "organization_policies.update": "Changed a policy",
  "organization_admin_assignments.insert": "Assigned an admin role",
  "organization_admin_assignments.update": "Changed an admin role",
  "organization_invitations.insert": "Invited a member",
  "organization_invitations.update": "Updated an invitation",
  "access_capsules.insert": "Shared an item",
  "access_capsules.update": "Changed a share",
  "access_requests.insert": "Requested access",
  "access_requests.update": "Access request decided",
  "approvals.insert": "Approved or denied access",
  "workspace_invites.insert": "Invited to a workspace",
  "workspace_invites.update": "Workspace invitation changed",
  "missions.insert": "Created a mission",
  "mission_runs.insert": "Started a mission",
  "secure_send.created": "Created a Secure Send link",
  "secure_send.opened": "Secure Send link opened",
  "secure_send.revoked": "Revoked a Secure Send link",
  "workspace_memberships.expiry_set": "Set temporary workspace access",
  "workspace_memberships.expired": "Temporary workspace access expired",
  "workspace_memberships.admin_revoked": "Removed workspace access",
  "vault.password_changed": "Changed vault password",
  "audit_webhook.created": "Added an audit streaming endpoint",
  "audit_webhook.deleted": "Deleted an audit streaming endpoint",
  "audit_webhook.enabled": "Resumed audit streaming",
  "audit_webhook.disabled": "Paused audit streaming",
  "audit_webhook.secret_rotated": "Rotated an audit streaming secret",
};

export function describeAuditAction(action: string) {
  return ACTION_LABELS[action] ?? action.replaceAll("_", " ").replace(".", " · ");
}

export const AUDIT_CATEGORIES: { label: string; prefix: string }[] = [
  { label: "All activity", prefix: "" },
  { label: "Vault items", prefix: "vault_item." },
  { label: "Secret access", prefix: "item." },
  { label: "Vault sessions", prefix: "vault." },
  { label: "Sharing", prefix: "access_" },
  { label: "Policies", prefix: "organization_policies." },
  { label: "Admin roles", prefix: "organization_admin_assignments." },
  { label: "Membership", prefix: "tenant_memberships." },
  { label: "Invitations", prefix: "organization_invitations." },
  { label: "Workspace access", prefix: "workspace_memberships." },
  { label: "Secure Send", prefix: "secure_send." },
  { label: "Audit streaming", prefix: "audit_webhook." },
];
