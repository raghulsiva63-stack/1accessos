import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "open" | "acknowledged" | "resolved";

export type SecurityAlert = {
  id: string;
  tenant_id: string;
  severity: AlertSeverity;
  kind: string;
  title: string;
  detail: Record<string, unknown>;
  actor_identity_id: string | null;
  status: AlertStatus;
  acknowledged_at: string | null;
  note: string | null;
  created_at: string;
};

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export const SEVERITY_ORDER: Record<AlertSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export async function listSecurityAlerts(tenantId: string, status: AlertStatus | "all" = "all"): Promise<SecurityAlert[]> {
  let query = db().from("security_alerts")
    .select("id,tenant_id,severity,kind,title,detail,actor_identity_id,status,acknowledged_at,note,created_at")
    .eq("tenant_id", tenantId);
  if (status !== "all") query = query.eq("status", status);
  const { data, error } = await query.order("created_at", { ascending: false }).limit(200);
  if (error) throw error;
  return (data ?? []) as SecurityAlert[];
}

export async function updateSecurityAlert(id: string, status: AlertStatus, note?: string) {
  const { error } = await db().rpc("update_security_alert", { p_id: id, p_status: status, p_note: note ?? null });
  if (error) throw error;
}

/** Plain-language guidance for each alert kind. */
export const ALERT_GUIDANCE: Record<string, string> = {
  "emergency_access.requested": "Confirm with the vault owner that this request is expected. Deny it in Emergency access if not.",
  "emergency_access.activated": "Someone opened a vault with emergency access. Confirm the situation and rotate sensitive secrets afterwards if needed.",
  "vault.exported": "Check that the export was expected and that the file is stored safely or deleted.",
  "admin.granted": "Verify the new administrator with a second person. Unexpected admin grants are a common takeover step.",
  "policy.changed": "Review the policy change in the audit log and confirm it was approved.",
  "audit_streaming.stopped": "Your SIEM no longer receives events. Re-enable streaming unless this was planned.",
  "secrets.burst": "Many secrets were revealed or copied in a short time. Contact the member and review the audit log.",
  "policy.blocked_repeatedly": "A member keeps hitting a policy. They may need help — or be probing restrictions.",
  "items.mass_deleted": "Many items were moved to trash. They can be restored from Trash within the retention period.",
  "scim.token_created": "A new provisioning token can create and remove members. Make sure it was created by your identity team.",
  "org_recovery.approved": "An administrator decrypted a member's vault key to help them recover. Confirm the member asked for it.",
  "org_recovery.key_set": "The organization recovery key changed. Make sure the new kit is stored offline and the old one destroyed.",
  "sso.optional": "Members can sign in without your identity provider again. Confirm this was intended.",
  "scim.user_deactivated": "Your identity provider removed a person. Their vault access was revoked; rotate shared secrets they knew.",
  "sign_in.unfamiliar": "A member signed in from a new device on a new network. They were emailed; confirm with them if it looks unexpected.",
  "sign_in.new_country": "A member signed in from a country they haven't used before. Check with them, and ask them to review Sign-in activity.",
  "sign_in.many_networks": "Sign-ins from many networks in an hour can mean a stolen password or session. Contact the member and have them sign out other sessions and change their account password.",
  "member.breach_exposed": "A member's work email is in a new data breach. Ask them to change any password they reused there; start a rotation campaign for shared logins they know.",
  "rotation.overdue": "A password rotation campaign passed its due date with open tasks. Remind the assignees or extend the campaign.",
};
