import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type AuditWebhook = {
  id: string;
  name: string;
  url: string;
  event_prefixes: string[];
  enabled: boolean;
  created_at: string;
  failure_count: number;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_status: number | null;
  last_error: string | null;
  last_test_status: number | null;
  last_test_at: string | null;
};

export const WEBHOOK_EVENT_FILTERS: { value: string; label: string }[] = [
  { value: "vault_item.", label: "Vault item changes" },
  { value: "item.", label: "Secret reveals and copies" },
  { value: "vault.", label: "Vault sessions, import and export" },
  { value: "organization_policies.", label: "Policy changes" },
  { value: "tenant_memberships.", label: "Membership and roles" },
  { value: "organization_admin_assignments.", label: "Admin role changes" },
  { value: "workspace_memberships.", label: "Workspace access" },
  { value: "access_", label: "Sharing and access requests" },
  { value: "secure_send.", label: "Secure Send" },
  { value: "audit_webhook.", label: "Audit streaming changes" },
];

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

const COLUMNS = "id,name,url,event_prefixes,enabled,created_at,failure_count,last_attempt_at,last_success_at,last_status,last_error,last_test_status,last_test_at";

export async function listAuditWebhooks(tenantId: string) {
  const { data, error } = await db().from("audit_webhooks").select(COLUMNS).eq("tenant_id", tenantId).order("created_at");
  if (error) throw error;
  return (data ?? []) as AuditWebhook[];
}

export async function createAuditWebhook(tenantId: string, name: string, url: string, prefixes: string[]) {
  const { data, error } = await db().rpc("create_audit_webhook", { p_tenant_id: tenantId, p_name: name, p_url: url.trim(), p_event_prefixes: prefixes });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as { id: string; secret: string } | undefined;
  if (!row) throw new Error("The webhook could not be created.");
  return row;
}

export async function setAuditWebhookEnabled(id: string, enabled: boolean) {
  const { error } = await db().rpc("update_audit_webhook", { p_id: id, p_enabled: enabled, p_rotate_secret: false });
  if (error) throw error;
}

export async function rotateAuditWebhookSecret(id: string) {
  const { data, error } = await db().rpc("update_audit_webhook", { p_id: id, p_enabled: null, p_rotate_secret: true });
  if (error) throw error;
  return data as string;
}

export async function deleteAuditWebhook(id: string) {
  const { error } = await db().rpc("delete_audit_webhook", { p_id: id });
  if (error) throw error;
}

export async function testAuditWebhook(id: string) {
  const { error } = await db().rpc("test_audit_webhook", { p_id: id });
  if (error) throw error;
}

export function webhookHealth(hook: AuditWebhook): { tone: "good" | "warn" | "bad" | "idle"; label: string } {
  if (!hook.enabled) return hook.failure_count >= 100 ? { tone: "bad", label: "Disabled after repeated failures" } : { tone: "idle", label: "Paused" };
  if (hook.failure_count > 0) return { tone: "warn", label: `Retrying · ${hook.failure_count} failed attempt${hook.failure_count === 1 ? "" : "s"}` };
  if (hook.last_success_at) return { tone: "good", label: "Delivering" };
  return { tone: "idle", label: "Waiting for events" };
}

export const SIGNATURE_EXAMPLE = `// Node.js — verify a Passkey-X audit webhook
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(rawBody, headers, secret) {
  const timestamp = headers["x-passkeyx-timestamp"];
  const signature = headers["x-passkeyx-signature"]?.replace(/^v1=/, "") ?? "";
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const expected = createHmac("sha256", secret).update(\`\${timestamp}.\${rawBody}\`).digest("hex");
  return signature.length === expected.length
    && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}`;
