import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type ScimToken = { id: string; name: string; token_hint: string; created_at: string; last_used_at: string | null; revoked_at: string | null };
export type ProvisionedUser = { id: string; external_id: string | null; user_name: string; display_name: string; job_title: string | null; active: boolean; identity_id: string | null; created_at: string };
export type SsoConnection = {
  tenant_id: string; domain: string; verification_token: string; domain_verified_at: string | null;
  metadata_url: string | null; status: "draft" | "requested" | "active" | "disabled"; enforce_sso: boolean; updated_at: string;
};

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

export function scimBaseUrl() {
  const base = process.env.NEXT_PUBLIC_SUPABASE_URL?.replace(/\/$/u, "") ?? "https://<project>.supabase.co";
  return `${base}/functions/v1/scim/v2`;
}

export async function listScimTokens(tenantId: string): Promise<ScimToken[]> {
  const { data, error } = await db().from("scim_tokens").select("id,name,token_hint,created_at,last_used_at,revoked_at")
    .eq("tenant_id", tenantId).order("created_at", { ascending: false });
  if (error) throw error;
  return (data ?? []) as ScimToken[];
}

export async function createScimToken(tenantId: string, name: string): Promise<string> {
  const { data, error } = await db().rpc("create_scim_token", { p_tenant_id: tenantId, p_name: name });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as { token: string } | undefined;
  if (!row?.token) throw new Error("The token could not be created.");
  return row.token;
}

export async function revokeScimToken(id: string) {
  const { error } = await db().rpc("revoke_scim_token", { p_id: id });
  if (error) throw error;
}

export async function listProvisionedUsers(tenantId: string): Promise<ProvisionedUser[]> {
  const { data, error } = await db().from("scim_provisioned_users")
    .select("id,external_id,user_name,display_name,job_title,active,identity_id,created_at")
    .eq("tenant_id", tenantId).order("created_at", { ascending: false }).limit(500);
  if (error) throw error;
  return (data ?? []) as ProvisionedUser[];
}

/** Organizations that provisioned the signed-in email but the person has not joined yet. */
export async function myPendingProvisioning(): Promise<ProvisionedUser[]> {
  const { data, error } = await db().from("scim_provisioned_users")
    .select("id,external_id,user_name,display_name,job_title,active,identity_id,created_at")
    .is("identity_id", null).eq("active", true).limit(5);
  if (error) throw error;
  return (data ?? []) as ProvisionedUser[];
}

export async function claimProvisionedMembership(id: string) {
  const { error } = await db().rpc("claim_provisioned_membership", { p_id: id });
  if (error) throw error;
}

export async function loadSsoConnection(tenantId: string): Promise<SsoConnection | null> {
  const { data, error } = await db().from("sso_connections")
    .select("tenant_id,domain,verification_token,domain_verified_at,metadata_url,status,enforce_sso,updated_at")
    .eq("tenant_id", tenantId).maybeSingle();
  if (error) throw error;
  return data as SsoConnection | null;
}

export async function saveSsoConnection(tenantId: string, domain: string, metadataUrl: string) {
  const { error } = await db().rpc("save_sso_connection", { p_tenant_id: tenantId, p_domain: domain, p_metadata_url: metadataUrl || null });
  if (error) throw error;
}

export async function verifySsoDomain(tenantId: string): Promise<boolean> {
  const { data, error } = await db().functions.invoke<{ verified?: boolean }>("identity-admin", { body: { action: "verify_domain", tenantId } });
  if (error) throw error;
  return data?.verified === true;
}

export async function requestSsoActivation(tenantId: string) {
  const { error } = await db().rpc("request_sso_activation", { p_tenant_id: tenantId });
  if (error) throw error;
}

export async function setSsoEnforcement(tenantId: string, enforce: boolean) {
  const { error } = await db().rpc("set_sso_enforcement", { p_tenant_id: tenantId, p_enforce: enforce });
  if (error) throw error;
}

/** Login screen: is SSO available / required for this email's domain? Fails closed to "not available". */
export async function ssoStatusForEmail(email: string): Promise<{ available: boolean; required: boolean }> {
  if (!/@[^@\s]+\.[^@\s]+$/u.test(email)) return { available: false, required: false };
  try {
    const { data, error } = await db().rpc("sso_status_for_email", { p_email: email });
    if (error) return { available: false, required: false };
    const row = (Array.isArray(data) ? data[0] : data) as { sso_available?: boolean; sso_required?: boolean } | undefined;
    return { available: row?.sso_available === true, required: row?.sso_required === true };
  } catch { return { available: false, required: false }; }
}

export async function signInWithSso(email: string) {
  const domain = email.split("@")[1]?.trim().toLowerCase();
  if (!domain) throw new Error("Enter your work email address.");
  const { data, error } = await db().auth.signInWithSSO({ domain, options: { redirectTo: `${window.location.origin}/` } });
  if (error) throw error;
  if (data?.url) window.location.assign(data.url);
}
