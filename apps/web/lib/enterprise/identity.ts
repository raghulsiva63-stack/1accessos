import { functionErrorCode } from "@/lib/supabase/function-error";
import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";

export type ScimToken = { id: string; name: string; token_hint: string; created_at: string; last_used_at: string | null; revoked_at: string | null };
export type ProvisionedUser = { id: string; external_id: string | null; user_name: string; display_name: string; job_title: string | null; active: boolean; identity_id: string | null; created_at: string };
export type SsoConnection = {
  tenant_id: string; domain: string; verification_token: string; domain_verified_at: string | null;
  metadata_url: string | null; status: "draft" | "requested" | "active" | "disabled"; enforce_sso: boolean; updated_at: string;
  activation_error?: string | null;
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

export type PendingProvisioning = { id: string; tenant_id: string; display_name: string };

/** Organizations that provisioned the signed-in email but the person has not joined yet (own offers only). */
export async function myPendingProvisioning(): Promise<PendingProvisioning[]> {
  const { data, error } = await db().rpc("my_pending_provisioning");
  if (error) throw error;
  return ((data ?? []) as PendingProvisioning[]).slice(0, 5);
}

export async function claimProvisionedMembership(id: string) {
  const { error } = await db().rpc("claim_provisioned_membership", { p_id: id });
  if (error) throw error;
}

export async function loadSsoConnection(tenantId: string): Promise<SsoConnection | null> {
  const { data, error } = await db().from("sso_connections")
    .select("tenant_id,domain,verification_token,domain_verified_at,metadata_url,status,enforce_sso,updated_at,activation_error")
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
  if (error) throw new Error(await functionErrorCode(error));
  return data?.verified === true;
}

export type SsoActivationResult = "active" | "requested";

/**
 * Self-serve activation: registers the identity provider with Supabase Auth through the
 * identity-admin function. When SAML is not enabled for the project yet, the connection
 * stays "requested" and Vlightsoft completes it.
 */
export async function activateSso(tenantId: string): Promise<SsoActivationResult> {
  const { data, error } = await db().functions.invoke<{ active?: boolean; error?: string }>("identity-admin", { body: { action: "activate_sso", tenantId } });
  if (error) {
    const code = await functionErrorCode(error);
    if (code === "saml_not_enabled") return "requested";
    throw new Error(code);
  }
  if (data?.error === "saml_not_enabled") return "requested";
  return data?.active ? "active" : "requested";
}

export async function deactivateSso(tenantId: string) {
  const { error } = await db().functions.invoke("identity-admin", { body: { action: "deactivate_sso", tenantId } });
  if (error) throw new Error(await functionErrorCode(error));
}

export const SSO_ACTIVATION_ERRORS: Record<string, string> = {
  domain_not_verified: "Verify your domain first.",
  metadata_missing: "Add your identity provider's metadata URL first.",
  metadata_invalid: "The metadata URL could not be read as SAML 2.0 metadata. Check that it is public and starts with https://.",
  domain_in_use: "This domain is already connected to another identity provider.",
  idp_in_use: "This identity provider (entity ID) is already connected to another organization.",
  business_plan_required: "Single sign-on needs an active Business plan.",
  activation_failed: "The identity provider could not be connected. Check the metadata URL and try again.",
  saml_not_enabled: "SAML is being enabled for your organization. Vlightsoft will finish the connection and email you.",
};

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
