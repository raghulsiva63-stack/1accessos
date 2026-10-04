import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json, publicError, required, requireTenantManager } from "../_shared/control-plane.ts";

/**
 * Organization identity administration that needs the network or the Auth admin API:
 *   verify_domain  — confirms the SSO domain's DNS TXT record (passkey-x-verification=…).
 *   activate_sso   — registers (or updates) the organization's SAML identity provider in Supabase
 *                    Auth, so SSO works without waiting for Vlightsoft. Needs a verified domain,
 *                    a metadata URL and the Business plan. If SAML is not enabled for the project,
 *                    the connection stays "requested" and Vlightsoft finishes it.
 *   deactivate_sso — removes the provider; members sign in with their password again.
 * Caller must be an owner or admin of the organization (two-step verification enforced).
 */

type Body = { action?: string; tenantId?: string };

const EMAIL_ATTRIBUTES = [
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  "urn:oid:0.9.2342.19200300.100.1.3", "email", "Email", "mail", "emailAddress",
];
const NAME_ATTRIBUTES = [
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "http://schemas.microsoft.com/identity/claims/displayname",
  "displayName", "name", "cn",
];

async function txtRecords(name: string): Promise<string[]> {
  const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(4_000),
  });
  if (!response.ok) throw new Error("dns_unavailable");
  const result = await response.json() as { Answer?: { type: number; data: string }[] };
  return (result.Answer ?? []).filter((answer) => answer.type === 16)
    .map((answer) => answer.data.replace(/^"|"$/gu, "").replace(/"\s+"/gu, ""));
}

function serviceKey() {
  const source = Deno.env.get("SUPABASE_SECRET_KEYS")?.trim();
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required("SUPABASE_SERVICE_ROLE_KEY");
}

async function authAdmin(path: string, method: string, body?: unknown) {
  const key = serviceKey();
  return fetch(`${required("SUPABASE_URL")}/auth/v1/admin/sso/providers${path}`, {
    method,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
}

async function activate(tenantId: string) {
  const admin = adminSupabase();
  const { data: connection, error } = await admin.from("sso_connections")
    .select("domain,domain_verified_at,metadata_url,provider_id,status").eq("tenant_id", tenantId).maybeSingle();
  if (error || !connection) return { status: 400, body: { error: "not_configured" } };
  if (!connection.domain_verified_at) return { status: 409, body: { error: "domain_not_verified" } };
  if (!connection.metadata_url) return { status: 409, body: { error: "metadata_missing" } };
  const { data: allowed, error: allowedError } = await admin.rpc("sso_activation_allowed", { p_tenant_id: tenantId });
  if (allowedError) throw allowedError;
  if (allowed !== true) return { status: 403, body: { error: "business_plan_required" } };

  const payload = {
    metadata_url: connection.metadata_url,
    domains: [connection.domain],
    attribute_mapping: { keys: { email: { names: EMAIL_ATTRIBUTES }, name: { names: NAME_ATTRIBUTES } } },
  };
  const existing = typeof connection.provider_id === "string" && /^[0-9a-f-]{36}$/iu.test(connection.provider_id) ? connection.provider_id : null;
  const response = existing
    ? await authAdmin(`/${existing}`, "PUT", payload)
    : await authAdmin("", "POST", { type: "saml", resource_id: `px-${tenantId}`, ...payload });
  const text = await response.text();
  if (response.ok) {
    const provider = JSON.parse(text) as { id?: string };
    const id = provider.id ?? existing;
    if (!id) return { status: 502, body: { error: "activation_failed" } };
    const { error: saveError } = await admin.rpc("set_sso_provider", { p_tenant_id: tenantId, p_provider_id: id, p_error: null });
    if (saveError) throw saveError;
    return { status: 200, body: { active: true } };
  }
  // Map Auth errors to actionable codes without echoing provider responses.
  const lower = text.toLowerCase();
  const code = response.status === 404 && lower.includes("saml") ? "saml_not_enabled"
    : lower.includes("already") && lower.includes("domain") ? "domain_in_use"
    : lower.includes("entity") && lower.includes("already") ? "idp_in_use"
    : lower.includes("metadata") ? "metadata_invalid"
    : "activation_failed";
  await admin.rpc("set_sso_provider", { p_tenant_id: tenantId, p_provider_id: null, p_error: code });
  return { status: code === "saml_not_enabled" ? 202 : 422, body: { error: code } };
}

async function deactivate(tenantId: string) {
  const admin = adminSupabase();
  const { data: connection } = await admin.from("sso_connections").select("provider_id").eq("tenant_id", tenantId).maybeSingle();
  const id = connection?.provider_id;
  if (typeof id === "string" && /^[0-9a-f-]{36}$/iu.test(id)) {
    const response = await authAdmin(`/${id}`, "DELETE");
    await response.body?.cancel();
    if (!response.ok && response.status !== 404) return { status: 502, body: { error: "deactivation_failed" } };
  }
  const { error } = await admin.rpc("clear_sso_provider", { p_tenant_id: tenantId });
  if (error) throw error;
  return { status: 200, body: { active: false } };
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const body = await request.json() as Body;
    if (!body.tenantId || !["verify_domain", "activate_sso", "deactivate_sso"].includes(body.action ?? "")) throw new Error("invalid_request");
    const context = await requireTenantManager(request, body.tenantId);

    if (body.action === "activate_sso") { const result = await activate(body.tenantId); return json(request, result.status, result.body); }
    if (body.action === "deactivate_sso") { const result = await deactivate(body.tenantId); return json(request, result.status, result.body); }

    const { data: connection, error } = await context.client.from("sso_connections")
      .select("domain,verification_token,domain_verified_at").eq("tenant_id", body.tenantId).maybeSingle();
    if (error || !connection) throw new Error("invalid_request");
    if (connection.domain_verified_at) return json(request, 200, { verified: true });
    const names = [connection.domain, `_passkey-x.${connection.domain}`];
    const records = (await Promise.all(names.map((name) => txtRecords(name).catch(() => [] as string[])))).flat();
    if (!records.includes(connection.verification_token)) return json(request, 200, { verified: false });
    const { error: markError } = await adminSupabase().rpc("mark_sso_domain_verified", { p_tenant_id: body.tenantId, p_domain: connection.domain });
    if (markError) throw markError;
    return json(request, 200, { verified: true });
  } catch (reason) {
    const error = publicError(reason);
    console.error(JSON.stringify({ function: "identity-admin", code: error.code }));
    return json(request, error.status, { error: error.code });
  }
});
