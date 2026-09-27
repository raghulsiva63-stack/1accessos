import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json, publicError, requireTenantManager } from "../_shared/control-plane.ts";

/**
 * Organization identity administration that needs the network:
 *   verify_domain — confirms the SSO domain's DNS TXT record (passkey-x-verification=…).
 * Caller must be an owner or admin of the organization.
 */

type Body = { action?: string; tenantId?: string };

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

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const body = await request.json() as Body;
    if (body.action !== "verify_domain" || !body.tenantId) throw new Error("invalid_request");
    const context = await requireTenantManager(request, body.tenantId);
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
