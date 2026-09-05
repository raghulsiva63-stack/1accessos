import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

const allowedOrigins = new Set([
  "https://1accessos-dev.netlify.app",
  "https://passkey-x.netlify.app",
  "https://passkey-x.com",
  "https://www.passkey-x.com",
]);

const itemTypes = [
  "login", "passkey", "secure-note", "identity", "payment-card",
  "recovery-codes", "wifi", "software-license", "api-key", "ssh-key",
  "database", "certificate", "custom-secret",
];

function headers(request: Request, requestId: string) {
  const origin = request.headers.get("origin") ?? "";
  return {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": requestId,
    "vary": "Origin",
    ...(allowedOrigins.has(origin) ? { "access-control-allow-origin": origin } : {}),
    "access-control-allow-headers": "authorization, apikey, content-type, idempotency-key, if-match",
    "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS",
  };
}

function response(request: Request, requestId: string, status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: headers(request, requestId) });
}

function failure(request: Request, requestId: string, status: number, code: string, message: string) {
  return response(request, requestId, status, { error: { code, message, request_id: requestId } });
}

function pathAfterFunction(url: URL) {
  const marker = "/v1";
  const index = url.pathname.lastIndexOf(marker);
  const value = index >= 0 ? url.pathname.slice(index + marker.length) : url.pathname;
  return value || "/";
}

function hasPlaintextKeys(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(hasPlaintextKeys);
  return Object.entries(value as Record<string, unknown>).some(([key, child]) =>
    [
      "password", "master_password", "plaintext", "private_key", "secret_value",
      "access_token", "refresh_token", "connector_token", "page_content", "form_content",
      "dom_content", "vault_content", "raw_prompt",
    ].includes(key.toLowerCase()) || hasPlaintextKeys(child)
  );
}

Deno.serve(async (request) => {
  const requestId = crypto.randomUUID();
  if (request.method === "OPTIONS") return response(request, requestId, 204);
  const url = new URL(request.url);
  const path = pathAfterFunction(url);
  if (request.method === "GET" && path === "/health") return response(request, requestId, 200, { status: "ok" });
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return failure(request, requestId, 401, "authentication_required", "A valid bearer token is required.");

  const client = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authorization } }, auth: { persistSession: false } },
  );
  const { data: userData, error: userError } = await client.auth.getUser();
  if (userError || !userData.user) return failure(request, requestId, 401, "invalid_token", "The bearer token is invalid or expired.");
  let identityId: string | null = null;
  async function currentIdentityId() {
    if (identityId) return identityId;
    const { data, error } = await client.from("identities").select("id").eq("auth_user_id", userData.user.id).single();
    if (error || !data) throw error ?? new Error("identity unavailable");
    identityId = data.id;
    return identityId;
  }

  try {
    if (request.method === "GET" && path === "/item-types") {
      return response(request, requestId, 200, { items: itemTypes.map((id) => ({ id, schema_version: 1 })) });
    }
    if (request.method === "GET" && path === "/connectors/catalog") {
      const { data, error } = await client.from("connector_catalog")
        .select("connector_key,display_name,category,auth_scheme,capabilities,minimum_scopes,adapter_stage,quality_label,certification_version,documentation_url")
        .eq("published", true).eq("phase5_target", true).order("category").order("display_name");
      if (error) throw error;
      return response(request, requestId, 200, { connectors: data ?? [] });
    }
    if (request.method === "GET" && path === "/connectors") {
      const tenantId = url.searchParams.get("tenant_id");
      if (!tenantId) return failure(request, requestId, 422, "tenant_required", "tenant_id is required.");
      const { data, error } = await client.from("tenant_connectors")
        .select("id,tenant_id,connector_key,display_name,status,granted_scopes,token_expires_at,token_rotation_state,last_health_at,last_sync_at,next_sync_at,discovered_records")
        .eq("tenant_id", tenantId).order("display_name");
      if (error) throw error;
      return response(request, requestId, 200, { connectors: data ?? [] });
    }
    if (request.method === "GET" && path === "/saas/dashboard") {
      const tenantId = url.searchParams.get("tenant_id");
      if (!tenantId) return failure(request, requestId, 422, "tenant_required", "tenant_id is required.");
      const { data, error } = await client.rpc("phase5_saas_dashboard", { p_tenant_id: tenantId });
      if (error) throw error;
      if (!data) return failure(request, requestId, 403, "tenant_forbidden", "The tenant context is not available.");
      return response(request, requestId, 200, data);
    }
    if (request.method === "GET" && path === "/saas/applications") {
      const tenantId = url.searchParams.get("tenant_id");
      if (!tenantId) return failure(request, requestId, 422, "tenant_required", "tenant_id is required.");
      const { data, error } = await client.from("saas_applications")
        .select("id,tenant_id,connector_id,app_key,display_name,category,sanctioned_state,data_risk,owner_identity_id,discovery_source,confidence,first_seen_at,last_seen_at")
        .eq("tenant_id", tenantId).order("last_seen_at", { ascending: false }).limit(500);
      if (error) throw error;
      return response(request, requestId, 200, { applications: data ?? [] });
    }
    if (request.method === "GET" && path === "/saas/recommendations") {
      const tenantId = url.searchParams.get("tenant_id");
      if (!tenantId) return failure(request, requestId, 422, "tenant_required", "tenant_id is required.");
      const { data, error } = await client.from("saas_recommendations")
        .select("id,tenant_id,application_id,kind,severity,title,explanation,estimated_savings_minor,currency,evidence,destructive_action,action_state,generated_at,reviewed_at")
        .eq("tenant_id", tenantId).order("generated_at", { ascending: false }).limit(500);
      if (error) throw error;
      return response(request, requestId, 200, { recommendations: data ?? [] });
    }
    if (request.method === "POST" && path === "/saas/recommendations/refresh") {
      const body = await request.json();
      if (hasPlaintextKeys(body)) return failure(request, requestId, 422, "plaintext_rejected", "Only approved non-secret metadata is accepted.");
      if (!body?.tenant_id) return failure(request, requestId, 422, "tenant_required", "tenant_id is required.");
      const { data, error } = await client.rpc("refresh_saas_recommendations", { p_tenant_id: body.tenant_id });
      if (error) throw error;
      return response(request, requestId, 200, { generated: data });
    }
    const connectorReconcileMatch = path.match(/^\/connectors\/([0-9a-f-]{36})\/reconcile$/iu);
    if (connectorReconcileMatch && request.method === "POST") {
      const { data: connector, error: connectorError } = await client.from("tenant_connectors")
        .select("id,connector_key,status,connector_catalog!inner(adapter_stage,quality_label)")
        .eq("id", connectorReconcileMatch[1]).single();
      if (connectorError) throw connectorError;
      const catalog = Array.isArray(connector.connector_catalog) ? connector.connector_catalog[0] : connector.connector_catalog;
      if (!catalog || catalog.adapter_stage !== "production" || catalog.quality_label !== "production_verified") {
        return failure(request, requestId, 409, "connector_not_certified", "This connector cannot reconcile until its adapter is production-certified.");
      }
      return failure(request, requestId, 503, "connector_runtime_unavailable", "The certified connector runtime is not configured in this environment.");
    }
    if (request.method === "GET" && path === "/workspaces") {
      const currentIdentity = await currentIdentityId();
      const { data: memberships, error: membershipError } = await client.from("workspace_memberships")
        .select("tenant_id,workspace_id,role,status")
        .eq("identity_id", currentIdentity)
        .eq("status", "active");
      if (membershipError) throw membershipError;
      if (!memberships?.length) return response(request, requestId, 200, { workspaces: [] });
      const { data, error } = await client.from("workspaces")
        .select("id,tenant_id,kind,suite,status,current_key_version,key_rotation_required,encrypted_name,name_nonce,name_aad_hash,created_at,updated_at")
        .in("id", memberships.map((membership) => membership.workspace_id))
        .eq("status", "active")
        .order("created_at");
      if (error) throw error;
      const roles = new Map(memberships.map((membership) => [membership.workspace_id, membership.role]));
      return response(request, requestId, 200, { workspaces: (data ?? []).map((workspace) => ({ ...workspace, caller_role: roles.get(workspace.id) })) });
    }
    const membersMatch = path.match(/^\/workspaces\/([0-9a-f-]{36})\/members$/iu);
    if (membersMatch && request.method === "GET") {
      const { data, error } = await client.from("workspace_memberships")
        .select("identity_id,tenant_id,workspace_id,role,status,created_at,updated_at")
        .eq("workspace_id", membersMatch[1])
        .order("created_at");
      if (error) throw error;
      return response(request, requestId, 200, { members: data ?? [] });
    }
    if (request.method === "GET" && path === "/missions") {
      const workspaceId = url.searchParams.get("workspace_id");
      if (!workspaceId) return failure(request, requestId, 422, "workspace_required", "workspace_id is required.");
      const { data, error } = await client.from("missions")
        .select("id,tenant_id,workspace_id,created_by,definition_nonce,encrypted_definition,definition_aad_hash,status,created_at,updated_at,mission_items(item_id,sort_order)")
        .eq("workspace_id", workspaceId)
        .eq("status", "active")
        .order("updated_at", { ascending: false });
      if (error) throw error;
      return response(request, requestId, 200, { missions: data ?? [] });
    }
    if (request.method === "GET" && path === "/access-requests") {
      const workspaceId = url.searchParams.get("workspace_id");
      if (!workspaceId) return failure(request, requestId, 422, "workspace_required", "workspace_id is required.");
      const { data, error } = await client.from("access_requests")
        .select("id,tenant_id,workspace_id,item_id,requester_identity_id,requested_scope,purpose_nonce,encrypted_purpose,purpose_aad_hash,requested_duration_minutes,status,expires_at,decided_at,created_at,updated_at")
        .eq("workspace_id", workspaceId)
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) throw error;
      return response(request, requestId, 200, { requests: data ?? [] });
    }
    if (request.method === "POST" && path === "/access-requests") {
      const body = await request.json();
      if (hasPlaintextKeys(body)) return failure(request, requestId, 422, "plaintext_rejected", "Only ciphertext envelopes are accepted.");
      const required = ["id", "tenant_id", "workspace_id", "requested_scope", "purpose_nonce", "encrypted_purpose", "purpose_aad_hash", "requested_duration_minutes", "expires_at"];
      if (required.some((key) => !(key in body))) return failure(request, requestId, 422, "invalid_envelope", "The encrypted access request is incomplete.");
      const currentIdentity = await currentIdentityId();
      const { data, error } = await client.from("access_requests").insert({
        id: body.id,
        tenant_id: body.tenant_id,
        workspace_id: body.workspace_id,
        item_id: body.item_id ?? null,
        requester_identity_id: currentIdentity,
        requested_scope: body.requested_scope,
        purpose_nonce: body.purpose_nonce,
        encrypted_purpose: body.encrypted_purpose,
        purpose_aad_hash: body.purpose_aad_hash,
        requested_duration_minutes: body.requested_duration_minutes,
        status: "pending",
        expires_at: body.expires_at,
      }).select("id,status,created_at").single();
      if (error) throw error;
      return response(request, requestId, 201, data);
    }
    const decisionMatch = path.match(/^\/access-requests\/([0-9a-f-]{36})\/decision$/iu);
    if (decisionMatch && request.method === "POST") {
      const body = await request.json();
      if (!body || !["approved", "denied"].includes(body.decision)) return failure(request, requestId, 422, "invalid_decision", "decision must be approved or denied.");
      const { data, error } = await client.rpc("decide_access_request", { p_request_id: decisionMatch[1], p_decision: body.decision });
      if (error) throw error;
      return response(request, requestId, 200, { approval_id: data, decision: body.decision });
    }
    if (request.method === "GET" && path === "/access-grants") {
      const workspaceId = url.searchParams.get("workspace_id");
      if (!workspaceId) return failure(request, requestId, 422, "workspace_required", "workspace_id is required.");
      const { data, error } = await client.from("access_grants")
        .select("id,tenant_id,workspace_id,item_id,subject_identity_id,scope,source_request_id,starts_at,expires_at,status,created_by,created_at,revoked_at")
        .eq("workspace_id", workspaceId)
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) throw error;
      return response(request, requestId, 200, { grants: data ?? [] });
    }
    if (request.method === "GET" && path === "/vault-items") {
      const workspaceId = url.searchParams.get("workspace_id");
      if (!workspaceId) return failure(request, requestId, 422, "workspace_required", "workspace_id is required.");
      const { data, error } = await client.from("vault_items").select("id,tenant_id,workspace_id,content_type,schema_version,head_revision,created_at,updated_at,deleted_at,vault_item_revisions(revision,envelope_version,algorithm,key_version,nonce,ciphertext,aad_hash,created_at)").eq("workspace_id", workspaceId).order("updated_at", { ascending: false }).limit(200);
      if (error) throw error;
      return response(request, requestId, 200, { items: data, next_cursor: null });
    }
    if (request.method === "GET" && path === "/sync/changes") {
      const workspaceId = url.searchParams.get("workspace_id");
      const cursor = Number(url.searchParams.get("cursor") ?? "0");
      if (!workspaceId || !Number.isSafeInteger(cursor) || cursor < 0) return failure(request, requestId, 422, "invalid_cursor", "A valid workspace_id and cursor are required.");
      const { data, error } = await client.from("sync_changes").select("sequence,entity_type,entity_id,operation,entity_version,occurred_at").eq("workspace_id", workspaceId).gt("sequence", cursor).order("sequence").limit(500);
      if (error) throw error;
      return response(request, requestId, 200, { changes: data, cursor: String(data?.at(-1)?.sequence ?? cursor) });
    }
    if (request.method === "POST" && path === "/vault-items") {
      const body = await request.json();
      if (hasPlaintextKeys(body)) return failure(request, requestId, 422, "plaintext_rejected", "Only ciphertext envelopes are accepted.");
      const required = ["id", "tenant_id", "workspace_id", "content_type", "schema_version", "nonce", "ciphertext", "aad_hash"];
      if (required.some((key) => !(key in body))) return failure(request, requestId, 422, "invalid_envelope", "The encrypted item envelope is incomplete.");
      const { data, error } = await client.rpc("create_vault_item", { p_item_id: body.id, p_tenant_id: body.tenant_id, p_workspace_id: body.workspace_id, p_content_type: body.content_type, p_schema_version: body.schema_version, p_nonce: body.nonce, p_ciphertext: body.ciphertext, p_aad_hash: body.aad_hash });
      if (error) throw error;
      return response(request, requestId, 201, { id: body.id, head_revision: data });
    }
    const itemMatch = path.match(/^\/vault-items\/([0-9a-f-]{36})$/iu);
    if (itemMatch && request.method === "PATCH") {
      const expected = Number((request.headers.get("if-match") ?? "").replaceAll('"', ""));
      const body = await request.json();
      if (!Number.isSafeInteger(expected) || expected < 1 || hasPlaintextKeys(body)) return failure(request, requestId, 422, "invalid_revision", "If-Match and a ciphertext envelope are required.");
      const { data, error } = await client.rpc("update_vault_item", { p_item_id: itemMatch[1], p_expected_revision: expected, p_nonce: body.nonce, p_ciphertext: body.ciphertext, p_aad_hash: body.aad_hash });
      if (error) throw error;
      return response(request, requestId, 200, { id: itemMatch[1], head_revision: data });
    }
    if (itemMatch && request.method === "DELETE") {
      const expected = Number((request.headers.get("if-match") ?? "").replaceAll('"', ""));
      if (!Number.isSafeInteger(expected) || expected < 1) return failure(request, requestId, 422, "invalid_revision", "If-Match is required.");
      const { error } = await client.rpc("delete_vault_item", { p_item_id: itemMatch[1], p_expected_revision: expected });
      if (error) throw error;
      return response(request, requestId, 204);
    }
    return failure(request, requestId, 404, "not_found", "The requested API operation does not exist.");
  } catch (error) {
    const code = typeof error === "object" && error && "code" in error ? String(error.code) : "request_failed";
    const status = code === "40001" ? 409 : code === "42501" ? 403 : 400;
    return failure(request, requestId, status, code, code === "40001" ? "The item changed; refresh and retry." : "The encrypted request could not be completed.");
  }
});
