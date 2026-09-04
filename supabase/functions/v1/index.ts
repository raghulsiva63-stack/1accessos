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
    ["password", "master_password", "plaintext", "private_key", "secret_value"].includes(key.toLowerCase()) || hasPlaintextKeys(child)
  );
}

Deno.serve(async (request) => {
  const requestId = crypto.randomUUID();
  if (request.method === "OPTIONS") return response(request, requestId, 204);
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return failure(request, requestId, 401, "authentication_required", "A valid bearer token is required.");

  const client = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authorization } }, auth: { persistSession: false } },
  );
  const { data: userData, error: userError } = await client.auth.getUser();
  if (userError || !userData.user) return failure(request, requestId, 401, "invalid_token", "The bearer token is invalid or expired.");

  const url = new URL(request.url);
  const path = pathAfterFunction(url);

  try {
    if (request.method === "GET" && path === "/item-types") {
      return response(request, requestId, 200, { items: itemTypes.map((id) => ({ id, schema_version: 1 })) });
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
    const status = code === "40001" ? 409 : 400;
    return failure(request, requestId, status, code, code === "40001" ? "The item changed; refresh and retry." : "The encrypted request could not be completed.");
  }
});
