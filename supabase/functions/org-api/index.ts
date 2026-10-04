import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase } from "../_shared/control-plane.ts";

/**
 * Passkey-X organization API (server-to-server).
 * Base URL: https://<project>.supabase.co/functions/v1/org-api/v1
 * Auth:     Authorization: Bearer pxk_…  (Admin console → Integrations → API keys)
 *
 * Read-only views of organization security metadata, plus alert status updates. Vault
 * contents are end-to-end encrypted and are never available through this API.
 *
 *   GET   /v1/me                         key, organization and scopes
 *   GET   /v1/audit-events?after=&limit= audit:read   (cursor = last "sequence" you received)
 *   GET   /v1/alerts?status=&limit=      alerts:read
 *   PATCH /v1/alerts/{id}                alerts:write {"status":"acknowledged"|"resolved"|"open","note":"…"}
 *   GET   /v1/members?offset=&limit=     members:read
 *   GET   /v1/security/summary           reports:read
 *   GET   /v1/reports/weekly?limit=      reports:read
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function reply(status: number, body: unknown, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra },
  });
}

function problem(status: number, code: string, message: string, extra: Record<string, string> = {}) {
  return reply(status, { error: { code, message } }, extra);
}

function integer(value: string | null, fallback: number, min: number, max: number) {
  if (value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new Error("invalid_parameter");
  return parsed;
}

type Key = { key_id: string; tenant_id: string; scopes: string[]; rate_limited: boolean };

Deno.serve(async (request: Request) => {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^.*?\/org-api(?=\/|$)/u, "").replace(/\/+$/u, "") || "/";
  if (request.method === "OPTIONS") return new Response(null, { status: 405 });

  const token = (request.headers.get("authorization") ?? "").match(/^Bearer\s+(pxk_[0-9a-f]{64})$/u)?.[1];
  if (!token) return problem(401, "unauthorized", "Send an organization API key: Authorization: Bearer pxk_…", { "WWW-Authenticate": "Bearer" });

  const admin = adminSupabase();
  const { data: keys, error: authError } = await admin.rpc("authenticate_org_api_key", { p_token: token });
  if (authError) return problem(503, "unavailable", "The API is temporarily unavailable.");
  const key = (Array.isArray(keys) ? keys[0] : keys) as Key | undefined;
  if (!key?.key_id) return problem(401, "unauthorized", "The API key is invalid, expired or revoked.", { "WWW-Authenticate": "Bearer" });
  if (key.rate_limited) return problem(429, "rate_limited", "Too many requests. The limit is 300 per minute per key.", { "Retry-After": "60" });
  const scoped = (scope: string) => key.scopes.includes(scope);

  try {
    if (request.method === "GET" && path === "/v1/me") {
      return reply(200, { key_id: key.key_id, organization_id: key.tenant_id, scopes: key.scopes });
    }
    if (request.method === "GET" && path === "/v1/audit-events") {
      if (!scoped("audit:read")) return problem(403, "forbidden", "This key needs the audit:read scope.");
      const after = integer(url.searchParams.get("after"), 0, 0, Number.MAX_SAFE_INTEGER);
      const limit = integer(url.searchParams.get("limit"), 100, 1, 500);
      const { data, error } = await admin.rpc("api_audit_events", { p_key_id: key.key_id, p_after: after, p_limit: limit });
      if (error) throw error;
      const events = (data ?? []) as { sequence: number }[];
      return reply(200, { data: events, next_after: events.length ? events[events.length - 1].sequence : after, has_more: events.length === limit });
    }
    if (request.method === "GET" && path === "/v1/alerts") {
      if (!scoped("alerts:read")) return problem(403, "forbidden", "This key needs the alerts:read scope.");
      const status = url.searchParams.get("status");
      if (status && !["open", "acknowledged", "resolved"].includes(status)) return problem(400, "invalid_parameter", "status must be open, acknowledged or resolved.");
      const { data, error } = await admin.rpc("api_alerts", { p_key_id: key.key_id, p_status: status, p_limit: integer(url.searchParams.get("limit"), 50, 1, 200) });
      if (error) throw error;
      return reply(200, { data: data ?? [] });
    }
    const alertMatch = path.match(/^\/v1\/alerts\/([^/]+)$/u);
    if (alertMatch && request.method === "PATCH") {
      if (!scoped("alerts:write")) return problem(403, "forbidden", "This key needs the alerts:write scope.");
      if (!UUID.test(alertMatch[1])) return problem(404, "not_found", "Alert not found.");
      let body: { status?: unknown; note?: unknown };
      try { body = await request.json(); } catch { return problem(400, "invalid_body", "Send a JSON body."); }
      if (typeof body.status !== "string" || !["open", "acknowledged", "resolved"].includes(body.status)) {
        return problem(400, "invalid_parameter", "status must be open, acknowledged or resolved.");
      }
      const note = typeof body.note === "string" ? body.note.slice(0, 500) : null;
      const { data, error } = await admin.rpc("api_update_alert", { p_key_id: key.key_id, p_alert_id: alertMatch[1], p_status: body.status, p_note: note });
      if (error) throw error;
      return reply(200, { data });
    }
    if (request.method === "GET" && path === "/v1/members") {
      if (!scoped("members:read")) return problem(403, "forbidden", "This key needs the members:read scope.");
      const { data, error } = await admin.rpc("api_members", {
        p_key_id: key.key_id, p_offset: integer(url.searchParams.get("offset"), 0, 0, 1_000_000), p_limit: integer(url.searchParams.get("limit"), 100, 1, 500),
      });
      if (error) throw error;
      return reply(200, { data: data ?? [] });
    }
    if (request.method === "GET" && path === "/v1/security/summary") {
      if (!scoped("reports:read")) return problem(403, "forbidden", "This key needs the reports:read scope.");
      const { data, error } = await admin.rpc("api_security_summary", { p_key_id: key.key_id });
      if (error) throw error;
      return reply(200, { data });
    }
    if (request.method === "GET" && path === "/v1/reports/weekly") {
      if (!scoped("reports:read")) return problem(403, "forbidden", "This key needs the reports:read scope.");
      const { data, error } = await admin.rpc("api_weekly_reports", { p_key_id: key.key_id, p_limit: integer(url.searchParams.get("limit"), 4, 1, 52) });
      if (error) throw error;
      return reply(200, { data: data ?? [] });
    }
    return problem(404, "not_found", "Unknown endpoint. See https://passkey-x.com/api-docs#organization-api");
  } catch (reason) {
    const message = reason instanceof Error ? reason.message : "";
    const code = String((reason as { code?: string })?.code ?? "");
    if (message === "invalid_parameter") return problem(400, "invalid_parameter", "A query parameter is out of range.");
    if (code === "P0002") return problem(404, "not_found", "Not found.");
    if (code === "42501") return problem(403, "forbidden", "This key is not allowed to do that.");
    if (code === "22023") return problem(400, "invalid_parameter", "Invalid value.");
    console.error(JSON.stringify({ function: "org-api", code: code || "error" }));
    return problem(500, "internal_error", "The request could not be completed.");
  }
});
