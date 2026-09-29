import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase } from "../_shared/control-plane.ts";
import { breachedAccountUrl, parseBreaches, spacingMs } from "../_shared/hibp.ts";

/**
 * Employee breach watch worker (organizations that turned it on). pg_cron wakes it with a
 * one-time token; it claims a few members who are due for their weekly check and asks Have I Been
 * Pwned which breaches list their work email. Only the email goes to HIBP; only breach metadata
 * (name, title, date, kinds of data) is stored. Needs HIBP_API_KEY; HIBP_RPM sets the plan's
 * requests-per-minute limit (default 10). Called without a Supabase JWT (verify_jwt = false).
 */

type Due = { tenant_id: string; identity_id: string; email: string };

function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function lookup(email: string, apiKey: string): Promise<unknown[]> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await fetch(breachedAccountUrl(email), {
      headers: { "hibp-api-key": apiKey, "user-agent": "Passkey-X-BreachWatch/1.0" },
      signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 404) { await response.body?.cancel(); return []; }
    if (response.status === 429 && attempt === 0) {
      await response.body?.cancel();
      const wait = Math.min(Number(response.headers.get("retry-after") ?? "6") || 6, 20);
      await sleep(wait * 1000);
      continue;
    }
    if (!response.ok) { await response.body?.cancel(); throw new Error(`hibp_${response.status}`); }
    return parseBreaches(await response.json());
  }
  throw new Error("hibp_rate_limited");
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return reply(405, { error: "method_not_allowed" });
  let body: { token?: unknown };
  try { body = await request.json(); } catch { return reply(400, { error: "invalid_request" }); }
  if (typeof body.token !== "string" || !/^[0-9a-f]{64}$/u.test(body.token)) return reply(400, { error: "invalid_request" });
  const apiKey = Deno.env.get("HIBP_API_KEY")?.trim();
  // Without a key nothing is claimed, so no member is marked as checked.
  if (!apiKey) return reply(503, { error: "breach_watch_not_configured" });

  const admin = adminSupabase();
  const rpm = Number(Deno.env.get("HIBP_RPM") ?? "10");
  const spacing = spacingMs(rpm);
  // Stay well inside the edge function time limit.
  const batch = Math.max(1, Math.min(40, Math.floor(100_000 / spacing)));
  const { data, error } = await admin.rpc("claim_breach_watch_batch", { p_token: body.token, p_limit: batch });
  if (error) return reply(403, { error: "invalid_token" });
  const due = (data ?? []) as Due[];
  let checked = 0; let failed = 0; let newBreaches = 0;
  for (const [index, member] of due.entries()) {
    if (index > 0) await sleep(spacing);
    try {
      const breaches = await lookup(member.email, apiKey);
      const { data: added, error: recordError } = await admin.rpc("record_breach_watch_result", {
        p_tenant_id: member.tenant_id, p_identity_id: member.identity_id, p_status: "ok", p_breaches: breaches,
      });
      if (recordError) throw recordError;
      newBreaches += Number(added ?? 0);
      checked += 1;
    } catch {
      failed += 1;
      await admin.rpc("record_breach_watch_result", {
        p_tenant_id: member.tenant_id, p_identity_id: member.identity_id, p_status: "error", p_breaches: [],
      });
    }
  }
  console.log(JSON.stringify({ function: "breach-watch", claimed: due.length, checked, failed, newBreaches }));
  return reply(200, { claimed: due.length, checked, failed, newBreaches });
});
