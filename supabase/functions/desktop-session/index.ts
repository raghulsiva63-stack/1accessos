import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json } from "../_shared/control-plane.ts";

/**
 * Finishes a desktop sign-in that the person approved in their browser.
 *
 * The desktop app sends the one-time code (from the browser) together with the PKCE
 * verifier that never left the app. The database checks both once (a wrong verifier
 * burns the code). On success this returns a single-use sign-in token; the app exchanges
 * it with Supabase Auth for its own session. That session starts at the first
 * assurance level, so accounts with two-step verification must still complete it in
 * the app before any vault data is readable.
 *
 * Deployed with verify_jwt = false: the app has no session yet. The anon key is still
 * required by the gateway, and the code + verifier are the credential.
 */

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const VERIFIER = /^[A-Za-z0-9_-]{43,128}$/u;

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const body = await request.json().catch(() => null) as { code?: unknown; verifier?: unknown } | null;
    const code = typeof body?.code === "string" ? body.code.trim() : "";
    const verifier = typeof body?.verifier === "string" ? body.verifier : "";
    if (!TOKEN.test(code) || !VERIFIER.test(verifier)) return json(request, 400, { error: "invalid_request" });

    const admin = adminSupabase();
    const { data: userId, error } = await admin.rpc("redeem_desktop_handoff", { p_code: code, p_verifier: verifier });
    if (error) throw error;
    // Same answer for unknown, used, expired and mismatched codes.
    if (!userId) return json(request, 400, { error: "invalid_or_expired_code" });

    const { data: user, error: userError } = await admin.auth.admin.getUserById(userId as string);
    if (userError || !user.user?.email || !user.user.email_confirmed_at) return json(request, 400, { error: "invalid_or_expired_code" });
    const banned = user.user.banned_until && new Date(user.user.banned_until).getTime() > Date.now();
    if (banned) return json(request, 403, { error: "account_unavailable" });

    // generateLink does not send an email; the hashed token is exchanged by the app immediately.
    const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: "magiclink", email: user.user.email });
    if (linkError || !link.properties?.hashed_token) throw linkError ?? new Error("link_unavailable");
    console.log(JSON.stringify({ function: "desktop-session", code: "desktop_signed_in", user: userId }));
    return json(request, 200, { tokenHash: link.properties.hashed_token, email: user.user.email });
  } catch (reason) {
    console.error(JSON.stringify({ function: "desktop-session", code: "failed", detail: reason instanceof Error ? reason.message.slice(0, 80) : "unknown" }));
    return json(request, 500, { error: "desktop_sign_in_unavailable" });
  }
});
