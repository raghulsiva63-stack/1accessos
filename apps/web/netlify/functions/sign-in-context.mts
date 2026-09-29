import type { Config, Context } from "@netlify/functions";
import { createClient } from "@supabase/supabase-js";

/**
 * Adds the sign-in country to the current session's sign-in record, so a sign-in from a new
 * country can raise an alert. Netlify knows the visitor's country (context.geo); the database
 * trusts it only with an HMAC signed by the shared GEO_ATTESTATION_KEY, bound to the caller's
 * own session id. No IP address or location beyond the two-letter country code is stored.
 */

const ALLOWED_ORIGINS = new Set(["https://passkey-x.com", "https://www.passkey-x.com", "https://passkey-x.netlify.app"]);
const DESKTOP_ORIGINS = new Set(["tauri://localhost", "http://tauri.localhost"]);

function sessionIdOf(token: string): string | null {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/gu, "+").replace(/_/gu, "/"))) as { session_id?: unknown };
    return typeof payload.session_id === "string" && /^[0-9a-f-]{36}$/u.test(payload.session_id) ? payload.session_id : null;
  } catch {
    return null;
  }
}

async function hmacHex(key: string, message: string) {
  const imported = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(message)));
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export default async (request: Request, context: Context) => {
  const origin = request.headers.get("origin");
  const desktop = Boolean(origin && DESKTOP_ORIGINS.has(origin));
  const cors: Record<string, string> = desktop ? { "Access-Control-Allow-Origin": origin!, "Vary": "Origin" } : {};
  if (desktop && request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { ...cors, "Access-Control-Allow-Methods": "POST", "Access-Control-Allow-Headers": "authorization, content-type", "Access-Control-Max-Age": "86400" } });
  }
  const done = (status: number) => new Response(null, { status, headers: { ...cors, "Cache-Control": "no-store" } });
  if (request.method !== "POST") return done(405);
  if (origin && !desktop && !ALLOWED_ORIGINS.has(origin)) return done(403);
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return done(401);
  const key = Netlify.env.get("GEO_ATTESTATION_KEY")?.trim();
  const country = context.geo?.country?.code?.toUpperCase();
  const sessionId = sessionIdOf(authorization.slice(7));
  if (!key || !country || !/^[A-Z]{2}$/u.test(country) || !sessionId) return done(204);
  const issuedAt = Math.floor(Date.now() / 1000);
  const signature = await hmacHex(key, `${sessionId}.${country}.${issuedAt}`);
  const supabaseUrl = Netlify.env.get("SUPABASE_URL")?.trim() || Netlify.env.get("NEXT_PUBLIC_SUPABASE_URL")?.trim();
  const publishableKey = Netlify.env.get("SUPABASE_PUBLISHABLE_KEY")?.trim() || Netlify.env.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")?.trim();
  if (!supabaseUrl || !publishableKey) return done(204);
  const client = createClient(supabaseUrl, publishableKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  // The database checks the signature against the session id in the verified token.
  await client.rpc("attest_sign_in_country", { p_country: country, p_issued_at: issuedAt, p_signature: signature });
  return done(204);
};

export const config: Config = {
  path: "/api/security/sign-in-context",
  method: ["POST", "OPTIONS"],
  rateLimit: { action: "rate_limit", aggregateBy: ["domain", "ip"], windowSize: 60, windowLimit: 10 },
};
