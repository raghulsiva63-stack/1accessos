import type { Config } from "@netlify/functions";
import { normalizePasskeyDirectory, normalizeTwoFactorDirectory, type SiteDirectory } from "../../lib/security/site-directory";

/**
 * Public list of websites that support two-step verification and passkeys (from 2fa.directory).
 * Everyone downloads the same cached file and matches it on their own device, so Passkey-X never
 * learns which websites a person uses. No authentication, no cookies, no personal data.
 */

const TFA_URL = Netlify.env.get("TFA_DIRECTORY_URL")?.trim() || "https://api.2fa.directory/v3/tfa.json";
const PASSKEY_URL = Netlify.env.get("PASSKEY_DIRECTORY_URL")?.trim() || "https://passkeys-api.2fa.directory/v1/all.json";

async function fetchJson(url: string): Promise<unknown | null> {
  try {
    const response = await fetch(url, { headers: { Accept: "application/json", "User-Agent": "Passkey-X-SiteDirectory/1.0" }, signal: AbortSignal.timeout(8_000) });
    if (!response.ok) return null;
    const text = await response.text();
    if (text.length > 20_000_000) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Max-Age": "86400" };

export default async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (request.method !== "GET") return Response.json({ error: "method_not_allowed" }, { status: 405, headers: CORS });
  const [tfa, passkeys] = await Promise.all([fetchJson(TFA_URL), fetchJson(PASSKEY_URL)]);
  if (!tfa && !passkeys) {
    return Response.json({ error: "directory_unavailable" }, { status: 503, headers: { ...CORS, "Cache-Control": "no-store" } });
  }
  const sites: SiteDirectory["sites"] = {};
  if (tfa) normalizeTwoFactorDirectory(tfa, sites);
  if (passkeys) normalizePasskeyDirectory(passkeys, sites);
  const body: SiteDirectory = { generatedAt: new Date().toISOString(), sites };
  return Response.json(body, {
    headers: {
      ...CORS,
      "Cache-Control": "public, max-age=3600",
      "Netlify-CDN-Cache-Control": "public, durable, max-age=86400, stale-while-revalidate=604800",
      "X-Content-Type-Options": "nosniff",
    },
  });
};

export const config: Config = {
  path: "/api/security/site-directory",
  method: ["GET", "OPTIONS"],
  rateLimit: { action: "rate_limit", aggregateBy: ["domain", "ip"], windowSize: 60, windowLimit: 30 },
};
