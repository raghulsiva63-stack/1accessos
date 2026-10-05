import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { corsHeaders, json, publicError, requireUser } from "../_shared/control-plane.ts";

/**
 * Known-malware lookup for downloaded files (verify_jwt = true). The desktop app sends the
 * SHA-256 of programs, installers, disk images and macro documents that arrived in the person's
 * Downloads folder (at most 10 per request) — never the files or their names. Hashes are looked
 * up in abuse.ch MalwareBazaar with the same Auth-Key as URLhaus (URLHAUS_AUTH_KEY). Without a
 * key the function answers with no matches, and the app relies on its other checks.
 */

type Match = { sha256: string; signature: string | null; source: string };
const cache = new Map<string, { match: Match | null; until: number }>();
const HIT_SECONDS = 24 * 3600;
const MISS_SECONDS = 3600;

async function lookup(hash: string, key: string): Promise<Match | null> {
  const cached = cache.get(hash);
  if (cached && cached.until > Date.now()) return cached.match;
  const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ query: "get_info", hash }),
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) { await response.body?.cancel(); throw new Error("lookup_failed"); }
  const body = await response.json() as { query_status?: string; data?: { sha256_hash?: string; signature?: string | null }[] };
  const entry = body.query_status === "ok" ? body.data?.find((item) => item.sha256_hash?.toLowerCase() === hash) : undefined;
  const match = entry ? { sha256: hash, signature: entry.signature ? String(entry.signature).slice(0, 80) : null, source: "MalwareBazaar" } : null;
  if (cache.size > 5000) cache.clear();
  cache.set(hash, { match, until: Date.now() + (match ? HIT_SECONDS : MISS_SECONDS) * 1000 });
  return match;
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    await requireUser(request);
    const body = await request.json().catch(() => null) as { hashes?: unknown } | null;
    const raw = Array.isArray(body?.hashes) ? body!.hashes : [];
    const hashes = [...new Set(raw.filter((value): value is string => typeof value === "string" && /^[0-9a-fA-F]{64}$/u.test(value)).map((value) => value.toLowerCase()))];
    if (!hashes.length || raw.length > 10 || hashes.length !== raw.length) return json(request, 400, { error: "invalid_request" });
    const key = Deno.env.get("URLHAUS_AUTH_KEY")?.trim();
    if (!key) return json(request, 200, { matches: [], checked: false });
    const results = await Promise.allSettled(hashes.map((hash) => lookup(hash, key)));
    const matches = results.flatMap((result) => result.status === "fulfilled" && result.value ? [result.value] : []);
    return json(request, 200, { matches, checked: results.every((result) => result.status === "fulfilled") });
  } catch (reason) {
    const { code, status } = publicError(reason);
    return json(request, status, { error: code });
  }
});
