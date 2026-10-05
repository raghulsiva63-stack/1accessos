import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase, corsHeaders, json, publicError, requireUser } from "../_shared/control-plane.ts";
import { fromBase64, PrefixSet } from "../_shared/url-hash.ts";

/**
 * Confirms hash-prefix matches (verify_jwt = true). A device sends only 4-byte prefixes that
 * matched its local list, never the address. The answer is the full hashes for those prefixes;
 * the device compares them itself.
 *
 * Google Web Risk full hashes (hashes.search) are fetched only for prefixes on the Web Risk list,
 * cached until Google's expiry, and capped per day by WEB_RISK_DAILY_LIMIT (default 300) because
 * each call is billed.
 */

const WEB_RISK_THREATS: Record<string, string> = { SOCIAL_ENGINEERING: "phishing", MALWARE: "malware", UNWANTED_SOFTWARE: "unwanted" };
type Match = { hash: string; threat: string; source: string };

let webRiskSet: { set: PrefixSet; loadedAt: number } | null = null;

async function loadWebRiskSet(admin: ReturnType<typeof adminSupabase>): Promise<PrefixSet | null> {
  if (webRiskSet && Date.now() - webRiskSet.loadedAt < 10 * 60_000) return webRiskSet.set;
  const file = await admin.storage.from("threat-intel").download("webrisk-prefixes.bin");
  if (!file.data) return null;
  try {
    webRiskSet = { set: PrefixSet.decode(new Uint8Array(await file.data.arrayBuffer())), loadedAt: Date.now() };
    return webRiskSet.set;
  } catch { return null; }
}

async function underDailyLimit(admin: ReturnType<typeof adminSupabase>, calls: number): Promise<boolean> {
  const limit = Number(Deno.env.get("WEB_RISK_DAILY_LIMIT") ?? "300");
  const key = `webrisk_calls:${new Date().toISOString().slice(0, 10)}`;
  const { data } = await admin.rpc("get_threat_intel_state", { p_key: key });
  const used = Number((data as { count?: number } | null)?.count ?? 0);
  if (used + calls > limit) return false;
  await admin.rpc("set_threat_intel_state", { p_key: key, p_value: { count: used + calls } });
  return true;
}

async function webRiskMatches(admin: ReturnType<typeof adminSupabase>, prefixes: string[], key: string): Promise<Match[]> {
  const set = await loadWebRiskSet(admin);
  if (!set) return [];
  const listed = prefixes.filter((prefix) => {
    const bytes = fromBase64(prefix);
    return set.has(((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0);
  });
  if (!listed.length) return [];
  const matches: Match[] = [];
  const { data: cached } = await admin.rpc("webrisk_cached", { p_prefixes: listed });
  const fresh = new Set(((cached ?? []) as { prefix: string; matches: Match[] }[]).map((row) => { matches.push(...row.matches); return row.prefix; }));
  const missing = listed.filter((prefix) => !fresh.has(prefix));
  if (!missing.length || !(await underDailyLimit(admin, missing.length))) return matches;
  for (const prefix of missing) {
    const url = new URL("https://webrisk.googleapis.com/v1/hashes:search");
    url.searchParams.set("hashPrefix", prefix);
    for (const type of Object.keys(WEB_RISK_THREATS)) url.searchParams.append("threatTypes", type);
    url.searchParams.set("key", key);
    const response = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    if (!response.ok) { await response.body?.cancel(); continue; }
    const body = await response.json() as { threats?: { threatTypes?: string[]; hash?: string; expireTime?: string }[]; negativeExpireTime?: string };
    const found: Match[] = [];
    let seconds = 1800;
    for (const threat of body.threats ?? []) {
      const kind = (threat.threatTypes ?? []).map((type) => WEB_RISK_THREATS[type]).find(Boolean);
      if (threat.hash && kind) found.push({ hash: threat.hash, threat: kind, source: "Google Web Risk" });
      if (threat.expireTime) seconds = Math.min(seconds, Math.max(60, (Date.parse(threat.expireTime) - Date.now()) / 1000));
    }
    if (!found.length && body.negativeExpireTime) seconds = Math.max(60, (Date.parse(body.negativeExpireTime) - Date.now()) / 1000);
    await admin.rpc("webrisk_store", { p_prefix: prefix, p_matches: found, p_seconds: Math.round(seconds) });
    matches.push(...found);
  }
  return matches;
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, 405, { error: "method_not_allowed" });
  try {
    const user = await requireUser(request);
    const body = await request.json().catch(() => null) as { prefixes?: unknown } | null;
    const prefixes = Array.isArray(body?.prefixes) ? body!.prefixes.filter((value): value is string => typeof value === "string" && /^[A-Za-z0-9+/]{5}[AQgw]==$/u.test(value)) : [];
    if (!prefixes.length || prefixes.length > 32 || prefixes.length !== (body!.prefixes as unknown[]).length) return json(request, 400, { error: "invalid_request" });
    const { data, error } = await user.client.rpc("threat_matches", { p_prefixes: prefixes });
    if (error) throw error;
    const matches = [...((data ?? []) as Match[])];
    const key = Deno.env.get("WEB_RISK_API_KEY")?.trim();
    if (key) {
      try { matches.push(...await webRiskMatches(adminSupabase(), prefixes, key)); } catch { /* lists still answer */ }
    }
    return json(request, 200, { matches, cacheSeconds: 1800 });
  } catch (reason) {
    const { code, status } = publicError(reason);
    return json(request, status, { error: code });
  }
});
