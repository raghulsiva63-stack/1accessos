import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { adminSupabase } from "../_shared/control-plane.ts";
import { canonicalExpression, encodePrefixSet, fromBase64, prefixOf, PrefixSet, sha256Bytes, toBase64 } from "../_shared/url-hash.ts";

/**
 * Threat list sync (pg_cron wakes it every 6 hours with a one-time token; verify_jwt = false).
 *
 * Sources, each used only when its credentials are configured:
 * * Google Web Risk (WEB_RISK_API_KEY): the hash-prefix lists for social engineering, malware and
 *   unwanted software, downloaded with threatLists.computeDiff (free). Full hashes are confirmed
 *   later by threat-check, only for prefixes that matched on a device.
 * * URLhaus (URLHAUS_AUTH_KEY): malware download addresses. Commercial use needs a Spamhaus
 *   subscription; set the key only once that is in place.
 * * A licensed feed of plain-text URLs (THREAT_FEED_URL, optional THREAT_FEED_HEADER "Name: value",
 *   THREAT_FEED_THREAT phishing|malware|unwanted), for example OpenPhish premium.
 *
 * Feed addresses are hashed here exactly like devices hash pages (url-hash.ts). The prefixes of
 * every list that applies to everyone are published as one file (threat-intel/prefixes.bin);
 * Web Risk prefixes are also kept in webrisk-prefixes.bin so threat-check knows when to ask Google.
 */

type Json = Record<string, unknown>;

function reply(status: number, body: Json) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

const WEB_RISK_TYPES = ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"] as const;
const MAX_FEED_ENTRIES = 200_000;

async function webRiskPrefixes(key: string): Promise<{ prefixes: number[]; versions: Record<string, string> }> {
  const prefixes: number[] = [];
  const versions: Record<string, string> = {};
  for (const type of WEB_RISK_TYPES) {
    const url = new URL("https://webrisk.googleapis.com/v1/threatLists:computeDiff");
    url.searchParams.set("threatType", type);
    url.searchParams.append("constraints.supportedCompressions", "RAW");
    url.searchParams.set("key", key);
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`webrisk_${response.status}`); }
    const body = await response.json() as { additions?: { rawHashes?: { prefixSize?: number; rawHashes?: string }[] }; newVersionToken?: string };
    for (const group of body.additions?.rawHashes ?? []) {
      const size = Number(group.prefixSize ?? 4);
      if (!group.rawHashes || size < 4 || size > 32) continue;
      const bytes = fromBase64(group.rawHashes);
      for (let offset = 0; offset + size <= bytes.length; offset += size) prefixes.push(prefixOf(bytes.subarray(offset, offset + 4)));
    }
    versions[type] = body.newVersionToken ?? "";
  }
  return { prefixes, versions };
}

async function textFeed(url: string, headers: HeadersInit): Promise<string[]> {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) { await response.body?.cancel(); throw new Error(`feed_${response.status}`); }
  return (await response.text()).split(/\r?\n/u).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")).slice(0, MAX_FEED_ENTRIES);
}

async function hashFeed(lines: string[]): Promise<{ hashes: string[]; expressions: string[] }> {
  const hashes: string[] = []; const expressions: string[] = []; const seen = new Set<string>();
  for (const line of lines) {
    const canonical = canonicalExpression(line);
    if (!canonical) continue;
    const expression = `${canonical.host}${canonical.path}${canonical.query}`;
    if (seen.has(expression) || expression.length > 600) continue;
    seen.add(expression);
    hashes.push(toBase64(await sha256Bytes(expression)));
    expressions.push(expression);
  }
  return { hashes, expressions };
}

async function replaceFeed(admin: ReturnType<typeof adminSupabase>, source: string, threat: string, lines: string[]) {
  const { hashes, expressions } = await hashFeed(lines);
  const { data, error } = await admin.rpc("replace_threat_feed", { p_source: source, p_threat: threat, p_hashes: hashes, p_expressions: expressions });
  if (error) throw new Error(`store_${source}`);
  return Number(data ?? 0);
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return reply(405, { error: "method_not_allowed" });
  let body: { token?: unknown };
  try { body = await request.json(); } catch { return reply(400, { error: "invalid_request" }); }
  if (typeof body.token !== "string" || !/^[0-9a-f]{64}$/u.test(body.token)) return reply(400, { error: "invalid_request" });
  const admin = adminSupabase();
  const { data: claimed, error: claimError } = await admin.rpc("claim_threat_sync", { p_token: body.token });
  if (claimError || !claimed) return reply(403, { error: "invalid_token" });

  const report: Json = {};
  const sources: string[] = ["organization", "community"];
  let webRisk: number[] = [];
  const webRiskKey = Deno.env.get("WEB_RISK_API_KEY")?.trim();
  if (webRiskKey) {
    try {
      const result = await webRiskPrefixes(webRiskKey);
      webRisk = result.prefixes;
      report.webRisk = webRisk.length;
      sources.push("webrisk");
    } catch (reason) {
      report.webRiskError = String((reason as Error).message ?? reason);
      // Keep publishing the last good Web Risk list rather than dropping it.
      const previous = await admin.storage.from("threat-intel").download("webrisk-prefixes.bin");
      if (previous.data) {
        try { webRisk = PrefixSet.decode(new Uint8Array(await previous.data.arrayBuffer())).toArray(); sources.push("webrisk"); } catch { /* unreadable: skip */ }
      }
    }
  }
  const urlhausKey = Deno.env.get("URLHAUS_AUTH_KEY")?.trim();
  if (urlhausKey) {
    try {
      const lines = await textFeed("https://urlhaus.abuse.ch/downloads/text_online/", { "Auth-Key": urlhausKey });
      report.urlhaus = await replaceFeed(admin, "urlhaus", "malware", lines);
      sources.push("urlhaus");
    } catch (reason) { report.urlhausError = String((reason as Error).message ?? reason); }
  }
  const feedUrl = Deno.env.get("THREAT_FEED_URL")?.trim();
  if (feedUrl?.startsWith("https://")) {
    try {
      const header = Deno.env.get("THREAT_FEED_HEADER")?.split(":");
      const headers: Record<string, string> = header && header.length >= 2 ? { [header[0].trim()]: header.slice(1).join(":").trim() } : {};
      const threat = ["phishing", "malware", "unwanted"].includes(Deno.env.get("THREAT_FEED_THREAT") ?? "") ? Deno.env.get("THREAT_FEED_THREAT")! : "phishing";
      report.feed = await replaceFeed(admin, "feed", threat, await textFeed(feedUrl, headers));
      sources.push("feed");
    } catch (reason) { report.feedError = String((reason as Error).message ?? reason); }
  }

  // Publish: everything that applies to everyone, plus the Web Risk prefixes on their own.
  const { data: globalPrefixes, error: prefixError } = await admin.rpc("global_threat_prefixes");
  if (prefixError) return reply(500, { error: "prefixes_unavailable" });
  const version = Math.floor(Date.now() / 1000);
  const own = ((globalPrefixes ?? []) as string[]).map((value) => prefixOf(fromBase64(value)));
  const combined = encodePrefixSet([...webRisk, ...own], version);
  const storage = admin.storage.from("threat-intel");
  const upload = await storage.upload("prefixes.bin", combined, { contentType: "application/octet-stream", upsert: true });
  if (upload.error) return reply(500, { error: "upload_failed" });
  if (webRiskKey && webRisk.length) {
    const webRiskUpload = await storage.upload("webrisk-prefixes.bin", encodePrefixSet(webRisk, version), { contentType: "application/octet-stream", upsert: true });
    if (webRiskUpload.error) return reply(500, { error: "upload_failed" });
  }
  await admin.rpc("set_threat_intel_state", { p_key: "prefix_set", p_value: { version, count: new Set([...webRisk, ...own]).size, sources, webRisk: webRisk.length > 0, at: new Date().toISOString() } });
  return reply(200, { ok: true, version, ...report });
});
