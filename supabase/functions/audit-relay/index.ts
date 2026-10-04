import "jsr:@supabase/functions-js@2/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.115.0";
import {
  CHAT_FORMATS, SIEM_FORMATS, elasticBulkFailed, hostAllowedForFormat, sentinelTokenRequest, shapeChat, shapeSiem,
  type AuditPayload, type ChatPayload,
} from "../_shared/connector-formats.ts";

/**
 * Audit webhook relay. The database never contacts customer endpoints directly
 * (that would let an admin probe the database host's private network). Instead it
 * queues a one-time delivery and calls this function with {id, token}. The relay
 * claims the delivery with the service role, resolves the destination over DNS,
 * refuses private / loopback / link-local addresses, and forwards the exact signed
 * body. It answers with the destination's status code (or 421 when blocked).
 *
 * Deliveries with a vendor format (Slack, Teams, Splunk HEC, Datadog, Sentinel, Elastic) are
 * shaped here and authenticated with the destination credential, which is never logged.
 */

type Delivery = { url: string; headers: Record<string, string>; body: string; format?: string; config?: Record<string, unknown>; credential?: string | null };

const sentinelTokens = new Map<string, { token: string; expires: number }>();

async function sentinelToken(config: Record<string, unknown>, secret: string) {
  const request = sentinelTokenRequest(config, secret);
  // The cache is keyed by the secret too, so a destination that copies another organization's
  // tenant and client IDs can never reuse that organization's token.
  const secretHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  const cacheKey = `${request.cacheKey}:${secretHash}`;
  const cached = sentinelTokens.get(cacheKey);
  if (cached && cached.expires > Date.now() + 60_000) return cached.token;
  const response = await fetch(request.url, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: request.body,
    signal: AbortSignal.timeout(6_000),
  });
  if (!response.ok) { await response.body?.cancel(); throw new Error("sentinel_auth_failed"); }
  const result = await response.json() as { access_token?: string; expires_in?: number };
  if (!result.access_token) throw new Error("sentinel_auth_failed");
  if (sentinelTokens.size > 200) sentinelTokens.clear();
  sentinelTokens.set(cacheKey, { token: result.access_token, expires: Date.now() + Math.max(60, Number(result.expires_in ?? 3600)) * 1000 });
  return result.access_token;
}

/** Applies the vendor format, returning the headers and body to send. */
async function prepare(delivery: Delivery): Promise<{ headers: Record<string, string>; body: string }> {
  const format = delivery.format ?? "raw";
  if (format === "raw") return { headers: delivery.headers, body: delivery.body };
  const base = { "User-Agent": delivery.headers["User-Agent"] ?? "Passkey-X/1" };
  if (CHAT_FORMATS.has(format)) {
    const shaped = shapeChat(format, JSON.parse(delivery.body) as ChatPayload);
    return { headers: { ...base, ...shaped.headers }, body: shaped.body };
  }
  if (SIEM_FORMATS.has(format)) {
    if (!delivery.credential) throw new Error("missing_credential");
    const config = delivery.config ?? {};
    const credential = format === "sentinel" ? await sentinelToken(config, delivery.credential) : delivery.credential;
    const shaped = shapeSiem(format, config, credential, JSON.parse(delivery.body) as AuditPayload);
    return { headers: { ...base, ...shaped.headers }, body: shaped.body };
  }
  throw new Error("unsupported_format");
}

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function required(name: string) {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`missing:${name}`);
  return value;
}

function serviceKey() {
  const source = Deno.env.get("SUPABASE_SECRET_KEYS")?.trim();
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required("SUPABASE_SERVICE_ROLE_KEY");
}

function ipv4Blocked(address: string) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 192 && b === 0 && parts[2] === 0)
    || (a === 198 && (b === 18 || b === 19));
}

export function addressBlocked(address: string) {
  const value = address.trim().toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/u.test(value)) return ipv4Blocked(value);
  if (!value.includes(":")) return true;
  if (value === "::" || value === "::1") return true;
  const mapped = value.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/u);
  if (mapped) return ipv4Blocked(mapped[1]);
  const first = Number.parseInt(value.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00 // unique local fc00::/7
    || (first & 0xffc0) === 0xfe80 // link local fe80::/10
    || (first & 0xff00) === 0xff00 // multicast
    || value.startsWith("64:ff9b:") // NAT64
    || value.startsWith("2001:db8:");
}

async function resolve(host: string, type: "A" | "AAAA") {
  const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(3_000),
  });
  if (!response.ok) throw new Error("dns_failed");
  const result = await response.json() as { Status: number; Answer?: { type: number; data: string }[] };
  const wanted = type === "A" ? 1 : 28;
  return (result.Answer ?? []).filter((answer) => answer.type === wanted).map((answer) => answer.data);
}

async function destinationAllowed(url: URL) {
  if (url.protocol !== "https:" || url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (!/\.[a-z]{2,}$/u.test(host) || /(^|\.)(localhost|local|internal|lan|home|corp|intranet)$/u.test(host)) return false;
  const [v4, v6] = await Promise.all([resolve(host, "A"), resolve(host, "AAAA")]);
  const addresses = [...v4, ...v6];
  return addresses.length > 0 && addresses.every((address) => !addressBlocked(address));
}

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  let body: { id?: unknown; token?: unknown };
  try { body = await request.json(); } catch { return json(400, { error: "invalid_request" }); }
  if (typeof body.id !== "number" || typeof body.token !== "string" || !/^[a-f0-9]{64}$/u.test(body.token)) {
    return json(400, { error: "invalid_request" });
  }

  const admin = createClient(required("SUPABASE_URL"), serviceKey(), {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await admin.rpc("claim_audit_webhook_delivery", { p_id: body.id, p_token: body.token });
  if (error || !data || !Array.isArray(data) || data.length === 0) return json(404, { error: "unknown_delivery" });
  const delivery = data[0] as Delivery;

  let target: URL;
  try { target = new URL(delivery.url); } catch { return json(421, { error: "destination_not_allowed" }); }
  if (!hostAllowedForFormat(delivery.format ?? "raw", target)) return json(421, { error: "destination_not_allowed" });
  try {
    if (!await destinationAllowed(target)) return json(421, { error: "destination_not_allowed" });
  } catch {
    return json(504, { error: "dns_lookup_failed" });
  }

  let prepared: { headers: Record<string, string>; body: string };
  try { prepared = await prepare(delivery); } catch (reason) {
    const code = reason instanceof Error ? reason.message : "prepare_failed";
    // 401 tells the database that the destination credential needs attention.
    return json(code === "sentinel_auth_failed" ? 401 : 422, { error: code });
  }

  try {
    const upstream = await fetch(target, {
      method: "POST",
      headers: prepared.headers,
      body: prepared.body,
      redirect: "manual",
      signal: AbortSignal.timeout(7_000),
    });
    let status = upstream.status >= 200 && upstream.status <= 599 ? upstream.status : 502;
    if (delivery.format === "elastic" && status >= 200 && status <= 299) {
      if (elasticBulkFailed((await upstream.text()).slice(0, 200_000))) status = 502;
    } else {
      await upstream.body?.cancel();
    }
    if (status === 204 || status === 205 || status === 304) return new Response(null, { status });
    return json(status, { forwarded: true, status: upstream.status });
  } catch {
    return json(504, { error: "destination_unreachable" });
  }
});
