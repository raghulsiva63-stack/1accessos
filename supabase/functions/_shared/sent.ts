import { createClient } from "npm:@supabase/supabase-js@2.115.0";

export function required(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`missing:${name}`);
  return value;
}

export function optional(name: string): string | null {
  return Deno.env.get(name)?.trim() || null;
}

function namedKey(sourceName: string, fallbackName: string): string {
  const source = optional(sourceName);
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required(fallbackName);
}

export function adminSupabase() {
  return createClient(
    required("SUPABASE_URL"),
    namedKey("SUPABASE_SECRET_KEYS", "SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
}

export function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Text(value: string): Promise<string> {
  return bytesToHex(await sha256(new TextEncoder().encode(value)));
}

function decodeBase64(value: string): Uint8Array {
  const decoded = atob(value);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left, 0);
  result.set(right, left.length);
  return result;
}

async function sentSignature(secret: string, webhookId: string, timestamp: string, rawBody: Uint8Array): Promise<Uint8Array> {
  const material = secret.replace(/^whsec_/u, "");
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64(material),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const prefix = new TextEncoder().encode(`${webhookId}.${timestamp}.`);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, concat(prefix, rawBody)));
}

export async function verifySentWebhook(headers: Headers, rawBody: Uint8Array): Promise<void> {
  const webhookId = headers.get("x-webhook-id")?.trim();
  const timestamp = headers.get("x-webhook-timestamp")?.trim();
  const signature = headers.get("x-webhook-signature")?.trim();
  if (!webhookId || !timestamp || !signature?.startsWith("v1,")) throw new Error("invalid_signature");

  const seconds = Number(timestamp);
  if (!Number.isInteger(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > 300) throw new Error("stale_signature");

  let delivered: Uint8Array;
  try { delivered = decodeBase64(signature.slice(3)); }
  catch { throw new Error("invalid_signature"); }

  const secrets = [optional("SENT_DM_WEBHOOK_SECRET"), optional("SENT_DM_WEBHOOK_SECRET_PREVIOUS")].filter(Boolean) as string[];
  if (!secrets.length) throw new Error("webhook_not_configured");
  for (const secret of secrets) {
    try {
      if (constantTimeEqual(await sentSignature(secret, webhookId, timestamp, rawBody), delivered)) return;
    } catch { /* try the rotation candidate */ }
  }
  throw new Error("invalid_signature");
}

export function safeCode(reason: unknown): string {
  const message = reason instanceof Error ? reason.message : String(reason ?? "unknown");
  if (/^(invalid_signature|stale_signature|invalid_payload|method_not_allowed|webhook_not_configured|sms_not_configured|sms_sandbox_only)$/u.test(message)) return message;
  if (message.startsWith("missing:")) return "sms_not_configured";
  return "provider_unavailable";
}
