import { createClient } from "npm:@supabase/supabase-js@2.115.0";

const APP_ORIGINS = new Set([
  "https://passkey-x.com",
  "https://www.passkey-x.com",
  "https://passkey-x.netlify.app",
  // Local development origin only when explicitly enabled for this function deployment.
  ...(Deno.env.get("ALLOW_LOCALHOST_ORIGIN") === "true" ? ["http://localhost:3000"] : []),
]);

export function required(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`missing:${name}`);
  return value;
}

function namedKey(sourceName: string, fallbackName: string): string {
  const source = Deno.env.get(sourceName)?.trim();
  if (source) {
    const keys = JSON.parse(source) as Record<string, string>;
    if (keys.default) return keys.default;
  }
  return required(fallbackName);
}

export function corsHeaders(request: Request): HeadersInit {
  const origin = request.headers.get("origin") ?? "";
  return {
    "Access-Control-Allow-Origin": APP_ORIGINS.has(origin) ? origin : "https://passkey-x.com",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Vary": "Origin",
  };
}

export function json(request: Request, status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(request) });
}

export function adminSupabase() {
  return createClient(
    required("SUPABASE_URL"),
    namedKey("SUPABASE_SECRET_KEYS", "SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
}

export function userSupabase(request: Request) {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) throw new Error("unauthorized");
  return createClient(
    required("SUPABASE_URL"),
    namedKey("SUPABASE_PUBLISHABLE_KEYS", "SUPABASE_ANON_KEY"),
    { global: { headers: { Authorization: authorization } }, auth: { persistSession: false } },
  );
}

function tokenAal(token: string): string | null {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/gu, "+").replace(/_/gu, "/"))) as { aal?: unknown };
    return typeof payload.aal === "string" ? payload.aal : null;
  } catch { return null; }
}

export async function requireUser(request: Request) {
  const client = userSupabase(request);
  const token = request.headers.get("authorization")!.slice(7);
  const { data: userData, error: userError } = await client.auth.getUser(token);
  if (userError || !userData.user?.email_confirmed_at) throw new Error("unauthorized");
  // Accounts with two-step verification must present an aal2 session, matching the database policies.
  const hasVerifiedFactor = (userData.user.factors ?? []).some((factor) => factor.status === "verified");
  if (hasVerifiedFactor && tokenAal(token) !== "aal2") throw new Error("mfa_required");
  const { data: identity, error: identityError } = await client.from("identities")
    .select("id,status")
    .eq("auth_user_id", userData.user.id)
    .eq("status", "active")
    .maybeSingle();
  if (identityError || !identity) throw new Error("unauthorized");
  return { client, user: userData.user, identityId: identity.id, token };
}

export async function requireTenantManager(request: Request, tenantId: string) {
  if (!isUuid(tenantId)) throw new Error("invalid_tenant");
  const user = await requireUser(request);
  const { data, error } = await user.client.from("tenant_memberships")
    .select("role,status")
    .eq("tenant_id", tenantId)
    .eq("identity_id", user.identityId)
    .eq("status", "active")
    .in("role", ["owner", "admin"])
    .maybeSingle();
  if (error || !data) throw new Error("forbidden");
  return { ...user, role: data.role };
}

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function toBytea(bytes: Uint8Array): string {
  return `\\x${bytesToHex(bytes)}`;
}

export function fromBytea(value: string): Uint8Array {
  const hex = value.replace(/^\\x/u, "");
  if (!/^[0-9a-f]*$/iu.test(hex) || hex.length % 2 !== 0) throw new Error("credential_corrupt");
  return Uint8Array.from(hex.match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

export async function sha256(value: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function decodeBase64(value: string): Uint8Array {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

async function credentialKey(): Promise<CryptoKey> {
  const material = decodeBase64(required("TENANT_CREDENTIAL_MASTER_KEY"));
  if (material.byteLength !== 32) throw new Error("credential_store_not_configured");
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function credentialAad(tenantId: string, purpose: string): Uint8Array {
  return new TextEncoder().encode(`passkey-x:tenant-credential:v1:${tenantId}:${purpose}`);
}

export async function encryptCredential(tenantId: string, purpose: string, plaintext: string) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: credentialAad(tenantId, purpose), tagLength: 128 },
    await credentialKey(),
    new TextEncoder().encode(plaintext),
  ));
  return { ciphertext, nonce };
}

export async function decryptCredential(tenantId: string, purpose: string, ciphertext: string, nonce: string) {
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBytea(nonce), additionalData: credentialAad(tenantId, purpose), tagLength: 128 },
    await credentialKey(),
    fromBytea(ciphertext),
  ));
  try { return new TextDecoder().decode(plaintext); }
  finally { plaintext.fill(0); }
}

export function publicError(reason: unknown): { code: string; status: number } {
  const message = reason instanceof Error ? reason.message : String(reason ?? "unknown");
  if (message === "unauthorized") return { code: message, status: 401 };
  if (message === "forbidden" || message === "mfa_required") return { code: message, status: 403 };
  if (["invalid_request", "invalid_tenant", "invalid_phone", "invalid_code", "invalid_credential", "invalid_profile"].includes(message)) return { code: message, status: 400 };
  if (["verification_expired", "verification_locked", "ownership_transfer_required", "credential_not_verified", "sms_not_ready", "recent_reauthentication_required"].includes(message)) return { code: message, status: 409 };
  if (message.startsWith("missing:") || message === "credential_store_not_configured") return { code: "service_not_configured", status: 503 };
  return { code: "service_unavailable", status: 503 };
}
