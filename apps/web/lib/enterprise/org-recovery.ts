import type { SupabaseClient } from "@supabase/supabase-js";
import {
  deriveMasterKey, fromBase64Url, randomBytes, toBase64Url, toPostgresBytea, unwrapKey, WEB_KDF_PROFILE, wrapKey,
} from "@/lib/crypto/vault";
import { supabase } from "@/lib/supabase/client";

/**
 * Opt-in organization recovery (zero-knowledge escrow).
 *
 * An administrator generates a P-256 key pair in the browser. Only the public key is
 * stored; the private key is downloaded as an offline "recovery kit". When the
 * organization enables recovery, each member's app encrypts their account root key to
 * the organization public key (ECDH + HKDF-SHA-256 + AES-256-GCM). To recover, an
 * admin loads the kit in their browser, decrypts the member's root key and re-encrypts
 * it under a one-time code that is handed to the member out of band. The server never
 * holds the private key, the root key or the code.
 */

export const RECOVERY_KIT_FORMAT = "passkey-x-org-recovery-kit";
export const RELEASE_CODE_PREFIX = "PX-ORC1-";

export type RecoveryKit = {
  format: typeof RECOVERY_KIT_FORMAT;
  version: 1;
  tenant_id: string;
  key_id: string;
  fingerprint: string;
  private_key_pkcs8: string;
  created_at: string;
};

export type RecoveryEnvelope = { ephemeralPublicKey: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array };

export type RecoveryQueueEntry = {
  request_id: string; identity_id: string; display_name: string; email: string | null; created_at: string;
  key_id: string; ephemeral_public_key: string; nonce: string; ciphertext: string;
};

const encoder = new TextEncoder();

function buffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

function bytea(value: string): Uint8Array {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

export function recoveryContext(tenantId: string, identityId: string) {
  return `1accessos:org-recovery:v1:${tenantId}:${identityId}`;
}

export function releaseContext(requestId: string) {
  return `1accessos:org-recovery-release:v1:${requestId}`;
}

export async function fingerprint(publicKey: Uint8Array) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(publicKey)));
  return Array.from(digest.slice(0, 12), (byte) => byte.toString(16).padStart(2, "0")).join("").match(/.{4}/gu)!.join(":");
}

async function deriveAesKey(shared: ArrayBuffer, keyId: string, context: string) {
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buffer(encoder.encode(keyId)), info: buffer(encoder.encode(context)) },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

export async function generateRecoveryKit(tenantId: string) {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const keyId = crypto.randomUUID();
  const kit: RecoveryKit = {
    format: RECOVERY_KIT_FORMAT, version: 1, tenant_id: tenantId, key_id: keyId,
    fingerprint: await fingerprint(publicKey), private_key_pkcs8: toBase64Url(pkcs8), created_at: new Date().toISOString(),
  };
  pkcs8.fill(0);
  return { kit, publicKey };
}

export function parseRecoveryKit(text: string, tenantId: string): RecoveryKit {
  let parsed: Partial<RecoveryKit>;
  try { parsed = JSON.parse(text) as Partial<RecoveryKit>; } catch { throw new Error("That file is not a Passkey-X recovery kit."); }
  if (parsed.format !== RECOVERY_KIT_FORMAT || parsed.version !== 1 || !parsed.key_id || !parsed.private_key_pkcs8) {
    throw new Error("That file is not a Passkey-X recovery kit.");
  }
  if (parsed.tenant_id !== tenantId) throw new Error("This recovery kit belongs to a different organization.");
  return parsed as RecoveryKit;
}

/** Member side: encrypts the account root key to the organization's public key. */
export async function sealRootForOrganization(rootKey: Uint8Array, publicKey: Uint8Array, keyId: string, tenantId: string, identityId: string): Promise<RecoveryEnvelope> {
  const recipient = await crypto.subtle.importKey("raw", buffer(publicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const context = recoveryContext(tenantId, identityId);
  const key = await deriveAesKey(shared, keyId, context);
  const nonce = randomBytes(12);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(context)) }, key, buffer(rootKey)));
  return { ephemeralPublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey)), nonce, ciphertext };
}

/** Admin side: opens a member's envelope with the offline kit. */
export async function openRootWithKit(kit: RecoveryKit, envelope: RecoveryEnvelope, tenantId: string, identityId: string) {
  const pkcs8 = fromBase64Url(kit.private_key_pkcs8);
  try {
    const privateKey = await crypto.subtle.importKey("pkcs8", buffer(pkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const ephemeral = await crypto.subtle.importKey("raw", buffer(envelope.ephemeralPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeral }, privateKey, 256);
    const context = recoveryContext(tenantId, identityId);
    const key = await deriveAesKey(shared, kit.key_id, context);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(envelope.nonce), additionalData: buffer(encoder.encode(context)) }, key, buffer(envelope.ciphertext)));
  } finally { pkcs8.fill(0); }
}

export function formatReleaseCode(code: Uint8Array) {
  return `${RELEASE_CODE_PREFIX}${toBase64Url(code)}`;
}

export function parseReleaseCode(text: string) {
  const trimmed = text.trim().replace(/\s+/gu, "");
  if (!trimmed.startsWith(RELEASE_CODE_PREFIX)) throw new Error("Enter the recovery code your administrator gave you (it starts with PX-ORC1-).");
  const code = fromBase64Url(trimmed.slice(RELEASE_CODE_PREFIX.length));
  if (code.byteLength !== 32) throw new Error("That recovery code is incomplete.");
  return code;
}

async function sha256(value: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(value)));
}

// ---------------------------------------------------------------------------
// Server calls
// ---------------------------------------------------------------------------
export type OrganizationRecoveryKey = { tenant_id: string; key_id: string; public_key: string; fingerprint: string; created_at: string };

export async function loadRecoveryKey(tenantId: string): Promise<OrganizationRecoveryKey | null> {
  const { data, error } = await db().from("organization_recovery_keys").select("tenant_id,key_id,public_key,fingerprint,created_at").eq("tenant_id", tenantId).maybeSingle();
  if (error) throw error;
  return data as OrganizationRecoveryKey | null;
}

export async function publishRecoveryKey(tenantId: string, kit: RecoveryKit, publicKey: Uint8Array) {
  const { error } = await db().rpc("set_organization_recovery_key", {
    p_tenant_id: tenantId, p_key_id: kit.key_id, p_public_key: toPostgresBytea(publicKey), p_fingerprint: kit.fingerprint,
  });
  if (error) throw error;
}

export async function myEnrollment(tenantId: string, identityId: string) {
  const { data, error } = await db().from("organization_recovery_enrollments").select("key_id,created_at")
    .eq("tenant_id", tenantId).eq("identity_id", identityId).maybeSingle();
  if (error) throw error;
  return data as { key_id: string; created_at: string } | null;
}

export async function listMyEnrollments(identityId: string) {
  const { data, error } = await db().from("organization_recovery_enrollments").select("tenant_id,key_id,created_at").eq("identity_id", identityId);
  if (error) throw error;
  return (data ?? []) as { tenant_id: string; key_id: string; created_at: string }[];
}

export async function enrollInOrganizationRecovery(rootKey: Uint8Array, recoveryKey: OrganizationRecoveryKey, identityId: string) {
  const envelope = await sealRootForOrganization(rootKey, bytea(recoveryKey.public_key), recoveryKey.key_id, recoveryKey.tenant_id, identityId);
  const { error } = await db().rpc("enroll_organization_recovery", {
    p_tenant_id: recoveryKey.tenant_id, p_key_id: recoveryKey.key_id,
    p_ephemeral_public_key: toPostgresBytea(envelope.ephemeralPublicKey),
    p_nonce: toPostgresBytea(envelope.nonce), p_ciphertext: toPostgresBytea(envelope.ciphertext),
  });
  if (error) throw error;
}

export async function requestOrganizationRecovery(tenantId: string): Promise<string> {
  const { data, error } = await db().rpc("request_organization_recovery", { p_tenant_id: tenantId });
  if (error) throw error;
  return String(data);
}

export async function loadMyRecoveryRequest(tenantId: string, identityId: string) {
  const { data, error } = await db().from("organization_recovery_requests")
    .select("id,status,release_nonce,release_ciphertext,expires_at,created_at")
    .eq("tenant_id", tenantId).eq("identity_id", identityId).in("status", ["pending", "approved"])
    .order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw error;
  return data as { id: string; status: "pending" | "approved"; release_nonce: string | null; release_ciphertext: string | null; expires_at: string } | null;
}

export async function loadRecoveryQueue(tenantId: string): Promise<RecoveryQueueEntry[]> {
  const { data, error } = await db().rpc("organization_recovery_queue", { p_tenant_id: tenantId });
  if (error) throw error;
  return (data ?? []) as RecoveryQueueEntry[];
}

/** Admin approves: decrypts with the kit and returns the one-time code to hand over. */
export async function approveRecovery(kit: RecoveryKit, entry: RecoveryQueueEntry, tenantId: string): Promise<string> {
  if (entry.key_id !== kit.key_id) throw new Error("This member enrolled with a different recovery key. Load the matching kit.");
  let root: Uint8Array | null = null;
  const code = randomBytes(32);
  try {
    root = await openRootWithKit(kit, {
      ephemeralPublicKey: bytea(entry.ephemeral_public_key), nonce: bytea(entry.nonce), ciphertext: bytea(entry.ciphertext),
    }, tenantId, entry.identity_id);
    const release = await wrapKey(code, root, releaseContext(entry.request_id));
    const { error } = await db().rpc("decide_organization_recovery", {
      p_request_id: entry.request_id, p_approve: true,
      p_release_nonce: toPostgresBytea(fromBase64Url(release.nonce)),
      p_release_ciphertext: toPostgresBytea(fromBase64Url(release.ciphertext)),
      p_release_code_hash: toPostgresBytea(await sha256(code)),
    });
    if (error) throw error;
    return formatReleaseCode(code);
  } finally {
    root?.fill(0);
    code.fill(0);
  }
}

export async function denyRecovery(requestId: string) {
  const { error } = await db().rpc("decide_organization_recovery", { p_request_id: requestId, p_approve: false });
  if (error) throw error;
}

/** Member finishes: opens the release with the code and sets a new vault password. */
export async function completeRecovery(request: { id: string; release_nonce: string; release_ciphertext: string }, codeText: string, newPassword: string) {
  const code = parseReleaseCode(codeText);
  let root: Uint8Array | null = null;
  let master: Uint8Array | null = null;
  try {
    try {
      root = await unwrapKey(code, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(request.release_nonce)), ciphertext: toBase64Url(bytea(request.release_ciphertext)) }, releaseContext(request.id));
    } catch { throw new Error("That recovery code does not match this request."); }
    const salt = randomBytes(16);
    master = await deriveMasterKey(newPassword, salt);
    const wrapped = await wrapKey(master, root, "1accessos:account-root:v1");
    const { error } = await db().rpc("complete_organization_recovery", {
      p_request_id: request.id, p_code_hash: toPostgresBytea(await sha256(code)),
      p_salt: toPostgresBytea(salt), p_kdf_parameters: WEB_KDF_PROFILE,
      p_master_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)), p_master_wrapped_root: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
    });
    if (error) throw error;
    return { salt: toBase64Url(salt), kdf_parameters: WEB_KDF_PROFILE, master_nonce: wrapped.nonce, master_wrapped_root: wrapped.ciphertext };
  } finally {
    code.fill(0);
    root?.fill(0);
    master?.fill(0);
  }
}
