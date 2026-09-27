import type { SupabaseClient } from "@supabase/supabase-js";
import { fromBase64Url, randomBytes, toBase64Url, toPostgresBytea, unwrapKey, wrapKey } from "@/lib/crypto/vault";
import { supabase } from "@/lib/supabase/client";
import type { WorkspaceVault } from "@/lib/vault/items";

/**
 * Zero-knowledge emergency access.
 *
 * The grantor wraps the workspace key with a random grant secret T and sends T to the
 * grantee in a one-time link fragment. The grantee stores T wrapped under their own
 * account root key. The server keeps the T-wrapped workspace key behind an approval
 * gate and releases it only after approval or the waiting period. Neither Vlightsoft
 * nor the server ever sees T or the workspace key.
 */

export type EmergencyKind = "personal" | "break_glass";
export type EmergencyStatus = "invited" | "active" | "requested" | "approved" | "revoked" | "used";

export type EmergencyGrant = {
  id: string;
  tenant_id: string;
  workspace_id: string;
  kind: EmergencyKind;
  grantor_identity_id: string;
  grantee_identity_id: string | null;
  label: string | null;
  wait_hours: number;
  access_hours: number;
  status: EmergencyStatus;
  invite_expires_at: string;
  key_version: number;
  requested_at: string | null;
  approved_at: string | null;
  used_at: string | null;
  created_at: string;
};

export type EmergencyLink = { id: string; token: Uint8Array };

const encoder = new TextEncoder();

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

function bytea(value: string): Uint8Array {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

async function sha256(value: string | Uint8Array) {
  const input = typeof value === "string" ? encoder.encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(input).buffer));
}

export function emergencyKeyAad(id: string, tenantId: string, workspaceId: string, keyVersion: number) {
  return `1accessos:emergency-key:v1:${id}:${tenantId}:${workspaceId}:${keyVersion}`;
}

export function emergencySecretAad(id: string) {
  return `1accessos:emergency-secret:v1:${id}`;
}

export function parseEmergencyLink(hash: string): EmergencyLink | null {
  const match = hash.match(/^#emergency=([0-9a-f-]{36})\.([A-Za-z0-9_-]+)$/iu);
  if (!match) return null;
  try {
    const token = fromBase64Url(match[2]);
    return token.byteLength === 32 ? { id: match[1], token } : null;
  } catch { return null; }
}

/** When a requested grant opens automatically (grantor has not answered). */
export function releaseTime(grant: Pick<EmergencyGrant, "requested_at" | "wait_hours">) {
  if (!grant.requested_at) return null;
  return new Date(Date.parse(grant.requested_at) + grant.wait_hours * 3_600_000);
}

export function isReleased(grant: EmergencyGrant, now: number) {
  if (grant.status === "approved") return true;
  const release = releaseTime(grant);
  return grant.status === "requested" && release !== null && release.getTime() <= now;
}

export async function listEmergencyGrants(): Promise<EmergencyGrant[]> {
  const { data, error } = await db().from("emergency_access_grants")
    .select("id,tenant_id,workspace_id,kind,grantor_identity_id,grantee_identity_id,label,wait_hours,access_hours,status,invite_expires_at,key_version,requested_at,approved_at,used_at,created_at")
    .order("created_at", { ascending: false })
    .limit(200);
  if (error) throw error;
  return (data ?? []) as EmergencyGrant[];
}

export async function createEmergencyGrant(vault: WorkspaceVault, options: {
  email: string; label: string; kind: EmergencyKind; waitHours: number; accessHours: number; origin: string;
}) {
  const id = crypto.randomUUID();
  const token = randomBytes(32);
  try {
    const aad = emergencyKeyAad(id, vault.tenantId, vault.workspaceId, vault.keyVersion);
    const wrapped = await wrapKey(token, vault.key, aad);
    const { error } = await db().rpc("create_emergency_access", {
      p_id: id,
      p_workspace_id: vault.workspaceId,
      p_kind: options.kind,
      p_recipient_email_hash: toPostgresBytea(await sha256(options.email.trim().toLowerCase())),
      p_label: options.label.trim() || null,
      p_wait_hours: options.waitHours,
      p_access_hours: options.accessHours,
      p_token_hash: toPostgresBytea(await sha256(token)),
      p_key_version: vault.keyVersion,
      p_key_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)),
      p_wrapped_workspace_key: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
      p_key_aad_hash: toPostgresBytea(await sha256(aad)),
    });
    if (error) throw error;
    return `${options.origin.replace(/\/$/u, "")}/#emergency=${id}.${toBase64Url(token)}`;
  } finally {
    token.fill(0);
  }
}

/** Grantee accepts: stores the grant secret wrapped under their own root key. */
export async function acceptEmergencyGrant(link: EmergencyLink, accountRootKey: Uint8Array) {
  const wrapped = await wrapKey(accountRootKey, link.token, emergencySecretAad(link.id));
  const { error } = await db().rpc("accept_emergency_access", {
    p_id: link.id,
    p_token_hash: toPostgresBytea(await sha256(link.token)),
    p_secret_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)),
    p_wrapped_secret: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
  });
  if (error) throw error;
  link.token.fill(0);
}

export async function requestEmergencyAccess(id: string): Promise<string> {
  const { data, error } = await db().rpc("request_emergency_access", { p_id: id });
  if (error) throw error;
  return String(data);
}

export async function decideEmergencyAccess(id: string, approve: boolean) {
  const { error } = await db().rpc("decide_emergency_access", { p_id: id, p_approve: approve });
  if (error) throw error;
}

export async function revokeEmergencyAccess(id: string) {
  const { error } = await db().rpc("revoke_emergency_access", { p_id: id });
  if (error) throw error;
}

type ClaimRow = {
  key_version: number; key_nonce: string; wrapped_workspace_key: string; key_aad_hash: string;
  grantee_secret_nonce: string; grantee_wrapped_secret: string; tenant_id: string; workspace_id: string;
};

/**
 * Opens a released grant: unwraps the grant secret with the account root key, the
 * workspace key with the grant secret, then stores the workspace key wrapped under
 * the root key so the vault appears as a normal (time-limited, read-only) workspace.
 */
export async function openEmergencyVault(id: string, accountRootKey: Uint8Array): Promise<{ workspaceId: string; expiresAt: string }> {
  const client = db();
  const { data, error } = await client.rpc("claim_emergency_access", { p_id: id });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as ClaimRow | undefined;
  if (!row) throw new Error("Emergency access is not available.");
  const aad = emergencyKeyAad(id, row.tenant_id, row.workspace_id, row.key_version);
  if (toBase64Url(await sha256(aad)) !== toBase64Url(bytea(row.key_aad_hash))) throw new Error("Emergency access metadata was changed.");
  let secret: Uint8Array | null = null;
  let workspaceKey: Uint8Array | null = null;
  try {
    secret = await unwrapKey(accountRootKey, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(row.grantee_secret_nonce)),
      ciphertext: toBase64Url(bytea(row.grantee_wrapped_secret)),
    }, emergencySecretAad(id));
    workspaceKey = await unwrapKey(secret, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(row.key_nonce)),
      ciphertext: toBase64Url(bytea(row.wrapped_workspace_key)),
    }, aad);
    const rootEnvelope = await wrapKey(accountRootKey, workspaceKey, "1accessos:workspace:v1");
    const { data: activated, error: activateError } = await client.rpc("activate_emergency_access", {
      p_id: id,
      p_root_key_nonce: toPostgresBytea(fromBase64Url(rootEnvelope.nonce)),
      p_root_wrapped_workspace_key: toPostgresBytea(fromBase64Url(rootEnvelope.ciphertext)),
    });
    if (activateError) throw activateError;
    const result = activated as { workspace_id: string; expires_at: string };
    return { workspaceId: result.workspace_id, expiresAt: result.expires_at };
  } finally {
    secret?.fill(0);
    workspaceKey?.fill(0);
  }
}

export function describeWait(hours: number) {
  if (hours === 0) return "immediately";
  if (hours % 24 === 0) return `${hours / 24} day${hours === 24 ? "" : "s"}`;
  return `${hours} hour${hours === 1 ? "" : "s"}`;
}
