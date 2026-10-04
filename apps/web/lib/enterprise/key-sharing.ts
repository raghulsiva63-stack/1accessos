import type { SupabaseClient } from "@supabase/supabase-js";
import { fromBase64Url, toBase64Url, toPostgresBytea, unwrapKey, wrapKey } from "@/lib/crypto/vault";
import { supabase } from "@/lib/supabase/client";
import type { WorkspaceVault } from "@/lib/vault/items";

/**
 * Direct workspace sharing inside an organization, without invitation links.
 *
 * Every member has a P-256 "sharing key". The public half is published; the private half is
 * stored encrypted under the member's account root key, so only their unlocked devices can
 * use it. To give someone a workspace, a key holder's device encrypts the 32-byte workspace
 * key to the recipient's public key (ephemeral ECDH + HKDF-SHA-256 + AES-256-GCM) bound to the
 * organization, workspace, recipient and key version. The recipient's device opens it and
 * re-wraps the key under their own root key. The server only stores public keys and ciphertext.
 *
 * Trust note: like other end-to-end encrypted products with server-held public keys, a fully
 * compromised server could try to substitute a public key. Fingerprints are shown in the admin
 * console so a security-sensitive organization can compare them out of band.
 */

const encoder = new TextEncoder();
const PRIVATE_KEY_CONTEXT = (identityId: string) => `1accessos:sharing-key:v1:${identityId}`;

export function grantContext(tenantId: string, workspaceId: string, recipientIdentityId: string, keyVersion: number) {
  return `1accessos:workspace-grant:v1:${tenantId}:${workspaceId}:${recipientIdentityId}:${keyVersion}`;
}

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

function buffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

export function bytea(value: string): Uint8Array {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

export async function sharingFingerprint(publicKey: Uint8Array) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(publicKey)));
  return Array.from(digest.slice(0, 12), (byte) => byte.toString(16).padStart(2, "0")).join("").match(/.{4}/gu)!.join(":");
}

async function aesKey(shared: ArrayBuffer, context: string) {
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buffer(encoder.encode("1accessos:workspace-grant-salt:v1")), info: buffer(encoder.encode(context)) },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

export type SealedKey = { ephemeralPublicKey: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array };

/** Encrypts a workspace key to a recipient's P-256 public key. */
export async function sealToPublicKey(workspaceKey: Uint8Array, recipientPublicKey: Uint8Array, context: string): Promise<SealedKey> {
  if (workspaceKey.length !== 32) throw new Error("Workspace keys are 32 bytes.");
  if (recipientPublicKey.length !== 65 || recipientPublicKey[0] !== 4) throw new Error("The member's sharing key is invalid.");
  const recipient = await crypto.subtle.importKey("raw", buffer(recipientPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const key = await aesKey(shared, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(context)), tagLength: 128 }, key, buffer(workspaceKey)));
  return { ephemeralPublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey)), nonce, ciphertext };
}

/** Opens a sealed workspace key with the recipient's private sharing key (PKCS#8). */
export async function openSealedKey(privateKeyPkcs8: Uint8Array, sealed: SealedKey, context: string) {
  const privateKey = await crypto.subtle.importKey("pkcs8", buffer(privateKeyPkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const ephemeral = await crypto.subtle.importKey("raw", buffer(sealed.ephemeralPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeral }, privateKey, 256);
  const key = await aesKey(shared, context);
  try {
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(sealed.nonce), additionalData: buffer(encoder.encode(context)), tagLength: 128 }, key, buffer(sealed.ciphertext)));
    if (plaintext.length !== 32) throw new Error("bad length");
    return plaintext;
  } catch {
    throw new Error("This shared workspace key could not be opened. Ask an administrator to share it again.");
  }
}

export type SharingKeyPair = { publicKey: Uint8Array; privateKeyPkcs8: Uint8Array; fingerprint: string };

export async function generateSharingKeyPair(): Promise<SharingKeyPair> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return { publicKey, privateKeyPkcs8, fingerprint: await sharingFingerprint(publicKey) };
}

/** Loads this member's private sharing key, creating and publishing a key pair the first time. */
export async function ensureSharingKey(identityId: string, rootKey: Uint8Array): Promise<SharingKeyPair> {
  const client = db();
  const [{ data: published, error: publicError }, { data: secret, error: secretError }] = await Promise.all([
    client.from("identity_sharing_keys").select("public_key,fingerprint").eq("identity_id", identityId).maybeSingle(),
    client.from("identity_sharing_key_secrets").select("nonce,wrapped_private_key").eq("identity_id", identityId).maybeSingle(),
  ]);
  if (publicError || secretError) throw publicError ?? secretError;
  if (published && secret) {
    try {
      const privateKeyPkcs8 = await unwrapKey(rootKey, {
        algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(secret.nonce)), ciphertext: toBase64Url(bytea(secret.wrapped_private_key)),
      }, PRIVATE_KEY_CONTEXT(identityId));
      const publicKey = bytea(published.public_key);
      const fingerprint = await sharingFingerprint(publicKey);
      if (fingerprint !== published.fingerprint) throw new Error("fingerprint mismatch");
      return { publicKey, privateKeyPkcs8, fingerprint };
    } catch {
      // Damaged or foreign key material: replace it. Grants sealed to the old key are re-requested.
    }
  }
  const pair = await generateSharingKeyPair();
  const wrapped = await wrapKey(rootKey, pair.privateKeyPkcs8, PRIVATE_KEY_CONTEXT(identityId));
  const { error } = await client.rpc("publish_sharing_key", {
    p_public_key: toPostgresBytea(pair.publicKey), p_fingerprint: pair.fingerprint,
    p_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)), p_wrapped_private_key: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
    p_replace: Boolean(published),
  });
  if (error) throw error;
  return pair;
}

type SealedGrantRow = {
  id: string; tenant_id: string; workspace_id: string; key_version: number;
  ephemeral_public_key: string; nonce: string; ciphertext: string;
};

/** Opens grants addressed to this member and stores the keys under their root key. Returns the workspace ids received. */
export async function acceptIncomingGrants(identityId: string, rootKey: Uint8Array, pair: SharingKeyPair): Promise<string[]> {
  const client = db();
  const { data, error } = await client.from("workspace_key_grants")
    .select("id,tenant_id,workspace_id,key_version,ephemeral_public_key,nonce,ciphertext")
    .eq("recipient_identity_id", identityId).eq("status", "sealed").limit(100);
  if (error) throw error;
  const received: string[] = [];
  for (const grant of (data ?? []) as SealedGrantRow[]) {
    let workspaceKey: Uint8Array | null = null;
    try {
      workspaceKey = await openSealedKey(pair.privateKeyPkcs8, {
        ephemeralPublicKey: bytea(grant.ephemeral_public_key), nonce: bytea(grant.nonce), ciphertext: bytea(grant.ciphertext),
      }, grantContext(grant.tenant_id, grant.workspace_id, identityId, grant.key_version));
      const rootEnvelope = await wrapKey(rootKey, workspaceKey, "1accessos:workspace:v1");
      const { error: acceptError } = await client.rpc("accept_workspace_key_grant", {
        p_grant_id: grant.id, p_root_nonce: toPostgresBytea(fromBase64Url(rootEnvelope.nonce)),
        p_root_wrapped_key: toPostgresBytea(fromBase64Url(rootEnvelope.ciphertext)),
      });
      if (!acceptError) received.push(grant.workspace_id);
    } catch {
      // Skip this grant; an administrator can share it again.
    } finally {
      workspaceKey?.fill(0);
    }
  }
  return received;
}

export type GrantToSeal = {
  grant_id: string; workspace_id: string; recipient_identity_id: string; role: string; source: string; display_name: string;
  public_key: string | null; fingerprint: string | null; key_version: number; created_at: string; requested_by: string | null;
};

// ---------------------------------------------------------------------------
// Trust on first use: this device remembers each recipient's sharing-key fingerprint and refuses
// to seal to a different key until an administrator confirms the change.
// ---------------------------------------------------------------------------
function pinStoreKey(sealerIdentityId: string) { return `px-sharing-pins:v1:${sealerIdentityId}`; }

function readPins(sealerIdentityId: string): Record<string, string> {
  try {
    const raw = globalThis.localStorage?.getItem(pinStoreKey(sealerIdentityId));
    const parsed = raw ? JSON.parse(raw) as unknown : {};
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, string> : {};
  } catch { return {}; }
}

function writePins(sealerIdentityId: string, pins: Record<string, string>) {
  try { globalThis.localStorage?.setItem(pinStoreKey(sealerIdentityId), JSON.stringify(pins)); } catch { /* storage blocked: pins stay in memory for this call */ }
}

/** Accepts a recipient's new sharing key after an administrator compared the fingerprint. */
export function trustRecipientKey(sealerIdentityId: string, recipientIdentityId: string, fingerprint: string) {
  const pins = readPins(sealerIdentityId);
  pins[recipientIdentityId] = fingerprint;
  writePins(sealerIdentityId, pins);
}

export function pinnedFingerprint(sealerIdentityId: string, recipientIdentityId: string): string | null {
  return readPins(sealerIdentityId)[recipientIdentityId] ?? null;
}

export async function listGrantsToSeal(tenantId: string): Promise<GrantToSeal[]> {
  const { data, error } = await db().rpc("grants_to_seal", { p_tenant_id: tenantId });
  if (error) throw error;
  return (data ?? []) as GrantToSeal[];
}

export type SealOutcome = { sealed: number; waiting: number; keyChanged: { identityId: string; name: string; fingerprint: string }[]; needsApproval: number };

/**
 * Seals pending grants for workspaces this device holds keys to.
 * - `approvedOnly`: when set (automatic background runs), only grants this person requested
 *   themselves are sealed; group-driven or other people's requests wait for an explicit
 *   "Deliver" click in the admin console.
 * - Recipients whose key differs from the fingerprint pinned on this device are skipped and
 *   reported in `keyChanged`.
 * People who have not unlocked Passkey-X yet (no sharing key) are counted as waiting.
 */
export async function sealPendingGrants(tenantId: string, vaults: WorkspaceVault[], options: { sealerIdentityId?: string; approvedOnly?: boolean } = {}): Promise<SealOutcome> {
  const pending = await listGrantsToSeal(tenantId);
  const outcome: SealOutcome = { sealed: 0, waiting: 0, keyChanged: [], needsApproval: 0 };
  const sealer = options.sealerIdentityId ?? vaults[0]?.identityId ?? "";
  const pins = sealer ? readPins(sealer) : {};
  let pinsChanged = false;
  for (const grant of pending) {
    if (options.approvedOnly && grant.requested_by !== sealer) { outcome.needsApproval += 1; continue; }
    const vault = vaults.find((entry) => entry.workspaceId === grant.workspace_id && entry.keyVersion === grant.key_version);
    if (!vault || !grant.public_key || !grant.fingerprint) { outcome.waiting += 1; continue; }
    const publicKey = bytea(grant.public_key);
    if (await sharingFingerprint(publicKey) !== grant.fingerprint) { outcome.waiting += 1; continue; }
    const pinned = pins[grant.recipient_identity_id];
    if (pinned && pinned !== grant.fingerprint) {
      outcome.keyChanged.push({ identityId: grant.recipient_identity_id, name: grant.display_name, fingerprint: grant.fingerprint });
      continue;
    }
    const box = await sealToPublicKey(vault.key, publicKey, grantContext(vault.tenantId, vault.workspaceId, grant.recipient_identity_id, vault.keyVersion));
    const { error } = await db().rpc("seal_workspace_key_grant", {
      p_grant_id: grant.grant_id, p_key_version: vault.keyVersion, p_recipient_fingerprint: grant.fingerprint,
      p_ephemeral_public_key: toPostgresBytea(box.ephemeralPublicKey), p_nonce: toPostgresBytea(box.nonce), p_ciphertext: toPostgresBytea(box.ciphertext),
    });
    if (error) { outcome.waiting += 1; continue; }
    outcome.sealed += 1;
    if (!pinned) { pins[grant.recipient_identity_id] = grant.fingerprint; pinsChanged = true; }
  }
  if (pinsChanged && sealer) writePins(sealer, pins);
  return outcome;
}

export type MemberSharingKey = { identity_id: string; public_key: string; fingerprint: string };

export async function loadSharingKeys(identityIds: string[]): Promise<Map<string, MemberSharingKey>> {
  if (!identityIds.length) return new Map();
  const { data, error } = await db().from("identity_sharing_keys").select("identity_id,public_key,fingerprint").in("identity_id", identityIds.slice(0, 500));
  if (error) throw error;
  return new Map(((data ?? []) as MemberSharingKey[]).map((row) => [row.identity_id, row]));
}

/** Gives an organization member access to a workspace this device holds the key for. */
export async function grantWorkspaceAccess(vault: WorkspaceVault, recipient: MemberSharingKey, role: "manager" | "editor" | "viewer",
  source: "admin" | "migration" = "admin") {
  const publicKey = bytea(recipient.public_key);
  if (await sharingFingerprint(publicKey) !== recipient.fingerprint) throw new Error("The member's sharing key does not match its fingerprint.");
  const pinned = pinnedFingerprint(vault.identityId, recipient.identity_id);
  if (pinned && pinned !== recipient.fingerprint) {
    throw new Error("This member's sharing key changed since you last shared with them. Confirm the new fingerprint with them in Identity & SSO first.");
  }
  const box = await sealToPublicKey(vault.key, publicKey, grantContext(vault.tenantId, vault.workspaceId, recipient.identity_id, vault.keyVersion));
  const { error } = await db().rpc("grant_workspace_access", {
    p_workspace_id: vault.workspaceId, p_identity_id: recipient.identity_id, p_role: role, p_key_version: vault.keyVersion,
    p_recipient_fingerprint: recipient.fingerprint, p_ephemeral_public_key: toPostgresBytea(box.ephemeralPublicKey),
    p_nonce: toPostgresBytea(box.nonce), p_ciphertext: toPostgresBytea(box.ciphertext), p_source: source,
  });
  if (error) throw error;
  if (!pinned) trustRecipientKey(vault.identityId, recipient.identity_id, recipient.fingerprint);
}

/** Gives access to a member who cannot receive keys yet; the key is delivered once they unlock Passkey-X. */
export async function requestMemberAccess(workspaceId: string, identityId: string, role: "manager" | "editor" | "viewer", source: "admin" | "migration" = "admin") {
  const { error } = await db().rpc("request_member_access", { p_workspace_id: workspaceId, p_identity_id: identityId, p_role: role, p_source: source });
  if (error) throw error;
}

/**
 * Runs after unlock: makes sure this member can receive keys, accepts keys shared with them and
 * delivers keys this device holds to people waiting for them. Never throws.
 */
export async function syncKeyGrants(identityId: string, rootKey: Uint8Array, vaults: WorkspaceVault[]) {
  const result = { received: [] as string[], sealed: 0 };
  try {
    const pair = await ensureSharingKey(identityId, rootKey);
    try { result.received = await acceptIncomingGrants(identityId, rootKey, pair); } finally { pair.privateKeyPkcs8.fill(0); }
  } catch { /* offline or not configured yet */ }
  const managedTenants = [...new Set(vaults.filter((vault) => vault.role === "owner" || vault.role === "manager")
    .filter((vault) => vault.kind !== "vault").map((vault) => vault.tenantId))];
  for (const tenantId of managedTenants) {
    // Automatic runs only deliver access this person asked for; group-driven access waits for approval.
    try { result.sealed += (await sealPendingGrants(tenantId, vaults, { sealerIdentityId: identityId, approvedOnly: true })).sealed; } catch { /* retried next unlock */ }
  }
  return result;
}

/** This member's published sharing-key fingerprint (to read out when an administrator asks). */
export async function myFingerprint(identityId: string): Promise<string | null> {
  const { data, error } = await db().from("identity_sharing_keys").select("fingerprint").eq("identity_id", identityId).maybeSingle();
  if (error) throw error;
  return (data as { fingerprint?: string } | null)?.fingerprint ?? null;
}
