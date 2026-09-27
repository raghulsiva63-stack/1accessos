import { supabase } from "@/lib/supabase/client";
import {
  fromBase64Url,
  randomBytes,
  toBase64Url,
  toPostgresBytea,
  unwrapKey,
  wrapKey,
} from "@/lib/crypto/vault";
import { workspaceNameAad, type VaultItem, type VaultPayload, type WorkspaceVault } from "@/lib/vault/items";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type WorkspaceSuite = "family" | "professional" | "team" | "business";
export type WorkspaceRole = "manager" | "editor" | "viewer";
export type InviteLink = { id: string; token: Uint8Array; kind: "invite" | "capsule" };

export type WorkspaceInvite = {
  id: string;
  role: WorkspaceRole;
  status: string;
  expiresAt: string;
  acceptedBy: string | null;
};

export type WorkspaceMember = {
  identityId: string;
  role: "owner" | WorkspaceRole;
  status: string;
  createdAt: string;
};

export type SentCapsule = {
  id: string;
  itemId: string;
  revealPolicy: "reveal" | "fill_only";
  purposeCode: string;
  status: string;
  expiresAt: string;
  maxUses: number;
  useCount: number;
};

export type ReceivedCapsule = SentCapsule & {
  payload: VaultPayload;
};

export type Mission = {
  id: string;
  title: string;
  durationMinutes: number;
  itemIds: string[];
  status: string;
};

export type AccessRequest = {
  id: string;
  itemId: string | null;
  requesterIdentityId: string;
  requestedScope: "use" | "reveal" | "edit" | "manage";
  purpose: string;
  durationMinutes: number;
  status: string;
  expiresAt: string;
};

function bytea(value: string): Uint8Array {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

async function sha256(value: string | Uint8Array) {
  const input = typeof value === "string" ? encoder.encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(input).buffer));
}

async function assertAad(value: string, stored: string) {
  if (toBase64Url(await sha256(value)) !== toBase64Url(bytea(stored))) {
    throw new Error("Encrypted collaboration metadata was changed.");
  }
}

export async function emailHash(email: string) {
  return sha256(email.trim().toLowerCase());
}

export function parseCollaborationLink(hash: string): InviteLink | null {
  const match = hash.match(/^#(invite|capsule)=([0-9a-f-]{36})\.([A-Za-z0-9_-]+)$/iu);
  if (!match) return null;
  const token = fromBase64Url(match[3]);
  if (token.byteLength !== 32) return null;
  return { kind: match[1] as InviteLink["kind"], id: match[2], token };
}

export async function createSharedWorkspace(
  identityId: string,
  accountRootKey: Uint8Array,
  name: string,
  suite: WorkspaceSuite,
): Promise<WorkspaceVault> {
  if (!supabase) throw new Error("Supabase is not configured.");
  const tenantId = crypto.randomUUID();
  const workspaceId = crypto.randomUUID();
  const workspaceKey = randomBytes(32);
  const kind = suite === "professional" ? "client" : "shared";
  const nameAad = workspaceNameAad(tenantId, workspaceId);
  const encryptedName = await wrapKey(workspaceKey, encoder.encode(name.trim()), nameAad);
  const rootEnvelope = await wrapKey(accountRootKey, workspaceKey, "1accessos:workspace:v1");
  const { error } = await supabase.rpc("create_shared_workspace", {
    p_tenant_id: tenantId,
    p_workspace_id: workspaceId,
    p_suite: suite,
    p_workspace_kind: kind,
    p_encrypted_name: toPostgresBytea(fromBase64Url(encryptedName.ciphertext)),
    p_name_nonce: toPostgresBytea(fromBase64Url(encryptedName.nonce)),
    p_name_aad_hash: toPostgresBytea(await sha256(nameAad)),
    p_key_nonce: toPostgresBytea(fromBase64Url(rootEnvelope.nonce)),
    p_wrapped_workspace_key: toPostgresBytea(fromBase64Url(rootEnvelope.ciphertext)),
  });
  if (error) {
    workspaceKey.fill(0);
    throw error;
  }
  return {
    identityId,
    tenantId,
    workspaceId,
    keyVersion: 1,
    key: workspaceKey,
    name: name.trim(),
    suite,
    kind,
    role: "owner",
    keyRotationRequired: false,
  };
}

export async function createWorkspaceInvite(
  vault: WorkspaceVault,
  recipientEmail: string,
  role: WorkspaceRole,
  expiresAt: string,
  origin: string,
) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const id = crypto.randomUUID();
  const token = randomBytes(32);
  const aad = `1accessos:workspace-invite-key:v1:${id}:${vault.tenantId}:${vault.workspaceId}`;
  const wrapped = await wrapKey(token, vault.key, aad);
  const { error } = await supabase.from("workspace_invites").insert({
    id,
    tenant_id: vault.tenantId,
    workspace_id: vault.workspaceId,
    created_by: vault.identityId,
    recipient_email_hash: toPostgresBytea(await emailHash(recipientEmail)),
    role,
    token_hash: toPostgresBytea(await sha256(token)),
    key_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)),
    wrapped_workspace_key: toPostgresBytea(fromBase64Url(wrapped.ciphertext)),
    key_aad_hash: toPostgresBytea(await sha256(aad)),
    status: "pending",
    expires_at: expiresAt,
  });
  if (error) throw error;
  const link = `${origin.replace(/\/$/u, "")}/#invite=${id}.${toBase64Url(token)}`;
  token.fill(0);
  return link;
}

export async function listWorkspaceInvites(vault: WorkspaceVault): Promise<WorkspaceInvite[]> {
  if (!supabase) return [];
  const { data, error } = await supabase.from("workspace_invites")
    .select("id,role,status,expires_at,accepted_by")
    .eq("workspace_id", vault.workspaceId)
    .order("created_at", { ascending: false });
  if (error) throw error;
  return (data ?? []).map((row) => ({
    id: row.id,
    role: row.role as WorkspaceRole,
    status: row.status,
    expiresAt: row.expires_at,
    acceptedBy: row.accepted_by,
  }));
}

export async function revokeWorkspaceInvite(id: string) {
  if (!supabase) return;
  const { error } = await supabase.rpc("revoke_workspace_invite", { p_invite_id: id });
  if (error) throw error;
}

export async function acceptWorkspaceInvite(link: InviteLink, accountRootKey: Uint8Array) {
  if (!supabase || link.kind !== "invite") throw new Error("That workspace invitation is invalid.");
  const { data: invite, error } = await supabase.from("workspace_invites")
    .select("id,tenant_id,workspace_id,key_nonce,wrapped_workspace_key,key_aad_hash,status")
    .eq("id", link.id).eq("status", "pending").single();
  if (error) throw new Error("This invitation is unavailable, expired, or belongs to another email address.");
  const aad = `1accessos:workspace-invite-key:v1:${invite.id}:${invite.tenant_id}:${invite.workspace_id}`;
  await assertAad(aad, invite.key_aad_hash);
  const workspaceKey = await unwrapKey(link.token, {
    algorithm: "AES-256-GCM",
    nonce: toBase64Url(bytea(invite.key_nonce)),
    ciphertext: toBase64Url(bytea(invite.wrapped_workspace_key)),
  }, aad);
  try {
    const rootEnvelope = await wrapKey(accountRootKey, workspaceKey, "1accessos:workspace:v1");
    const { error: acceptError } = await supabase.rpc("accept_workspace_invite", {
      p_invite_id: invite.id,
      p_token_hash: toPostgresBytea(await sha256(link.token)),
      p_root_key_nonce: toPostgresBytea(fromBase64Url(rootEnvelope.nonce)),
      p_root_wrapped_workspace_key: toPostgresBytea(fromBase64Url(rootEnvelope.ciphertext)),
    });
    if (acceptError) throw acceptError;
    link.token.fill(0); // only after success, so a transient failure can be retried
    return invite.workspace_id;
  } finally {
    workspaceKey.fill(0);
  }
}

export async function listWorkspaceMembers(vault: WorkspaceVault): Promise<WorkspaceMember[]> {
  if (!supabase) return [];
  const { data, error } = await supabase.from("workspace_memberships")
    .select("identity_id,role,status,created_at")
    .eq("workspace_id", vault.workspaceId)
    .order("created_at");
  if (error) throw error;
  return (data ?? []).map((row) => ({
    identityId: row.identity_id,
    role: row.role as WorkspaceMember["role"],
    status: row.status,
    createdAt: row.created_at,
  }));
}

export async function revokeWorkspaceMember(vault: WorkspaceVault, identityId: string) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase.rpc("revoke_workspace_member", {
    p_workspace_id: vault.workspaceId,
    p_identity_id: identityId,
  });
  if (error) throw error;
}

export async function createAccessCapsule(
  vault: WorkspaceVault,
  item: VaultItem,
  recipientEmail: string,
  revealPolicy: "reveal" | "fill_only",
  purposeCode: string,
  expiresAt: string,
  maxUses: number,
  origin: string,
) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const id = crypto.randomUUID();
  const shareKey = randomBytes(32);
  const token = randomBytes(32);
  const payloadAad = `1accessos:capsule-payload:v1:${id}:${vault.tenantId}:${vault.workspaceId}:${item.id}`;
  const keyAad = `1accessos:capsule-invite-key:v1:${id}`;
  try {
    const payload = await wrapKey(shareKey, encoder.encode(JSON.stringify(item.payload)), payloadAad);
    const keyEnvelope = await wrapKey(token, shareKey, keyAad);
    const { error } = await supabase.from("access_capsules").insert({
      id,
      tenant_id: vault.tenantId,
      workspace_id: vault.workspaceId,
      item_id: item.id,
      created_by: vault.identityId,
      recipient_email_hash: toPostgresBytea(await emailHash(recipientEmail)),
      reveal_policy: revealPolicy,
      purpose_code: purposeCode,
      payload_nonce: toPostgresBytea(fromBase64Url(payload.nonce)),
      payload_ciphertext: toPostgresBytea(fromBase64Url(payload.ciphertext)),
      payload_aad_hash: toPostgresBytea(await sha256(payloadAad)),
      token_hash: toPostgresBytea(await sha256(token)),
      invite_key_nonce: toPostgresBytea(fromBase64Url(keyEnvelope.nonce)),
      invite_wrapped_key: toPostgresBytea(fromBase64Url(keyEnvelope.ciphertext)),
      invite_key_aad_hash: toPostgresBytea(await sha256(keyAad)),
      status: "pending",
      expires_at: expiresAt,
      max_uses: maxUses,
    });
    if (error) throw error;
    return `${origin.replace(/\/$/u, "")}/#capsule=${id}.${toBase64Url(token)}`;
  } finally {
    shareKey.fill(0);
    token.fill(0);
  }
}

export async function acceptAccessCapsule(link: InviteLink, accountRootKey: Uint8Array) {
  if (!supabase || link.kind !== "capsule") throw new Error("That Access Capsule is invalid.");
  const { data: capsule, error } = await supabase.from("access_capsules")
    .select("id,invite_key_nonce,invite_wrapped_key,invite_key_aad_hash,status")
    .eq("id", link.id).eq("status", "pending").single();
  if (error) throw new Error("This Access Capsule is unavailable, expired, or belongs to another email address.");
  const keyAad = `1accessos:capsule-invite-key:v1:${capsule.id}`;
  await assertAad(keyAad, capsule.invite_key_aad_hash);
  const shareKey = await unwrapKey(link.token, {
    algorithm: "AES-256-GCM",
    nonce: toBase64Url(bytea(capsule.invite_key_nonce)),
    ciphertext: toBase64Url(bytea(capsule.invite_wrapped_key)),
  }, keyAad);
  try {
    const recipientAad = `1accessos:capsule-recipient:v1:${capsule.id}`;
    const recipientEnvelope = await wrapKey(accountRootKey, shareKey, recipientAad);
    const { error: acceptError } = await supabase.rpc("accept_access_capsule", {
      p_capsule_id: capsule.id,
      p_token_hash: toPostgresBytea(await sha256(link.token)),
      p_recipient_key_nonce: toPostgresBytea(fromBase64Url(recipientEnvelope.nonce)),
      p_recipient_wrapped_key: toPostgresBytea(fromBase64Url(recipientEnvelope.ciphertext)),
      p_recipient_key_aad_hash: toPostgresBytea(await sha256(recipientAad)),
    });
    if (acceptError) throw acceptError;
    link.token.fill(0); // only after success, so a transient failure can be retried
  } finally {
    shareKey.fill(0);
  }
}

export async function listSentCapsules(vault: WorkspaceVault): Promise<SentCapsule[]> {
  if (!supabase) return [];
  const { data, error } = await supabase.from("access_capsules")
    .select("id,item_id,reveal_policy,purpose_code,status,expires_at,max_uses,use_count")
    .eq("workspace_id", vault.workspaceId)
    .eq("created_by", vault.identityId)
    .order("created_at", { ascending: false });
  if (error) throw error;
  return (data ?? []).map((row) => ({
    id: row.id, itemId: row.item_id, revealPolicy: row.reveal_policy as SentCapsule["revealPolicy"],
    purposeCode: row.purpose_code, status: row.status, expiresAt: row.expires_at,
    maxUses: row.max_uses, useCount: row.use_count,
  }));
}

export async function listReceivedCapsules(identityId: string, accountRootKey: Uint8Array): Promise<ReceivedCapsule[]> {
  if (!supabase) return [];
  const { data, error } = await supabase.from("access_capsules")
    .select("id,item_id,tenant_id,workspace_id,reveal_policy,purpose_code,status,expires_at,max_uses,use_count,payload_nonce,payload_ciphertext,payload_aad_hash,recipient_key_nonce,recipient_wrapped_key,recipient_key_aad_hash")
    .eq("accepted_by", identityId).eq("status", "accepted").order("accepted_at", { ascending: false });
  if (error) throw error;
  return Promise.all((data ?? []).map(async (row) => {
    if (!row.recipient_key_nonce || !row.recipient_wrapped_key || !row.recipient_key_aad_hash) {
      throw new Error("Access Capsule recipient envelope is incomplete.");
    }
    const recipientAad = `1accessos:capsule-recipient:v1:${row.id}`;
    await assertAad(recipientAad, row.recipient_key_aad_hash);
    const shareKey = await unwrapKey(accountRootKey, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(row.recipient_key_nonce)),
      ciphertext: toBase64Url(bytea(row.recipient_wrapped_key)),
    }, recipientAad);
    try {
      const payloadAad = `1accessos:capsule-payload:v1:${row.id}:${row.tenant_id}:${row.workspace_id}:${row.item_id}`;
      await assertAad(payloadAad, row.payload_aad_hash);
      const plaintext = await unwrapKey(shareKey, {
        algorithm: "AES-256-GCM",
        nonce: toBase64Url(bytea(row.payload_nonce)),
        ciphertext: toBase64Url(bytea(row.payload_ciphertext)),
      }, payloadAad);
      try {
        return {
          id: row.id, itemId: row.item_id, revealPolicy: row.reveal_policy as SentCapsule["revealPolicy"],
          purposeCode: row.purpose_code, status: row.status, expiresAt: row.expires_at,
          maxUses: row.max_uses, useCount: row.use_count,
          payload: JSON.parse(decoder.decode(plaintext)) as VaultPayload,
        };
      } finally { plaintext.fill(0); }
    } finally { shareKey.fill(0); }
  }));
}

export async function consumeAccessCapsule(id: string) {
  if (!supabase) return;
  const { error } = await supabase.rpc("consume_access_capsule", { p_capsule_id: id });
  if (error) throw error;
}

export async function revokeAccessCapsule(id: string) {
  if (!supabase) return;
  const { error } = await supabase.rpc("revoke_access_capsule", { p_capsule_id: id });
  if (error) throw error;
}

export async function createMission(vault: WorkspaceVault, title: string, itemIds: string[], durationMinutes: number) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const id = crypto.randomUUID();
  const aad = `1accessos:mission:v1:${id}:${vault.tenantId}:${vault.workspaceId}`;
  const definition = await wrapKey(vault.key, encoder.encode(JSON.stringify({
    version: 1, title: title.trim(), durationMinutes, createdAt: new Date().toISOString(),
  })), aad);
  const { error } = await supabase.rpc("create_mission", {
    p_mission_id: id,
    p_tenant_id: vault.tenantId,
    p_workspace_id: vault.workspaceId,
    p_definition_nonce: toPostgresBytea(fromBase64Url(definition.nonce)),
    p_encrypted_definition: toPostgresBytea(fromBase64Url(definition.ciphertext)),
    p_definition_aad_hash: toPostgresBytea(await sha256(aad)),
    p_item_ids: itemIds,
  });
  if (error) throw error;
}

export async function listMissions(vault: WorkspaceVault): Promise<Mission[]> {
  if (!supabase) return [];
  const [{ data: rows, error }, { data: links, error: linkError }] = await Promise.all([
    supabase.from("missions").select("id,definition_nonce,encrypted_definition,definition_aad_hash,status")
      .eq("workspace_id", vault.workspaceId).order("updated_at", { ascending: false }),
    supabase.from("mission_items").select("mission_id,item_id,sort_order")
      .eq("workspace_id", vault.workspaceId).order("sort_order"),
  ]);
  if (error) throw error;
  if (linkError) throw linkError;
  return Promise.all((rows ?? []).map(async (row) => {
    const aad = `1accessos:mission:v1:${row.id}:${vault.tenantId}:${vault.workspaceId}`;
    await assertAad(aad, row.definition_aad_hash);
    const plaintext = await unwrapKey(vault.key, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(row.definition_nonce)),
      ciphertext: toBase64Url(bytea(row.encrypted_definition)),
    }, aad);
    try {
      const definition = JSON.parse(decoder.decode(plaintext)) as { title: string; durationMinutes: number };
      return {
        id: row.id, title: definition.title, durationMinutes: definition.durationMinutes,
        itemIds: (links ?? []).filter((link) => link.mission_id === row.id).map((link) => link.item_id),
        status: row.status,
      };
    } finally { plaintext.fill(0); }
  }));
}

export async function startMission(vault: WorkspaceVault, mission: Mission) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const expiresAt = new Date(Date.now() + mission.durationMinutes * 60_000).toISOString();
  const { error } = await supabase.from("mission_runs").insert({
    mission_id: mission.id,
    tenant_id: vault.tenantId,
    workspace_id: vault.workspaceId,
    started_by: vault.identityId,
    status: "running",
    expires_at: expiresAt,
  });
  if (error) throw error;
  return expiresAt;
}

export async function createAccessRequest(
  vault: WorkspaceVault,
  itemId: string | null,
  scope: AccessRequest["requestedScope"],
  purpose: string,
  durationMinutes: number,
) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const id = crypto.randomUUID();
  const aad = `1accessos:access-request:v1:${id}:${vault.tenantId}:${vault.workspaceId}`;
  const encrypted = await wrapKey(vault.key, encoder.encode(purpose.trim()), aad);
  const { error } = await supabase.from("access_requests").insert({
    id,
    tenant_id: vault.tenantId,
    workspace_id: vault.workspaceId,
    item_id: itemId,
    requester_identity_id: vault.identityId,
    requested_scope: scope,
    purpose_nonce: toPostgresBytea(fromBase64Url(encrypted.nonce)),
    encrypted_purpose: toPostgresBytea(fromBase64Url(encrypted.ciphertext)),
    purpose_aad_hash: toPostgresBytea(await sha256(aad)),
    requested_duration_minutes: durationMinutes,
    status: "pending",
    expires_at: new Date(Date.now() + 24 * 60 * 60_000).toISOString(),
  });
  if (error) throw error;
}

export async function listAccessRequests(vault: WorkspaceVault): Promise<AccessRequest[]> {
  if (!supabase) return [];
  const { data, error } = await supabase.from("access_requests")
    .select("id,item_id,requester_identity_id,requested_scope,purpose_nonce,encrypted_purpose,purpose_aad_hash,requested_duration_minutes,status,expires_at")
    .eq("workspace_id", vault.workspaceId).order("created_at", { ascending: false });
  if (error) throw error;
  return Promise.all((data ?? []).map(async (row) => {
    const aad = `1accessos:access-request:v1:${row.id}:${vault.tenantId}:${vault.workspaceId}`;
    await assertAad(aad, row.purpose_aad_hash);
    const plaintext = await unwrapKey(vault.key, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(row.purpose_nonce)),
      ciphertext: toBase64Url(bytea(row.encrypted_purpose)),
    }, aad);
    try {
      return {
        id: row.id, itemId: row.item_id, requesterIdentityId: row.requester_identity_id,
        requestedScope: row.requested_scope as AccessRequest["requestedScope"],
        purpose: decoder.decode(plaintext), durationMinutes: row.requested_duration_minutes,
        status: row.status, expiresAt: row.expires_at,
      };
    } finally { plaintext.fill(0); }
  }));
}

export async function decideAccessRequest(id: string, decision: "approved" | "denied") {
  if (!supabase) return;
  const { error } = await supabase.rpc("decide_access_request", { p_request_id: id, p_decision: decision });
  if (error) throw error;
}
