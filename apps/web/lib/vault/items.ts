import { supabase } from "@/lib/supabase/client";
import {
  fromBase64Url,
  toBase64Url,
  toPostgresBytea,
  unwrapKey,
  wrapKey,
} from "@/lib/crypto/vault";

export type ItemKind =
  | "login"
  | "passkey"
  | "secure-note"
  | "identity"
  | "payment-card"
  | "recovery-codes"
  | "wifi"
  | "software-license"
  | "api-key"
  | "ssh-key"
  | "database"
  | "certificate"
  | "custom-secret";

export type VaultPayload = {
  version: 1;
  title: string;
  username?: string;
  secret?: string;
  url?: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
  archived?: boolean;
  fields?: Record<string, string>;
  updatedAt: string;
};

export type VaultItem = {
  id: string;
  contentType: ItemKind;
  revision: number;
  deletedAt: string | null;
  payload: VaultPayload;
};

export type WorkspaceVault = {
  identityId: string;
  tenantId: string;
  workspaceId: string;
  keyVersion: number;
  key: Uint8Array;
  name: string;
  suite: "personal" | "family" | "professional" | "team" | "business";
  kind: "vault" | "project" | "client" | "shared";
  role: "owner" | "manager" | "editor" | "viewer";
  keyRotationRequired: boolean;
};

type ItemRow = {
  id: string;
  content_type: ItemKind;
  schema_version: number;
  head_revision: number;
  deleted_at: string | null;
};

type RevisionRow = {
  item_id: string;
  revision: number;
  nonce: string;
  ciphertext: string;
  aad_hash: string;
  key_version: number;
};

function bytea(value: string): Uint8Array {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/g) ?? [], (part) => Number.parseInt(part, 16));
}

function aadFor(
  vault: Pick<WorkspaceVault, "tenantId" | "workspaceId">,
  itemId: string,
  revision: number,
  contentType: string,
  schemaVersion = 1,
) {
  return `1accessos:item:v1:${vault.tenantId}:${vault.workspaceId}:${itemId}:${revision}:${contentType}:${schemaVersion}`;
}

async function sha256(value: string) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

export function workspaceNameAad(tenantId: string, workspaceId: string) {
  return `1accessos:workspace-name:v1:${tenantId}:${workspaceId}`;
}

export async function listWorkspaceVaults(identityId: string, accountRootKey: Uint8Array): Promise<WorkspaceVault[]> {
  if (!supabase) throw new Error("Supabase is not configured.");

  const { data: memberships, error: membershipError } = await supabase
    .from("workspace_memberships")
    .select("tenant_id,workspace_id,role,created_at")
    .eq("identity_id", identityId)
    .eq("status", "active")
    .order("created_at", { ascending: true });
  if (membershipError) throw membershipError;
  if (!memberships?.length) throw new Error("No active workspace is available.");

  const workspaceIds = memberships.map((membership) => membership.workspace_id);
  const [{ data: workspaceRows, error: workspaceError }, { data: envelopes, error: envelopeError }] = await Promise.all([
    supabase.from("workspaces")
      .select("id,tenant_id,kind,suite,encrypted_name,name_nonce,name_aad_hash,current_key_version,key_rotation_required,status")
      .in("id", workspaceIds)
      .eq("status", "active"),
    supabase
    .from("key_envelopes")
    .select("tenant_id,workspace_id,key_version,nonce,wrapped_key")
    .eq("recipient_identity_id", identityId)
    .eq("key_kind", "workspace")
    .is("revoked_at", null)
    .order("key_version", { ascending: false })
  ]);
  if (workspaceError) throw workspaceError;
  if (envelopeError) throw envelopeError;

  const rows = new Map((workspaceRows ?? []).map((workspace) => [workspace.id, workspace]));
  const opened: WorkspaceVault[] = [];
  for (const membership of memberships) {
    const workspace = rows.get(membership.workspace_id);
    const envelope = envelopes?.find((candidate) =>
      candidate.workspace_id === membership.workspace_id
      && candidate.tenant_id === membership.tenant_id
      && candidate.key_version === workspace?.current_key_version
    );
    if (!workspace || !envelope) continue;
    const key = await unwrapKey(accountRootKey, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(envelope.nonce)),
      ciphertext: toBase64Url(bytea(envelope.wrapped_key)),
    }, "1accessos:workspace:v1");
    let name = workspace.suite === "personal" ? "Personal vault" : `${workspace.suite[0].toUpperCase()}${workspace.suite.slice(1)} workspace`;
    if (workspace.encrypted_name && workspace.name_nonce && workspace.name_aad_hash) {
      const aad = workspaceNameAad(workspace.tenant_id, workspace.id);
      if (toBase64Url(bytea(workspace.name_aad_hash)) !== toBase64Url(await sha256(aad))) {
        key.fill(0);
        throw new Error("Workspace name authentication metadata is invalid.");
      }
      const plaintext = await unwrapKey(key, {
        algorithm: "AES-256-GCM",
        nonce: toBase64Url(bytea(workspace.name_nonce)),
        ciphertext: toBase64Url(bytea(workspace.encrypted_name)),
      }, aad);
      name = new TextDecoder().decode(plaintext);
      plaintext.fill(0);
    }
    opened.push({
      identityId,
      tenantId: membership.tenant_id,
      workspaceId: membership.workspace_id,
      keyVersion: envelope.key_version,
      key,
      name,
      suite: workspace.suite as WorkspaceVault["suite"],
      kind: workspace.kind as WorkspaceVault["kind"],
      role: membership.role as WorkspaceVault["role"],
      keyRotationRequired: workspace.key_rotation_required,
    });
  }
  if (!opened.length) throw new Error("No decryptable workspace key is available for this account.");
  return opened;
}

export async function openWorkspaceVault(identityId: string, accountRootKey: Uint8Array): Promise<WorkspaceVault> {
  const workspaces = await listWorkspaceVaults(identityId, accountRootKey);
  return workspaces[0];
}

export async function listVaultItems(vault: WorkspaceVault, options: { trash?: boolean } = {}): Promise<VaultItem[]> {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { data: itemRows, error: itemError } = await supabase
    .from("vault_items")
    .select("id,content_type,schema_version,head_revision,deleted_at")
    .eq("tenant_id", vault.tenantId)
    .eq("workspace_id", vault.workspaceId)
    .order("updated_at", { ascending: false });
  const filteredRows = options.trash
    ? itemRows?.filter((row) => row.deleted_at !== null)
    : itemRows?.filter((row) => row.deleted_at === null);
  if (itemError) throw itemError;

  const items = (filteredRows ?? []) as ItemRow[];
  if (items.length === 0) return [];

  const { data: revisionRows, error: revisionError } = await supabase
    .from("vault_item_revisions")
    .select("item_id,revision,nonce,ciphertext,aad_hash,key_version")
    .eq("tenant_id", vault.tenantId)
    .eq("workspace_id", vault.workspaceId)
    .in("item_id", items.map((item) => item.id));
  if (revisionError) throw revisionError;

  const revisions = new Map(
    ((revisionRows ?? []) as RevisionRow[]).map((revision) => [
      `${revision.item_id}:${revision.revision}`,
      revision,
    ]),
  );

  return Promise.all(items.map(async (item) => {
    const revision = revisions.get(`${item.id}:${item.head_revision}`);
    if (!revision) throw new Error(`Encrypted revision missing for item ${item.id}.`);
    if (revision.key_version !== vault.keyVersion) throw new Error("Unsupported workspace key version.");
    const aad = aadFor(vault, item.id, revision.revision, item.content_type, item.schema_version);
    const expectedHash = toBase64Url(await sha256(aad));
    if (toBase64Url(bytea(revision.aad_hash)) !== expectedHash) throw new Error("Vault item authentication metadata is invalid.");
    const plaintext = await unwrapKey(
      vault.key,
      {
        algorithm: "AES-256-GCM",
        nonce: toBase64Url(bytea(revision.nonce)),
        ciphertext: toBase64Url(bytea(revision.ciphertext)),
      },
      aad,
    );
    try {
      return {
        id: item.id,
        contentType: item.content_type,
        revision: revision.revision,
        deletedAt: item.deleted_at,
        payload: JSON.parse(new TextDecoder().decode(plaintext)) as VaultPayload,
      };
    } finally { plaintext.fill(0); }
  }));
}

async function encryptedRevision(
  vault: WorkspaceVault,
  itemId: string,
  revision: number,
  contentType: ItemKind,
  payload: VaultPayload,
) {
  const aad = aadFor(vault, itemId, revision, contentType);
  const encrypted = await wrapKey(vault.key, new TextEncoder().encode(JSON.stringify(payload)), aad);
  return {
    nonce: toPostgresBytea(fromBase64Url(encrypted.nonce)),
    ciphertext: toPostgresBytea(fromBase64Url(encrypted.ciphertext)),
    aadHash: toPostgresBytea(await sha256(aad)),
  };
}

export async function createVaultItem(vault: WorkspaceVault, contentType: ItemKind, payload: VaultPayload) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const id = crypto.randomUUID();
  const encrypted = await encryptedRevision(vault, id, 1, contentType, payload);
  const { error } = await supabase.rpc("create_vault_item", {
    p_item_id: id,
    p_tenant_id: vault.tenantId,
    p_workspace_id: vault.workspaceId,
    p_content_type: contentType,
    p_schema_version: 1,
    p_nonce: encrypted.nonce,
    p_ciphertext: encrypted.ciphertext,
    p_aad_hash: encrypted.aadHash,
  });
  if (error) throw error;
}

export async function updateVaultItem(vault: WorkspaceVault, item: VaultItem, payload: VaultPayload) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const encrypted = await encryptedRevision(vault, item.id, item.revision + 1, item.contentType, payload);
  const { error } = await supabase.rpc("update_vault_item", {
    p_item_id: item.id,
    p_expected_revision: item.revision,
    p_nonce: encrypted.nonce,
    p_ciphertext: encrypted.ciphertext,
    p_aad_hash: encrypted.aadHash,
  });
  if (error) throw error;
}

export async function deleteVaultItem(vault: WorkspaceVault, item: VaultItem) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase.rpc("delete_vault_item", {
    p_item_id: item.id,
    p_expected_revision: item.revision,
  });
  if (error) throw error;
}

export async function restoreVaultItem(vault: WorkspaceVault, item: VaultItem) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase.rpc("restore_vault_item", {
    p_item_id: item.id,
    p_expected_revision: item.revision,
  });
  if (error) throw error;
}

export type VaultHistoryEntry = {
  revision: number;
  createdAt: string;
  payload: VaultPayload;
};

export async function listVaultItemHistory(vault: WorkspaceVault, item: VaultItem): Promise<VaultHistoryEntry[]> {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { data, error } = await supabase
    .from("vault_item_revisions")
    .select("revision,nonce,ciphertext,aad_hash,key_version,created_at")
    .eq("tenant_id", vault.tenantId)
    .eq("workspace_id", vault.workspaceId)
    .eq("item_id", item.id)
    .order("revision", { ascending: false });
  if (error) throw error;
  return Promise.all((data ?? []).map(async (revision) => {
    if (revision.key_version !== vault.keyVersion) throw new Error("Unsupported workspace key version.");
    const aad = aadFor(vault, item.id, revision.revision, item.contentType);
    const expectedHash = toBase64Url(await sha256(aad));
    if (toBase64Url(bytea(revision.aad_hash)) !== expectedHash) throw new Error("Revision authentication metadata is invalid.");
    const plaintext = await unwrapKey(vault.key, {
      algorithm: "AES-256-GCM",
      nonce: toBase64Url(bytea(revision.nonce)),
      ciphertext: toBase64Url(bytea(revision.ciphertext)),
    }, aad);
    try {
      return {
        revision: revision.revision,
        createdAt: revision.created_at,
        payload: JSON.parse(new TextDecoder().decode(plaintext)) as VaultPayload,
      };
    } finally { plaintext.fill(0); }
  }));
}
