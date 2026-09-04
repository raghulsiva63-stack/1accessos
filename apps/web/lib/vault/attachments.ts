import { supabase } from "@/lib/supabase/client";
import { fromBase64Url, toBase64Url, toPostgresBytea, unwrapKey, wrapKey } from "@/lib/crypto/vault";
import type { WorkspaceVault } from "@/lib/vault/items";

export type VaultAttachment = {
  id: string;
  itemId: string;
  name: string;
  mimeType: string;
  size: number;
  storagePath: string;
  nonce: string;
  aadHash: string;
};

function bytea(value: string) {
  if (!value.startsWith("\\x")) return fromBase64Url(value);
  return Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16));
}

async function sha256(value: Uint8Array | string) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer));
}

function metadataAad(vault: WorkspaceVault, itemId: string, attachmentId: string) {
  return `1accessos:attachment-metadata:v1:${vault.tenantId}:${vault.workspaceId}:${itemId}:${attachmentId}`;
}

function contentAad(vault: WorkspaceVault, itemId: string, attachmentId: string, version = 1) {
  return `1accessos:attachment-content:v1:${vault.tenantId}:${vault.workspaceId}:${itemId}:${attachmentId}:${version}`;
}

export async function uploadEncryptedAttachment(vault: WorkspaceVault, itemId: string, file: File) {
  if (!supabase) throw new Error("Supabase is not configured.");
  if (file.size > 25 * 1024 * 1024) throw new Error("Attachments are limited to 25 MB.");
  const id = crypto.randomUUID();
  const path = `${vault.tenantId}/${vault.workspaceId}/${id}/1`;
  const metadataContext = metadataAad(vault, itemId, id);
  const contentContext = contentAad(vault, itemId, id);
  const metadata = await wrapKey(vault.key, new TextEncoder().encode(JSON.stringify({ name: file.name, mimeType: file.type || "application/octet-stream", size: file.size })), metadataContext);
  const content = await wrapKey(vault.key, new Uint8Array(await file.arrayBuffer()), contentContext);
  const ciphertext = fromBase64Url(content.ciphertext);

  const { error: storageError } = await supabase.storage.from("vault-attachments").upload(path, new Blob([Uint8Array.from(ciphertext).buffer], { type: "application/octet-stream" }), { upsert: false, contentType: "application/octet-stream" });
  if (storageError) throw storageError;
  try {
    const { error: attachmentError } = await supabase.rpc("create_attachment", {
      p_attachment_id: id,
      p_tenant_id: vault.tenantId,
      p_workspace_id: vault.workspaceId,
      p_item_id: itemId,
      p_encrypted_metadata: toPostgresBytea(fromBase64Url(metadata.ciphertext)),
      p_metadata_nonce: toPostgresBytea(fromBase64Url(metadata.nonce)),
      p_metadata_aad_hash: toPostgresBytea(await sha256(metadataContext)),
      p_storage_path: path,
      p_ciphertext_size: ciphertext.byteLength,
      p_ciphertext_sha256: toPostgresBytea(await sha256(ciphertext)),
      p_key_version: vault.keyVersion,
      p_nonce: toPostgresBytea(fromBase64Url(content.nonce)),
      p_aad_hash: toPostgresBytea(await sha256(contentContext)),
    });
    if (attachmentError) throw attachmentError;
  } catch (error) {
    await supabase.storage.from("vault-attachments").remove([path]);
    throw error;
  }
}

export async function listEncryptedAttachments(vault: WorkspaceVault, itemId: string): Promise<VaultAttachment[]> {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { data: attachments, error } = await supabase.from("attachments").select("id,item_id,encrypted_metadata,metadata_nonce,metadata_aad_hash").eq("tenant_id", vault.tenantId).eq("workspace_id", vault.workspaceId).eq("item_id", itemId).is("deleted_at", null);
  if (error) throw error;
  const ids = (attachments ?? []).map((attachment) => attachment.id);
  if (!ids.length) return [];
  const { data: versions, error: versionError } = await supabase.from("attachment_versions").select("attachment_id,storage_path,ciphertext_size,nonce,aad_hash").in("attachment_id", ids).eq("version", 1);
  if (versionError) throw versionError;
  const byAttachment = new Map((versions ?? []).map((version) => [version.attachment_id, version]));
  return Promise.all((attachments ?? []).map(async (attachment) => {
    if (!attachment.metadata_nonce || !attachment.metadata_aad_hash) throw new Error("Attachment metadata is incomplete.");
    const context = metadataAad(vault, itemId, attachment.id);
    if (toBase64Url(bytea(attachment.metadata_aad_hash)) !== toBase64Url(await sha256(context))) throw new Error("Attachment metadata authentication failed.");
    const plaintext = await unwrapKey(vault.key, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(attachment.metadata_nonce)), ciphertext: toBase64Url(bytea(attachment.encrypted_metadata)) }, context);
    const metadata = JSON.parse(new TextDecoder().decode(plaintext)) as { name: string; mimeType: string; size: number };
    const version = byAttachment.get(attachment.id);
    if (!version?.nonce || !version.aad_hash) throw new Error("Attachment ciphertext record is incomplete.");
    return { id: attachment.id, itemId, ...metadata, storagePath: version.storage_path, nonce: toBase64Url(bytea(version.nonce)), aadHash: toBase64Url(bytea(version.aad_hash)) };
  }));
}

export async function downloadEncryptedAttachment(vault: WorkspaceVault, attachment: VaultAttachment) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const context = contentAad(vault, attachment.itemId, attachment.id);
  if (attachment.aadHash !== toBase64Url(await sha256(context))) throw new Error("Attachment authentication metadata changed.");
  const { data, error } = await supabase.storage.from("vault-attachments").download(attachment.storagePath);
  if (error) throw error;
  const plaintext = await unwrapKey(vault.key, { algorithm: "AES-256-GCM", nonce: attachment.nonce, ciphertext: toBase64Url(new Uint8Array(await data.arrayBuffer())) }, context);
  const url = URL.createObjectURL(new Blob([Uint8Array.from(plaintext).buffer], { type: attachment.mimeType }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = attachment.name; anchor.click();
  URL.revokeObjectURL(url); plaintext.fill(0);
}
