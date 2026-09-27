import type { SupabaseClient } from "@supabase/supabase-js";
import { argon2id } from "hash-wasm";
import { fromBase64Url, randomBytes, toBase64Url, toPostgresBytea } from "@/lib/crypto/vault";
import { supabase } from "@/lib/supabase/client";

export const SEND_MAX_FILE_BYTES = 5 * 1024 * 1024;
export const SEND_MAX_TEXT_CHARS = 50_000;

export type SendPayload =
  | { v: 1; kind: "text"; text: string }
  | { v: 1; kind: "file"; name: string; type: string; data: string };

export type SendLink = { id: string; key: Uint8Array };

export type SentSummary = {
  id: string;
  kind: "text" | "file";
  byte_size: number;
  requires_passphrase: boolean;
  max_views: number;
  view_count: number;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
  last_viewed_at: string | null;
};

export type SendPreview = {
  kind: "text" | "file";
  byte_size: number;
  requires_passphrase: boolean;
  passphrase_salt: string | null;
  views_left: number;
  expires_at: string;
  available: boolean;
  sender: string | null;
};

const encoder = new TextEncoder();

function buffer(value: Uint8Array) { return Uint8Array.from(value).buffer; }

function bytea(value: string) {
  return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64Url(value);
}

function db() {
  if (!supabase) throw new Error("Supabase is not configured.");
  return supabase as unknown as SupabaseClient;
}

async function passphraseKey(passphrase: string, salt: Uint8Array) {
  if (passphrase.length < 8) throw new Error("Use a passphrase of at least 8 characters.");
  const result = await argon2id({
    password: passphrase.normalize("NFKC"), salt, parallelism: 1, iterations: 3,
    memorySize: 65_536, hashLength: 32, outputType: "binary",
  });
  return new Uint8Array(result);
}

/**
 * HKDF-SHA256 over the link key (and optional passphrase key), bound to the send id.
 * Produces the content key and an independent access proof: the server stores only
 * SHA-256(proof), so a view is consumed only by someone holding the full link
 * (and passphrase) — a wrong passphrase never burns a one-time link.
 */
export async function deriveSendMaterial(id: string, linkKey: Uint8Array, passphrase?: Uint8Array) {
  const ikm = new Uint8Array(linkKey.byteLength + (passphrase?.byteLength ?? 0));
  ikm.set(linkKey);
  if (passphrase) ikm.set(passphrase, linkKey.byteLength);
  const base = await crypto.subtle.importKey("raw", buffer(ikm), "HKDF", false, ["deriveKey", "deriveBits"]);
  ikm.fill(0);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode(`passkey-x:send:v1:${id}`) },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const proof = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode(`passkey-x:send:v1:${id}:access-proof`) },
    base, 256,
  ));
  return { key, proof };
}

function aad(id: string, kind: string) { return encoder.encode(`passkey-x:send:v1:${id}:${kind}`); }

export async function encryptSend(id: string, payload: SendPayload, passphrase?: string) {
  const linkKey = randomBytes(32);
  const salt = passphrase ? randomBytes(16) : null;
  const passKey = passphrase && salt ? await passphraseKey(passphrase, salt) : undefined;
  try {
    const { key, proof } = await deriveSendMaterial(id, linkKey, passKey);
    const nonce = randomBytes(12);
    const plaintext = encoder.encode(JSON.stringify(payload));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(aad(id, payload.kind)), tagLength: 128 }, key, buffer(plaintext)));
    plaintext.fill(0);
    return { linkKey, salt, nonce, ciphertext, proof };
  } finally { passKey?.fill(0); }
}

export async function decryptSend(id: string, kind: string, key: CryptoKey, nonce: Uint8Array, ciphertext: Uint8Array) {
  try {
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(aad(id, kind)), tagLength: 128 }, key, buffer(ciphertext)));
    try { return JSON.parse(new TextDecoder().decode(plaintext)) as SendPayload; }
    finally { plaintext.fill(0); }
  } catch {
    throw new Error("This link is incomplete or was changed.");
  }
}

export function sendLink(origin: string, link: SendLink) {
  return `${origin.replace(/\/$/u, "")}/send#${link.id}.${toBase64Url(link.key)}`;
}

export function parseSendLink(hash: string): SendLink | null {
  const match = hash.match(/^#([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/iu);
  if (!match) return null;
  const key = fromBase64Url(match[2]);
  return key.byteLength === 32 ? { id: match[1].toLowerCase(), key } : null;
}

export async function fileToPayload(file: File): Promise<SendPayload> {
  if (file.size > SEND_MAX_FILE_BYTES) throw new Error("Files can be up to 5 MB.");
  const bytes = new Uint8Array(await file.arrayBuffer());
  return { v: 1, kind: "file", name: file.name.slice(0, 200), type: file.type || "application/octet-stream", data: toBase64Url(bytes) };
}

export function payloadToBlob(payload: Extract<SendPayload, { kind: "file" }>) {
  return new Blob([buffer(fromBase64Url(payload.data))], { type: payload.type || "application/octet-stream" });
}

export async function createSecureSend(
  tenantId: string, payload: SendPayload,
  options: { maxViews: number; expiresInHours: number; passphrase?: string; showSender: boolean },
  origin: string,
) {
  if (payload.kind === "text" && (!payload.text.trim() || payload.text.length > SEND_MAX_TEXT_CHARS)) {
    throw new Error(`Enter up to ${SEND_MAX_TEXT_CHARS.toLocaleString()} characters.`);
  }
  const id = crypto.randomUUID();
  const encrypted = await encryptSend(id, payload, options.passphrase || undefined);
  try {
    const { error } = await db().rpc("create_secure_send", {
      p_id: id,
      p_tenant_id: tenantId,
      p_kind: payload.kind,
      p_nonce: toPostgresBytea(encrypted.nonce),
      p_ciphertext: toPostgresBytea(encrypted.ciphertext),
      p_passphrase_salt: encrypted.salt ? toPostgresBytea(encrypted.salt) : null,
      p_max_views: options.maxViews,
      p_expires_at: new Date(Date.now() + options.expiresInHours * 3_600_000).toISOString(),
      p_show_sender: options.showSender,
      p_access_check: toPostgresBytea(encrypted.proof),
    });
    if (error) throw error;
    return sendLink(origin, { id, key: encrypted.linkKey });
  } finally { encrypted.linkKey.fill(0); encrypted.proof.fill(0); }
}

export async function listMySends(identityId: string) {
  const { data, error } = await db().from("secure_sends")
    .select("id,kind,byte_size,requires_passphrase,max_views,view_count,expires_at,revoked_at,created_at,last_viewed_at")
    .eq("created_by", identityId).order("created_at", { ascending: false }).limit(100);
  if (error) throw error;
  return (data ?? []) as SentSummary[];
}

export async function revokeSecureSend(id: string) {
  const { error } = await db().rpc("revoke_secure_send", { p_id: id });
  if (error) throw error;
}

export async function peekSecureSend(id: string) {
  const { data, error } = await db().rpc("peek_secure_send", { p_id: id });
  if (error) throw error;
  const row = (Array.isArray(data) ? data[0] : data) as SendPreview | undefined;
  return row ?? null;
}

export async function openSecureSend(link: SendLink, preview: SendPreview, passphrase?: string) {
  const passKey = preview.requires_passphrase && preview.passphrase_salt
    ? await passphraseKey(passphrase ?? "", bytea(preview.passphrase_salt)) : undefined;
  const { key, proof } = await deriveSendMaterial(link.id, link.key, passKey);
  passKey?.fill(0);
  try {
    const { data, error } = await db().rpc("open_secure_send", { p_id: link.id, p_proof: toPostgresBytea(proof) });
    if (error) throw new Error("This link has expired or was already used.");
    const row = (Array.isArray(data) ? data[0] : data) as { kind: string; nonce: string; ciphertext: string; views_left: number } | undefined;
    if (!row) throw new Error(preview.requires_passphrase ? "That passphrase is incorrect." : "This link is incomplete or was changed.");
    const payload = await decryptSend(link.id, row.kind, key, bytea(row.nonce), bytea(row.ciphertext));
    return { payload, viewsLeft: row.views_left };
  } finally { proof.fill(0); }
}

export function sendStatus(send: SentSummary, now = Date.now()) {
  if (send.revoked_at) return "Revoked";
  if (Date.parse(send.expires_at) <= now) return "Expired";
  if (send.view_count >= send.max_views) return "Used";
  return "Active";
}
