import { createClient } from "@supabase/supabase-js";
import { argon2id } from "hash-wasm";

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || "https://egqgzkirazabocqwdlfp.supabase.co";
const SUPABASE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY || "sb_publishable_GxkSBRRftqpxFFGFL9jq6A_ZZiXCagU";
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false, autoRefreshToken: true } });
const encoder = new TextEncoder();

type Credential = { id: string; revision: number; title: string; username: string; secret: string; url: string };
type Candidate = { origin: string; url: string; username: string; secret: string };
type VaultContext = { identityId: string; tenantId: string; workspaceId: string; keyVersion: number; key: Uint8Array };

let vault: VaultContext | null = null;
let credentials: Credential[] = [];
const candidates = new Map<number, Candidate>();
const candidateTimers = new Map<number, ReturnType<typeof setTimeout>>();

function forgetCandidate(tabId: number) {
  const candidate = candidates.get(tabId);
  if (candidate) candidate.secret = "";
  candidates.delete(tabId);
  const timer = candidateTimers.get(tabId);
  if (timer) clearTimeout(timer);
  candidateTimers.delete(tabId);
}

async function isIgnored(origin: string) {
  const state = await chrome.storage.local.get("ignoredOrigins");
  return Array.isArray(state.ignoredOrigins) && state.ignoredOrigins.includes(origin);
}

async function ignoreOrigin(origin: string) {
  const state = await chrome.storage.local.get("ignoredOrigins");
  const origins = new Set(Array.isArray(state.ignoredOrigins) ? state.ignoredOrigins.filter((value): value is string => typeof value === "string") : []);
  origins.add(origin);
  await chrome.storage.local.set({ ignoredOrigins: [...origins].sort() });
}

function base64url(bytes: Uint8Array) {
  let binary = ""; bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function fromBase64url(value: string) { const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "="); return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0)); }
function bytea(value: string) { return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64url(value); }
function toBytea(value: Uint8Array) { return `\\x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`; }
function buffer(value: Uint8Array) { return Uint8Array.from(value).buffer; }
function randomBytes(length: number) { return crypto.getRandomValues(new Uint8Array(length)); }
async function digest(value: string) { return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(encoder.encode(value)))); }

async function derive(password: string, salt: Uint8Array, profile: { memoryKib: number; iterations: number; parallelism: number; hashLength: number }) {
  return new Uint8Array(await argon2id({ password: password.normalize("NFKC"), salt, parallelism: profile.parallelism, iterations: profile.iterations, memorySize: profile.memoryKib, hashLength: profile.hashLength, outputType: "binary" }));
}
async function open(keyBytes: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: string) {
  const key = await crypto.subtle.importKey("raw", buffer(keyBytes), "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(aad)), tagLength: 128 }, key, buffer(ciphertext)));
}
async function seal(keyBytes: Uint8Array, plaintext: Uint8Array, aad: string) {
  const nonce = randomBytes(12); const key = await crypto.subtle.importKey("raw", buffer(keyBytes), "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(aad)), tagLength: 128 }, key, buffer(plaintext)));
  return { nonce, ciphertext, aadHash: await digest(aad) };
}
function aad(context: VaultContext, itemId: string, revision: number) { return `1accessos:item:v1:${context.tenantId}:${context.workspaceId}:${itemId}:${revision}:login:1`; }

async function unlock(email: string, loginPassword: string, vaultPassword: string) {
  lock();
  const { error: authError } = await supabase.auth.signInWithPassword({ email, password: loginPassword });
  if (authError) throw authError;
  const { data: profile, error: profileError } = await supabase.from("account_crypto_profiles").select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root").single();
  if (profileError) throw profileError;
  const master = await derive(vaultPassword, bytea(profile.salt), profile.kdf_parameters as { memoryKib: number; iterations: number; parallelism: number; hashLength: number });
  let root: Uint8Array;
  try { root = await open(master, bytea(profile.master_nonce), bytea(profile.master_wrapped_root), "1accessos:account-root:v1"); }
  finally { master.fill(0); }
  const { data: membership, error: membershipError } = await supabase.from("workspace_memberships").select("tenant_id,workspace_id").eq("identity_id", profile.identity_id).eq("status", "active").limit(1).single();
  if (membershipError) { root.fill(0); throw membershipError; }
  const { data: envelope, error: envelopeError } = await supabase.from("key_envelopes").select("key_version,nonce,wrapped_key").eq("tenant_id", membership.tenant_id).eq("workspace_id", membership.workspace_id).eq("recipient_identity_id", profile.identity_id).eq("key_kind", "workspace").is("revoked_at", null).order("key_version", { ascending: false }).limit(1).single();
  if (envelopeError) { root.fill(0); throw envelopeError; }
  const workspaceKey = await open(root, bytea(envelope.nonce), bytea(envelope.wrapped_key), "1accessos:workspace:v1"); root.fill(0);
  vault = { identityId: profile.identity_id, tenantId: membership.tenant_id, workspaceId: membership.workspace_id, keyVersion: envelope.key_version, key: workspaceKey };
  await reloadCredentials();
}

async function reloadCredentials() {
  if (!vault) return;
  const current = vault;
  const { data: items, error } = await supabase.from("vault_items").select("id,head_revision").eq("tenant_id", current.tenantId).eq("workspace_id", current.workspaceId).eq("content_type", "login").is("deleted_at", null);
  if (error) throw error;
  if (!items?.length) { credentials = []; return; }
  const { data: revisions, error: revisionError } = await supabase.from("vault_item_revisions").select("item_id,revision,nonce,ciphertext").eq("tenant_id", current.tenantId).eq("workspace_id", current.workspaceId).in("item_id", items.map((item) => item.id));
  if (revisionError) throw revisionError;
  const heads = new Map(items.map((item) => [item.id, item.head_revision]));
  credentials = (await Promise.all((revisions ?? []).filter((revision) => heads.get(revision.item_id) === revision.revision).map(async (revision) => {
    const plaintext = await open(current.key, bytea(revision.nonce), bytea(revision.ciphertext), aad(current, revision.item_id, revision.revision));
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { title: string; username?: string; secret?: string; url?: string };
    plaintext.fill(0);
    return { id: revision.item_id, revision: revision.revision, title: payload.title, username: payload.username ?? "", secret: payload.secret ?? "", url: payload.url ?? "" };
  }))).filter((credential) => credential.secret);
}

async function saveCandidate(tabId: number) {
  if (!vault) throw new Error("Unlock Passkey-X first.");
  const candidate = candidates.get(tabId); if (!candidate) throw new Error("No submitted login is waiting to be saved.");
  const current = vault; const existing = credentials.find((credential) => credential.username === candidate.username && safeOrigin(credential.url) === candidate.origin); const itemId = existing?.id ?? crypto.randomUUID(); const revision = (existing?.revision ?? 0) + 1;
  const payload = { version: 1, title: new URL(candidate.origin).hostname, username: candidate.username, secret: candidate.secret, url: candidate.url, tags: ["browser-save"], updatedAt: new Date().toISOString() };
  const encrypted = await seal(current.key, encoder.encode(JSON.stringify(payload)), aad(current, itemId, revision));
  const args = { p_item_id: itemId, p_expected_revision: existing?.revision, p_tenant_id: current.tenantId, p_workspace_id: current.workspaceId, p_content_type: "login", p_schema_version: 1, p_nonce: toBytea(encrypted.nonce), p_ciphertext: toBytea(encrypted.ciphertext), p_aad_hash: toBytea(encrypted.aadHash) };
  const result = existing ? await supabase.rpc("update_vault_item", { p_item_id: args.p_item_id, p_expected_revision: args.p_expected_revision!, p_nonce: args.p_nonce, p_ciphertext: args.p_ciphertext, p_aad_hash: args.p_aad_hash }) : await supabase.rpc("create_vault_item", { p_item_id: args.p_item_id, p_tenant_id: args.p_tenant_id, p_workspace_id: args.p_workspace_id, p_content_type: args.p_content_type, p_schema_version: args.p_schema_version, p_nonce: args.p_nonce, p_ciphertext: args.p_ciphertext, p_aad_hash: args.p_aad_hash });
  if (result.error) throw result.error;
  forgetCandidate(tabId); await reloadCredentials();
}

function safeOrigin(value: string) { try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.origin : ""; } catch { return ""; } }
function matches(origin: string) { return credentials.filter((credential) => safeOrigin(credential.url) === origin).map(({ id, title, username }) => ({ id, title, username })); }
function lock() { vault?.key.fill(0); vault = null; for (const credential of credentials) credential.secret = ""; credentials = []; for (const tabId of candidates.keys()) forgetCandidate(tabId); void supabase.auth.signOut(); }

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = message as Record<string, unknown>;
  if (!request || typeof request.type !== "string") return false;
  void (async () => {
    try {
      if (request.type === "PX_CANDIDATE") {
        if (!sender.tab?.id || !sender.tab.url) throw new Error("A top-level tab is required.");
        const origin = safeOrigin(sender.tab.url);
        if (!origin || request.origin !== origin || typeof request.username !== "string" || typeof request.secret !== "string" || !request.secret) throw new Error("Rejected untrusted login candidate.");
        if (await isIgnored(origin)) { sendResponse({ ok: true, ignored: true }); return; }
        forgetCandidate(sender.tab.id);
        candidates.set(sender.tab.id, { origin, url: String(request.url), username: request.username, secret: request.secret });
        candidateTimers.set(sender.tab.id, setTimeout(() => forgetCandidate(sender.tab!.id!), 60_000));
        sendResponse({ ok: true }); return;
      }
      const tabId = Number(request.tabId); const origin = safeOrigin(String(request.origin ?? ""));
      if (request.type === "PX_UNLOCK") await unlock(String(request.email), String(request.loginPassword), String(request.vaultPassword));
      else if (request.type === "PX_LOCK") lock();
      else if (request.type === "PX_SAVE") await saveCandidate(tabId);
      else if (request.type === "PX_NEVER") { if (!Number.isInteger(tabId) || !origin) throw new Error("A supported page is required."); await ignoreOrigin(origin); forgetCandidate(tabId); }
      else if (request.type === "PX_FILL") {
        if (!vault || !Number.isInteger(tabId) || !origin) throw new Error("Unlock Passkey-X on a supported page.");
        const credential = credentials.find((item) => item.id === request.id && safeOrigin(item.url) === origin); if (!credential) throw new Error("That login does not match this page.");
        await chrome.tabs.sendMessage(tabId, { type: "PX_FILL", origin, username: credential.username, secret: credential.secret });
      }
      sendResponse({ ok: true, unlocked: Boolean(vault), matches: origin ? matches(origin) : [], candidate: Number.isInteger(tabId) ? Boolean(candidates.get(tabId)) : false });
    } catch (error) { sendResponse({ ok: false, error: error instanceof Error ? error.message : "Passkey-X extension error." }); }
  })();
  return true;
});

chrome.runtime.onSuspend.addListener(lock);
chrome.tabs.onRemoved.addListener(forgetCandidate);
chrome.commands.onCommand.addListener((command) => {
  if (command !== "fill-login" || !vault) return;
  void chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
    if (!tab?.id || !tab.url) return;
    const origin = safeOrigin(tab.url); const credential = matches(origin)[0];
    if (!origin || !credential) return;
    const secret = credentials.find((item) => item.id === credential.id);
    if (!secret) return;
    await chrome.tabs.sendMessage(tab.id, { type: "PX_FILL", origin, username: secret.username, secret: secret.secret });
  });
});
