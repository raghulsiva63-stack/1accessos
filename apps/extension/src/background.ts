import { authorizedExtensionMessage, authorizedPairingMessage, type PendingPairing } from "./message-boundary";
import { sessionStorageAdapter } from "./session-storage";
import { createClient } from "@supabase/supabase-js";
import { argon2id } from "hash-wasm";

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
if (SUPABASE_URL !== "https://wkkmyacbhqloubtwvjom.supabase.co" || !SUPABASE_KEY?.startsWith("sb_publishable_")) throw new Error("Passkey-X extension production configuration is missing.");
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: {
  persistSession: true, autoRefreshToken: false, detectSessionInUrl: false,
  storageKey: "passkeyXSession", storage: sessionStorageAdapter(chrome.storage.session),
} });
const encoder = new TextEncoder();
const PAIRING_KEY = "passkeyXPendingPairing";
let pairingBusy = false;
let locallyDisconnected = false;
let vaultGeneration = 0;
let vaultOperationBusy = false;
let idleTimer: ReturnType<typeof setTimeout> | undefined;
let lastActivity = 0;
const IDLE_MS = 5 * 60_000;
function touchVault() {
  lastActivity = Date.now();
  clearTimeout(idleTimer);
  idleTimer = setTimeout(clearVault, IDLE_MS);
}
function requireUnlocked() {
  if (!vaults.length || Date.now() - lastActivity >= IDLE_MS) { clearVault(); throw new Error("Unlock Passkey-X first."); }
}

type Credential = {
  key: string;
  id: string;
  revision: number;
  title: string;
  username: string;
  secret: string;
  url: string;
  source: "workspace" | "capsule";
  context?: VaultContext;
  capsuleId?: string;
  maxUses?: number;
  useCount?: number;
};
type Candidate = { id: string; origin: string; url: string; username: string; secret: string; prompted: boolean };
type VaultContext = { identityId: string; tenantId: string; workspaceId: string; keyVersion: number; key: Uint8Array; name: string; writable: boolean };

let vaults: VaultContext[] = [];
let accountRoot: Uint8Array | null = null;
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
  void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
}

async function offerSave(tabId: number) {
  const candidate = candidates.get(tabId);
  if (!candidate || candidate.prompted) return;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (candidates.get(tabId) !== candidate) return;
    if (safeOrigin(tab.url ?? "") !== candidate.origin) { forgetCandidate(tabId); return; }
    if (!tab.active || tab.status === "loading") return;
    candidate.prompted = true;
    // Browser-owned UI keeps the save approval and vault password off the website.
    await chrome.action.openPopup({ windowId: tab.windowId });
  } catch {
    // Browsers can deny opening a popup. The SAVE badge remains an explicit fallback.
  }
}

function candidateSummary(tabId: number, origin: string) {
  const candidate = candidates.get(tabId);
  if (!candidate || candidate.origin !== origin) return null;
  return { id: candidate.id, username: candidate.username, origin: candidate.origin,
    modes: Object.fromEntries(vaults.filter(context => context.writable).map(context => {
      const saved = credentials.find(item => item.source === "workspace" && item.context?.workspaceId === context.workspaceId && safeOrigin(item.url) === candidate.origin && item.username === candidate.username);
      return [context.workspaceId, saved ? saved.secret === candidate.secret ? "same" : "update" : "save"];
    })),
  };
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
  if (!profile || !Number.isInteger(profile.memoryKib) || profile.memoryKib < 65_536 || profile.memoryKib > 262_144 || !Number.isInteger(profile.iterations) || profile.iterations < 3 || profile.iterations > 10 || !Number.isInteger(profile.parallelism) || profile.parallelism < 1 || profile.parallelism > 4 || profile.hashLength !== 32 || salt.length !== 16) throw new Error("Unsupported vault encryption profile. Open the web vault for help.");
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

async function restoreSession() {
  if (locallyDisconnected) return null;
  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session) { clearVault(); return null; }
  return data.session;
}

async function unlock(vaultPassword: string) {
  // A just-submitted website login can wait in memory while its owner unlocks.
  // Explicit lock, disconnect, expiry and worker shutdown still erase it.
  clearVault(false);
  const generation = vaultGeneration;
  if (!(await restoreSession())) throw new Error("Connect this extension to Passkey-X first.");
  const { data: profile, error: profileError } = await supabase.from("account_crypto_profiles").select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root").single();
  if (profileError) throw profileError;
  const master = await derive(vaultPassword, bytea(profile.salt), profile.kdf_parameters as { memoryKib: number; iterations: number; parallelism: number; hashLength: number });
  let root: Uint8Array;
  try { root = await open(master, bytea(profile.master_nonce), bytea(profile.master_wrapped_root), "1accessos:account-root:v1"); }
  finally { master.fill(0); }
  const { data: memberships, error: membershipError } = await supabase.from("workspace_memberships").select("tenant_id,workspace_id,role,created_at").eq("identity_id", profile.identity_id).eq("status", "active").order("created_at");
  if (membershipError || !memberships?.length) { root.fill(0); throw membershipError ?? new Error("No active workspace is available."); }
  const { data: envelopes, error: envelopeError } = await supabase.from("key_envelopes").select("tenant_id,workspace_id,key_version,nonce,wrapped_key").eq("recipient_identity_id", profile.identity_id).eq("key_kind", "workspace").is("revoked_at", null).order("key_version", { ascending: false });
  if (envelopeError) { root.fill(0); throw envelopeError; }
  const opened: VaultContext[] = [];
  try {
    const { data: workspaceRows, error: workspaceError } = await supabase.from("workspaces")
      .select("id,tenant_id,suite,encrypted_name,name_nonce,name_aad_hash,current_key_version,key_rotation_required")
      .in("id", memberships.map(row => row.workspace_id)).eq("status", "active");
    if (workspaceError) throw workspaceError;
    for (const membership of memberships) {
      const workspace = workspaceRows?.find(row => row.id === membership.workspace_id && row.tenant_id === membership.tenant_id);
      const envelope = envelopes?.find(row => row.workspace_id === membership.workspace_id && row.tenant_id === membership.tenant_id && row.key_version === workspace?.current_key_version);
      if (!workspace || !envelope) continue;
      const context: VaultContext = {
        identityId: profile.identity_id,
        tenantId: membership.tenant_id,
        workspaceId: membership.workspace_id,
        keyVersion: envelope.key_version,
        key: await open(root, bytea(envelope.nonce), bytea(envelope.wrapped_key), "1accessos:workspace:v1"),
        name: workspace.suite === "personal" ? "Personal vault" : `${workspace.suite} workspace`,
        writable: ["owner", "manager", "editor"].includes(membership.role) && !workspace.key_rotation_required,
      };
      opened.push(context);
      if (workspace.encrypted_name && workspace.name_nonce && workspace.name_aad_hash) {
        const nameAad = `1accessos:workspace-name:v1:${workspace.tenant_id}:${workspace.id}`;
        if (base64url(await digest(nameAad)) !== base64url(bytea(workspace.name_aad_hash))) throw new Error("Workspace name authentication failed.");
        const name = await open(context.key, bytea(workspace.name_nonce), bytea(workspace.encrypted_name), nameAad);
        try { context.name = new TextDecoder().decode(name); } finally { name.fill(0); }
      }
    }
    if (!opened.length) throw new Error("No authorized workspace key is available.");
    if (generation !== vaultGeneration) throw new Error("Vault unlock was cancelled.");
    vaults = opened;
    accountRoot = root;
    await reloadCredentials();
    if (generation !== vaultGeneration) throw new Error("Vault unlock was cancelled.");
    touchVault();
  } catch (error) {
    for (const context of opened) context.key.fill(0);
    root.fill(0);
    vaults = [];
    accountRoot = null;
    throw error;
  }
}

async function reloadCredentials() {
  if (!vaults.length || !accountRoot) return;
  const generation = vaultGeneration;
  const workspaceIds = vaults.map((context) => context.workspaceId);
  const { data: items, error } = await supabase.from("vault_items").select("id,tenant_id,workspace_id,head_revision").in("workspace_id", workspaceIds).eq("content_type", "login").is("deleted_at", null);
  if (error) throw error;
  const { data: revisions, error: revisionError } = items?.length
    ? await supabase.from("vault_item_revisions").select("item_id,tenant_id,workspace_id,revision,nonce,ciphertext").in("workspace_id", workspaceIds).in("item_id", items.map((item) => item.id))
    : { data: [], error: null };
  if (revisionError) throw revisionError;
  const heads = new Map((items ?? []).map((item) => [item.id, item.head_revision]));
  const workspaceCredentials = (await Promise.all((revisions ?? []).filter((revision) => heads.get(revision.item_id) === revision.revision).map(async (revision) => {
    const current = vaults.find((context) => context.tenantId === revision.tenant_id && context.workspaceId === revision.workspace_id);
    if (!current) return null;
    const plaintext = await open(current.key, bytea(revision.nonce), bytea(revision.ciphertext), aad(current, revision.item_id, revision.revision));
    try {
      const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { title: string; username?: string; secret?: string; url?: string; archived?: boolean };
      if (payload.archived || typeof payload.secret !== "string" || typeof payload.title !== "string") return null;
      return { key: `workspace:${revision.item_id}`, id: revision.item_id, revision: revision.revision, title: payload.title, username: typeof payload.username === "string" ? payload.username : "", secret: payload.secret, url: typeof payload.url === "string" ? payload.url : "", source: "workspace" as const, context: current };
    } finally { plaintext.fill(0); }
  }))).filter((credential): credential is NonNullable<typeof credential> => Boolean(credential?.secret));

  const { data: capsules, error: capsuleError } = await supabase.from("access_capsules")
    .select("id,item_id,tenant_id,workspace_id,reveal_policy,payload_nonce,payload_ciphertext,payload_aad_hash,recipient_key_nonce,recipient_wrapped_key,recipient_key_aad_hash,max_uses,use_count")
    .eq("accepted_by", vaults[0].identityId).eq("status", "accepted");
  if (capsuleError) throw capsuleError;
  const capsuleCredentials = (await Promise.all((capsules ?? []).map(async (capsule) => {
    if (!capsule.recipient_key_nonce || !capsule.recipient_wrapped_key || !capsule.recipient_key_aad_hash) return null;
    const recipientAad = `1accessos:capsule-recipient:v1:${capsule.id}`;
    if (base64url(await digest(recipientAad)) !== base64url(bytea(capsule.recipient_key_aad_hash))) throw new Error("Access Capsule recipient metadata was changed.");
    const shareKey = await open(accountRoot!, bytea(capsule.recipient_key_nonce), bytea(capsule.recipient_wrapped_key), recipientAad);
    try {
      const payloadAad = `1accessos:capsule-payload:v1:${capsule.id}:${capsule.tenant_id}:${capsule.workspace_id}:${capsule.item_id}`;
      if (base64url(await digest(payloadAad)) !== base64url(bytea(capsule.payload_aad_hash))) throw new Error("Access Capsule payload metadata was changed.");
      const plaintext = await open(shareKey, bytea(capsule.payload_nonce), bytea(capsule.payload_ciphertext), payloadAad);
      try {
        const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { title: string; username?: string; secret?: string; url?: string };
        if (!payload.secret || !safeOrigin(payload.url ?? "")) return null;
        return { key: `capsule:${capsule.id}`, id: capsule.item_id, revision: 1, title: payload.title, username: payload.username ?? "", secret: payload.secret, url: payload.url ?? "", source: "capsule" as const, capsuleId: capsule.id, maxUses: capsule.max_uses, useCount: capsule.use_count };
      } finally { plaintext.fill(0); }
    } finally { shareKey.fill(0); }
  }))).filter((credential): credential is NonNullable<typeof credential> => Boolean(credential));
  if (generation !== vaultGeneration) {
    for (const credential of [...workspaceCredentials, ...capsuleCredentials]) credential.secret = "";
    throw new Error("The vault was locked during synchronization.");
  }
  for (const credential of credentials) credential.secret = "";
  credentials = [...workspaceCredentials, ...capsuleCredentials];
}

async function saveCandidate(tabId: number, workspaceId: unknown) {
  requireUnlocked();
  const generation = vaultGeneration;
  const candidate = candidates.get(tabId); if (!candidate) throw new Error("No submitted login is waiting to be saved.");
  await reloadCredentials();
  if (generation !== vaultGeneration || candidates.get(tabId) !== candidate) throw new Error("The login request expired. Submit it again.");
  const current = vaults.find(context => context.workspaceId === workspaceId && context.writable);
  if (!current) throw new Error("Choose an authorized writable workspace.");
  const existing = credentials.find((credential) => credential.source === "workspace" && credential.context?.workspaceId === current.workspaceId && credential.username === candidate.username && safeOrigin(credential.url) === candidate.origin);
  if (existing?.secret === candidate.secret) { forgetCandidate(tabId); return; }
  const itemId = existing?.id ?? crypto.randomUUID(); const revision = (existing?.revision ?? 0) + 1;
  let previous: Record<string, unknown> = {};
  if (existing) {
    const { data, error } = await supabase.from("vault_item_revisions").select("nonce,ciphertext").eq("item_id", existing.id).eq("revision", existing.revision).single();
    if (error) throw error;
    const plaintext = await open(current.key, bytea(data.nonce), bytea(data.ciphertext), aad(current, existing.id, existing.revision));
    try { previous = JSON.parse(new TextDecoder().decode(plaintext)); } finally { plaintext.fill(0); }
  }
  if (candidates.get(tabId) !== candidate || generation !== vaultGeneration) throw new Error("The save request expired.");
  const payload = { ...previous, version: 1, title: previous.title ?? new URL(candidate.origin).hostname, username: candidate.username, secret: candidate.secret, url: candidate.url, tags: previous.tags ?? ["browser-save"], updatedAt: new Date().toISOString() };
  const plaintext = encoder.encode(JSON.stringify(payload));
  let encrypted: Awaited<ReturnType<typeof seal>>;
  try { encrypted = await seal(current.key, plaintext, aad(current, itemId, revision)); }
  finally { plaintext.fill(0); previous.secret = ""; payload.secret = ""; }
  if (generation !== vaultGeneration || candidates.get(tabId) !== candidate) throw new Error("The vault was locked or the save request expired.");
  if (safeOrigin((await chrome.tabs.get(tabId)).url ?? "") !== candidate.origin) throw new Error("The page changed before saving.");
  if (generation !== vaultGeneration || candidates.get(tabId) !== candidate) throw new Error("The save request expired.");
  const args = { p_item_id: itemId, p_expected_revision: existing?.revision, p_tenant_id: current.tenantId, p_workspace_id: current.workspaceId, p_content_type: "login", p_schema_version: 1, p_nonce: toBytea(encrypted.nonce), p_ciphertext: toBytea(encrypted.ciphertext), p_aad_hash: toBytea(encrypted.aadHash) };
  const result = existing ? await supabase.rpc("update_vault_item", { p_item_id: args.p_item_id, p_expected_revision: args.p_expected_revision!, p_nonce: args.p_nonce, p_ciphertext: args.p_ciphertext, p_aad_hash: args.p_aad_hash }) : await supabase.rpc("create_vault_item", { p_item_id: args.p_item_id, p_tenant_id: args.p_tenant_id, p_workspace_id: args.p_workspace_id, p_content_type: args.p_content_type, p_schema_version: args.p_schema_version, p_nonce: args.p_nonce, p_ciphertext: args.p_ciphertext, p_aad_hash: args.p_aad_hash });
  if (result.error) throw result.error;
  forgetCandidate(tabId); await reloadCredentials();
}

function safeOrigin(value: string) { try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.origin : ""; } catch { return ""; } }
function matches(origin: string) { return credentials.filter((credential) => safeOrigin(credential.url) === origin).map(({ key: id, title, username, source }) => ({ id, title: source === "capsule" ? `${title} · shared` : title, username })); }
function clearVault(forgetPending = true) { vaultGeneration++; clearTimeout(idleTimer); for (const context of vaults) context.key.fill(0); vaults = []; accountRoot?.fill(0); accountRoot = null; for (const credential of credentials) credential.secret = ""; credentials = []; if (forgetPending) for (const tabId of [...candidates.keys()]) forgetCandidate(tabId); }
async function disconnect() {
  locallyDisconnected = true;
  clearVault();
  await chrome.storage.session.remove(PAIRING_KEY);
  const { error } = await supabase.auth.signOut({ scope: "local" });
  // Always clear this browser even if network revocation is unavailable.
  await chrome.storage.session.remove("passkeyXSession");
  if (error) throw new Error("Local session removed. Server sign-out failed; revoke this session in account settings.");
}

async function beginPairing() {
  const nonce = Array.from(randomBytes(32), byte => byte.toString(16).padStart(2, "0")).join("");
  const url = new URL("https://passkey-x.com/extension/connect");
  url.searchParams.set("extension_id", chrome.runtime.id);
  url.hash = nonce;
  const tab = await chrome.tabs.create({ url: url.href });
  if (tab.id === undefined) throw new Error("Unable to open the connection page.");
  await chrome.storage.session.set({ [PAIRING_KEY]: { nonce, tabId: tab.id, expiresAt: Date.now() + 300_000 } });
}

async function fillCredential(tabId: number, origin: string, id: unknown) {
  requireUnlocked();
  const generation = vaultGeneration;
  if (!(await restoreSession())) throw new Error("Connect Passkey-X again.");
  // Refresh RLS-filtered memberships/items before releasing any cached secret.
  const { data: memberships, error } = await supabase.from("workspace_memberships")
    .select("workspace_id").eq("identity_id", vaults[0]?.identityId).eq("status", "active");
  if (error) throw new Error("Unable to verify workspace access.");
  const allowed = new Set((memberships ?? []).map(row => row.workspace_id));
  for (const context of vaults) if (!allowed.has(context.workspaceId)) context.key.fill(0);
  vaults = vaults.filter(context => allowed.has(context.workspaceId));
  if (!vaults.length) { clearVault(); throw new Error("Workspace access is no longer available."); }
  await reloadCredentials();
  const credential = credentials.find(item => item.key === id && safeOrigin(item.url) === origin);
  if (!credential) throw new Error("That login is no longer available for this page.");
  const tab = await chrome.tabs.get(tabId);
  if (safeOrigin(tab.url ?? "") !== origin) throw new Error("The page changed. Open Passkey-X again.");
  if (generation !== vaultGeneration) throw new Error("The vault was locked before filling.");
  if (credential.source === "capsule" && credential.capsuleId) {
    const { data: uses, error: useError } = await supabase.rpc("consume_access_capsule", { p_capsule_id: credential.capsuleId });
    if (useError) throw new Error("That Access Capsule is no longer available.");
    credential.useCount = uses;
  }
  if (generation !== vaultGeneration) throw new Error("The vault was locked before filling.");
  try {
    const result = await chrome.tabs.sendMessage(tabId, { type: "PX_FILL", origin, username: credential.username, secret: credential.secret }, { frameId: 0 });
    if (!result?.ok) throw new Error("No visible login form was found on this page.");
    touchVault();
  } finally {
    if (credential.source === "capsule" && credential.maxUses && (credential.useCount ?? 0) >= credential.maxUses) {
      credential.secret = "";
      credentials = credentials.filter(item => item !== credential);
    }
  }
}

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (!authorizedExtensionMessage(message, sender, chrome.runtime.id, chrome.runtime.getURL("popup.html"))) {
    sendResponse({ ok: false, error: "Rejected untrusted extension request." });
    return false;
  }
  const request = message as Record<string, unknown>;
  const guarded = ["PX_UNLOCK", "PX_SAVE", "PX_FILL"].includes(String(request.type));
  if (guarded && (vaultOperationBusy || pairingBusy)) { sendResponse({ ok: false, error: "Another vault operation is running. Try again shortly." }); return false; }
  if (guarded) vaultOperationBusy = true;
  void (async () => {
    try {
      if (vaults.length && Date.now() - lastActivity >= IDLE_MS) clearVault();
      if (request.type === "PX_CANDIDATE") {
        if (sender.tab?.id === undefined || !sender.tab.url || !(await restoreSession())) { sendResponse({ ok: true, ignored: true }); return; }
        const origin = safeOrigin(sender.tab.url);
        if (!origin || request.origin !== origin || typeof request.username !== "string" || typeof request.secret !== "string" || !request.secret) throw new Error("Rejected untrusted login candidate.");
        const generation = vaultGeneration;
        if (await isIgnored(origin) || generation !== vaultGeneration) { sendResponse({ ok: true, ignored: true }); return; }
        if (credentials.some(item => item.source === "workspace" && safeOrigin(item.url) === origin && item.username === request.username && item.secret === request.secret)) { sendResponse({ ok: true, ignored: true }); return; }
        const pending = candidates.get(sender.tab.id);
        if (pending?.origin === origin && pending.username === request.username && pending.secret === request.secret) { sendResponse({ ok: true, duplicate: true }); return; }
        forgetCandidate(sender.tab.id);
        const url = new URL(String(request.url));
        // Query strings/fragments can contain site bearer tokens. Save only the login path.
        candidates.set(sender.tab.id, { id: crypto.randomUUID(), origin, url: url.origin + url.pathname, username: request.username, secret: request.secret, prompted: false });
        candidateTimers.set(sender.tab.id, setTimeout(() => forgetCandidate(sender.tab!.id!), 120_000));
        await chrome.action.setBadgeText({ tabId: sender.tab.id, text: "SAVE" });
        await chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#345bfa" });
        setTimeout(() => void offerSave(sender.tab!.id!), 700);
        sendResponse({ ok: true }); return;
      }
      const tabId = Number(request.tabId); const origin = safeOrigin(String(request.origin ?? ""));
      if (request.type === "PX_CONNECT") await beginPairing();
      else if (request.type === "PX_UNLOCK") {
        if (typeof request.vaultPassword !== "string" || !request.vaultPassword || request.vaultPassword.length > 4096) throw new Error("Enter your vault password.");
        await unlock(request.vaultPassword);
      }
      else if (request.type === "PX_LOCK") clearVault();
      else if (request.type === "PX_DISCONNECT") {
        if (pairingBusy) throw new Error("Wait for the connection to finish, then disconnect.");
        await disconnect();
      }
      else if (request.type === "PX_SAVE") {
        const tab = await chrome.tabs.get(tabId);
        if (!origin || safeOrigin(tab.url ?? "") !== origin || candidates.get(tabId)?.origin !== origin) throw new Error("The page changed. Submit the login again.");
        if (request.candidateId !== candidates.get(tabId)?.id) throw new Error("The login details changed. Review the new save request.");
        await saveCandidate(tabId, request.workspaceId); touchVault();
      }
      else if (request.type === "PX_DISMISS") {
        if (candidates.get(tabId)?.id === request.candidateId) forgetCandidate(tabId);
      }
      else if (request.type === "PX_NEVER" || request.type === "PX_ALLOW") {
        if (!Number.isInteger(tabId) || !origin || safeOrigin((await chrome.tabs.get(tabId)).url ?? "") !== origin) throw new Error("The page changed. Reopen Passkey-X.");
        if (request.type === "PX_NEVER") { await ignoreOrigin(origin); forgetCandidate(tabId); }
        else {
          const state = await chrome.storage.local.get("ignoredOrigins");
          await chrome.storage.local.set({ ignoredOrigins: (Array.isArray(state.ignoredOrigins) ? state.ignoredOrigins : []).filter(value => value !== origin) });
        }
      }
      else if (request.type === "PX_FILL") await fillCredential(tabId, origin, request.id);
      const session = await restoreSession();
      sendResponse({ ok: true, connected: Boolean(session), email: session?.user.email, unlocked: vaults.length > 0, matches: origin ? matches(origin) : [], workspaces: vaults.filter(context => context.writable).map(context => ({ id: context.workspaceId, name: context.name })), ignored: Boolean(origin && await isIgnored(origin)), candidate: Number.isInteger(tabId) ? candidateSummary(tabId, origin) : null });
    } catch (error) { sendResponse({ ok: false, error: error instanceof Error ? error.message : "Passkey-X extension error." }); }
    finally { if (guarded) vaultOperationBusy = false; }
  })();
  return true;
});

chrome.runtime.onMessageExternal.addListener((message: unknown, sender, sendResponse) => {
  if (pairingBusy || vaultOperationBusy) { sendResponse({ ok: false, error: "Passkey-X is busy. Try again shortly." }); return false; }
  pairingBusy = true;
  void (async () => {
    try {
      const pending = (await chrome.storage.session.get(PAIRING_KEY))[PAIRING_KEY] as PendingPairing | undefined;
      if (!authorizedPairingMessage(message, sender, chrome.runtime.id, pending)) throw new Error("Connection request expired or is untrusted. Start again from the extension.");
      // Consume before authentication so concurrent messages/replays cannot reuse it.
      await chrome.storage.session.remove(PAIRING_KEY);
      const request = message as Record<string, string>;
      const { data: verified, error: verifyError } = await supabase.auth.getUser(request.accessToken);
      if (verifyError || !verified.user) throw new Error("The Passkey-X session is invalid.");
      const assurance = await supabase.auth.mfa.getAuthenticatorAssuranceLevel(request.accessToken);
      if (assurance.error || !assurance.data || (assurance.data.nextLevel === "aal2" && assurance.data.currentLevel !== "aal2")) throw new Error("Complete your account's second verification step before connecting.");
      clearVault();
      const { data, error } = await supabase.auth.setSession({ access_token: request.accessToken, refresh_token: request.refreshToken });
      if (error || !data.session || data.user?.id !== verified.user.id) { await disconnect().catch(() => {}); throw new Error("Unable to establish the Passkey-X session."); }
      locallyDisconnected = false;
      sendResponse({ ok: true, email: data.user.email ?? "" });
    } catch (error) { sendResponse({ ok: false, error: error instanceof Error ? error.message : "Unable to connect Passkey-X." }); }
    finally { pairingBusy = false; }
  })();
  return true;
});
supabase.auth.onAuthStateChange((event) => { if (event === "SIGNED_OUT") clearVault(); });
chrome.runtime.onSuspend.addListener(clearVault);
chrome.tabs.onRemoved.addListener(forgetCandidate);
chrome.tabs.onUpdated.addListener((tabId, change) => {
  const candidate = candidates.get(tabId);
  if (change.url && candidate && safeOrigin(change.url) !== candidate.origin) forgetCandidate(tabId);
  else if (change.status === "complete") void offerSave(tabId);
});
chrome.tabs.onActivated.addListener(({ tabId }) => void offerSave(tabId));
chrome.commands.onCommand.addListener((command) => {
  if (command !== "fill-login" || !vaults.length || vaultOperationBusy || pairingBusy) return;
  vaultOperationBusy = true;
  void (async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id === undefined || !tab.url) return;
      const origin = safeOrigin(tab.url); const credential = matches(origin)[0];
      if (origin && credential) await fillCredential(tab.id, origin, credential.id);
    } catch {
      // No secret/error details in logs. Open the popup for a visible retry.
    } finally { vaultOperationBusy = false; }
  })();
});
