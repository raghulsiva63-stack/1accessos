// "Unlock with Passkey-X desktop": talks to the desktop app through native messaging
// (host com.vlightsoft.passkeyx). Pairing uses an ECDH P-256 key agreement; both sides show
// the same 6-digit code and the person approves it in the desktop app. Only the derived
// AES-256-GCM key is kept (non-extractable, in this extension's IndexedDB). The desktop app
// answers unlock requests only for an approved pairing, only while it is unlocked, and only
// for the same account.

const HOST = "com.vlightsoft.passkeyx";
const DB = "passkey-x-desktop-link";
const STORE = "pairing";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Envelope = { nonce: string; ciphertext: string };
type Pairing = { id: string; key: CryptoKey; createdAt: string };
type Reply = Record<string, unknown> & { type?: string; id?: string };
export type DesktopState = { available: boolean; paired: boolean; pendingCode: string | null; unlocked: boolean | null };

function buffer(bytes: Uint8Array) { return Uint8Array.from(bytes).buffer; }
export function base64url(bytes: Uint8Array) {
  let binary = ""; bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
export function fromBase64url(value: string) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

/** Same derivation as apps/web/lib/desktop/browser-link.ts (pairingSecrets). */
export async function pairingSecrets(privateKey: CryptoKey, peerPublicKey: Uint8Array, pairingId: string) {
  if (peerPublicKey.length !== 65 || peerPublicKey[0] !== 4) throw new Error("The desktop app sent an invalid key.");
  const peer = await crypto.subtle.importKey("raw", buffer(peerPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey", "deriveBits"]);
  const salt = buffer(encoder.encode("passkey-x:browser-link:v1"));
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: buffer(encoder.encode(`aes:${pairingId}`)) },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const codeBits = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: buffer(encoder.encode(`code:${pairingId}`)) }, material, 32));
  const code = String(new DataView(codeBits.buffer).getUint32(0) % 1_000_000).padStart(6, "0");
  return { key, code };
}

export async function seal(key: CryptoKey, pairingId: string, type: string, value: unknown): Promise<Envelope> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  try {
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(`passkey-x:browser-link:v1:${pairingId}:${type}`)) }, key, buffer(plaintext)));
    return { nonce: base64url(nonce), ciphertext: base64url(ciphertext) };
  } finally { plaintext.fill(0); }
}

export async function open<T>(key: CryptoKey, pairingId: string, type: string, envelope: unknown): Promise<T> {
  const value = envelope as Partial<Envelope> | null;
  if (!value || typeof value.nonce !== "string" || typeof value.ciphertext !== "string") throw new Error("The desktop app sent an invalid reply.");
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(fromBase64url(value.nonce)), additionalData: buffer(encoder.encode(`passkey-x:browser-link:v1:${pairingId}:${type}`)) },
    key, buffer(fromBase64url(value.ciphertext))));
  try { return JSON.parse(decoder.decode(plaintext)) as T; } finally { plaintext.fill(0); }
}

// ---------------------------------------------------------------------------
// Pairing storage
// ---------------------------------------------------------------------------

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function store<T>(mode: IDBTransactionMode, action: (objects: IDBObjectStore) => IDBRequest): Promise<T> {
  const database = await db();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(STORE, mode);
      const request = action(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result as T);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}
async function loadPairing(): Promise<Pairing | null> {
  try { return (await store<Pairing | undefined>("readonly", (objects) => objects.get("current"))) ?? null; } catch { return null; }
}
const savePairing = (pairing: Pairing) => store("readwrite", (objects) => objects.put(pairing, "current"));
export const forgetPairing = () => store("readwrite", (objects) => objects.delete("current")).catch(() => undefined);

// ---------------------------------------------------------------------------
// Connection to the desktop app
// ---------------------------------------------------------------------------

let port: chrome.runtime.Port | null = null;
const waiting = new Map<string, { resolve: (reply: Reply) => void; timer: ReturnType<typeof setTimeout> }>();
const typeWaiters = new Map<string, (reply: Reply) => void>();
let pendingCode: string | null = null;
let onDesktopLocked: () => void = () => {};

export function whenDesktopLocks(callback: () => void) { onDesktopLocked = callback; }

async function permitted() {
  try { return await chrome.permissions.contains({ permissions: ["nativeMessaging"] }); } catch { return false; }
}

function connect(): chrome.runtime.Port {
  if (port) return port;
  const next = chrome.runtime.connectNative(HOST);
  next.onMessage.addListener((message: Reply) => {
    if (!message || typeof message !== "object") return;
    if (message.type === "locked") { onDesktopLocked(); return; }
    const id = typeof message.id === "string" ? message.id : "";
    const pending = id ? waiting.get(id) : undefined;
    if (pending) { clearTimeout(pending.timer); waiting.delete(id); pending.resolve(message); return; }
    const byType = typeof message.type === "string" ? typeWaiters.get(message.type) : undefined;
    if (byType) { typeWaiters.delete(message.type as string); byType(message); }
  });
  next.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    port = null;
    for (const [id, pending] of waiting) { clearTimeout(pending.timer); pending.resolve({ type: "error", id, error: "desktop_unavailable" }); }
    waiting.clear();
    pendingCode = null;
  });
  port = next;
  return next;
}

function request(message: Record<string, unknown>, timeoutMs = 8000): Promise<Reply> {
  const id = crypto.randomUUID();
  return new Promise((resolve) => {
    const timer = setTimeout(() => { waiting.delete(id); resolve({ type: "error", id, error: "timeout" }); }, timeoutMs);
    waiting.set(id, { resolve, timer });
    try { connect().postMessage({ ...message, id }); }
    catch { clearTimeout(timer); waiting.delete(id); resolve({ type: "error", id, error: "desktop_unavailable" }); }
  });
}

function explain(error: unknown) {
  switch (error) {
    case "desktop_unavailable": case "timeout": return "Passkey-X desktop isn't running. Open it and try again.";
    case "browser_integration_off": return "Turn on Browser extension in Passkey-X desktop › Settings › This computer.";
    case "desktop_locked": return "Unlock Passkey-X desktop first.";
    case "different_account": return "Passkey-X desktop is signed in to a different account.";
    case "not_paired": return "This browser is no longer paired. Pair it again.";
    default: return "Passkey-X desktop couldn't complete the request.";
  }
}

export async function desktopState(): Promise<DesktopState> {
  const pairing = await loadPairing();
  if (!(await permitted())) return { available: false, paired: Boolean(pairing), pendingCode: null, unlocked: null };
  return { available: true, paired: Boolean(pairing), pendingCode, unlocked: null };
}

/**
 * Starts pairing; resolves with the code to compare once the desktop app shows its prompt.
 * `finished` resolves when the person approves or denies it in the app (up to two minutes).
 */
export async function startPairing(browser: string): Promise<{ code: string; finished: Promise<boolean> }> {
  if (!(await permitted())) throw new Error("Allow Passkey-X to talk to the desktop app first.");
  const keys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]) as CryptoKeyPair;
  const pairingId = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const publicKey = base64url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
  const result = new Promise<Reply>((resolve) => {
    typeWaiters.set("pair-result", resolve);
    setTimeout(() => { if (typeWaiters.get("pair-result") === resolve) { typeWaiters.delete("pair-result"); resolve({ type: "pair-result", ok: false }); } }, 125_000);
  });
  const started = await request({ type: "pair", pairingId, publicKey, browser });
  if (started.type !== "pair-started" || typeof started.publicKey !== "string") {
    typeWaiters.delete("pair-result");
    throw new Error(explain(started.error));
  }
  const { key, code } = await pairingSecrets(keys.privateKey, fromBase64url(started.publicKey), pairingId);
  pendingCode = code;
  const finished = result.then(async (reply) => {
    pendingCode = null;
    if (reply.ok !== true) return false;
    await savePairing({ id: pairingId, key, createdAt: new Date().toISOString() });
    return true;
  });
  return { code, finished };
}

/** Asks the unlocked desktop app for this account's root key. The caller zeroes it after use. */
export async function rootKeyFromDesktop(identityId: string): Promise<Uint8Array> {
  const pairing = await loadPairing();
  if (!pairing) throw new Error("Pair this browser with Passkey-X desktop first.");
  if (!(await permitted())) throw new Error("Allow Passkey-X to talk to the desktop app first.");
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const reply = await request({ type: "unlock", pairingId: pairing.id, payload: await seal(pairing.key, pairing.id, "unlock", { identityId, nonce }) });
  if (reply.type !== "unlock-result" || reply.ok !== true) {
    if (reply.error === "not_paired") await forgetPairing();
    throw new Error(explain(reply.error));
  }
  const answer = await open<{ identityId?: string; root?: string; nonce?: string }>(pairing.key, pairing.id, "unlock-result", reply.payload);
  if (answer.identityId !== identityId || answer.nonce !== nonce || typeof answer.root !== "string") throw new Error("Passkey-X desktop sent an unexpected reply.");
  const root = fromBase64url(answer.root);
  answer.root = "";
  if (root.length !== 32) { root.fill(0); throw new Error("Passkey-X desktop sent an unexpected reply."); }
  return root;
}
