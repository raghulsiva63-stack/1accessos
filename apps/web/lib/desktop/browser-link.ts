/**
 * Desktop side of "Unlock the browser extension with Passkey-X desktop".
 *
 * The extension reaches this app through native messaging (relayed by the app, see
 * apps/desktop/src-tauri/src/browser_link.rs). Before anything is shared, the extension and this
 * app pair: both create P-256 keys, agree a secret (ECDH + HKDF-SHA-256) and show the same
 * 6-digit code, which the person compares and approves here. After that, while this app is
 * unlocked, a paired extension can ask for the account key of the same account, encrypted
 * (AES-256-GCM) to that pairing only. Pairings are kept in the app's encrypted store and can be
 * removed in Settings › This computer.
 */
import { desktop, isDesktopApp } from "@/lib/desktop/bridge";
import { fromBase64Url, toBase64Url } from "@/lib/crypto/vault";

const RECORD = "px-browser-pairings";
const MAX_PAIRINGS = 10;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/u;
const ORIGIN_PATTERN = /^chrome-extension:\/\/[a-p]{32}\/$/u;

export type BrowserPairing = {
  id: string;
  origin: string;
  browser: string;
  extensionPublicKey: string;
  desktopPublicKey: string;
  desktopPrivateKey: JsonWebKey;
  createdAt: string;
  lastUsedAt: string | null;
};

export type PairingRequest = { connection: number; origin: string; browser: string; code: string; expiresAt: number };

type Envelope = { nonce: string; ciphertext: string };
type Incoming = { connection: number; origin: string; message: Record<string, unknown> };

function buffer(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }

// ---------------------------------------------------------------------------
// Crypto (shared with the extension; keep both sides identical)
// ---------------------------------------------------------------------------

export async function pairingSecrets(privateKey: CryptoKey, peerPublicKey: Uint8Array, pairingId: string) {
  if (peerPublicKey.length !== 65 || peerPublicKey[0] !== 4) throw new Error("invalid_public_key");
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

export async function sealLinkMessage(key: CryptoKey, pairingId: string, type: string, value: unknown): Promise<Envelope> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  try {
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(`passkey-x:browser-link:v1:${pairingId}:${type}`)) }, key, buffer(plaintext)));
    return { nonce: toBase64Url(nonce), ciphertext: toBase64Url(ciphertext) };
  } finally { plaintext.fill(0); }
}

export async function openLinkMessage<T>(key: CryptoKey, pairingId: string, type: string, envelope: unknown): Promise<T> {
  const value = envelope as Partial<Envelope> | null;
  if (!value || typeof value.nonce !== "string" || typeof value.ciphertext !== "string" || value.ciphertext.length > 8192) throw new Error("invalid_message");
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(fromBase64Url(value.nonce)), additionalData: buffer(encoder.encode(`passkey-x:browser-link:v1:${pairingId}:${type}`)) },
    key, buffer(fromBase64Url(value.ciphertext))));
  try { return JSON.parse(decoder.decode(plaintext)) as T; } finally { plaintext.fill(0); }
}

// ---------------------------------------------------------------------------
// Pairings store
// ---------------------------------------------------------------------------

export async function listPairings(): Promise<BrowserPairing[]> {
  try {
    const raw = await desktop.record.get(RECORD);
    const parsed = raw ? JSON.parse(raw) as unknown : [];
    return Array.isArray(parsed) ? parsed.filter((entry): entry is BrowserPairing => Boolean(entry) && typeof entry === "object" && ID_PATTERN.test((entry as BrowserPairing).id)) : [];
  } catch { return []; }
}

async function savePairings(pairings: BrowserPairing[]) {
  await desktop.record.set(RECORD, JSON.stringify(pairings.slice(-MAX_PAIRINGS)));
  notify();
}

export async function removePairing(id: string) {
  await savePairings((await listPairings()).filter((pairing) => pairing.id !== id));
}

export async function removeAllPairings() {
  await desktop.record.remove(RECORD).catch(() => undefined);
  notify();
}

export function browserName(origin: string, hint: unknown) {
  const name = typeof hint === "string" ? hint.trim().slice(0, 40) : "";
  return /^[A-Za-z0-9 ._-]{2,40}$/u.test(name) ? name : origin.slice(19, 27);
}

// ---------------------------------------------------------------------------
// Live state (for the approval dialog and settings)
// ---------------------------------------------------------------------------

type Pending = PairingRequest & { id: string; extensionPublicKey: string; keys: CryptoKeyPair; desktopPublicKey: string };
let pending: Pending | null = null;
let vault: { identityId: string; rootKey: Uint8Array } | null = null;
const connections = new Set<number>();
const subscribers = new Set<() => void>();
let version = 0;

function notify() { version += 1; for (const subscriber of subscribers) subscriber(); }
export function subscribeBrowserLink(callback: () => void) { subscribers.add(callback); return () => { subscribers.delete(callback); }; }
export function browserLinkVersion() { return version; }
export function pendingPairing(): PairingRequest | null {
  if (pending && pending.expiresAt <= Date.now()) pending = null;
  return pending ? { connection: pending.connection, origin: pending.origin, browser: pending.browser, code: pending.code, expiresAt: pending.expiresAt } : null;
}

async function send(connection: number, message: Record<string, unknown>) {
  try { await desktop.browserLinkSend(connection, message); } catch { connections.delete(connection); }
}

/** Called by the unlocked vault (and with null when it locks). Locking also locks paired extensions. */
export function setBrowserLinkVault(next: { identityId: string; rootKey: Uint8Array } | null) {
  const wasUnlocked = Boolean(vault);
  vault = next;
  if (wasUnlocked && !next) for (const connection of connections) void send(connection, { type: "locked" });
}

export async function answerPairing(approve: boolean) {
  const request = pending;
  pending = null;
  notify();
  if (!request) return;
  if (!approve || request.expiresAt <= Date.now()) {
    await send(request.connection, { type: "pair-result", ok: false });
    return;
  }
  const pairings = (await listPairings()).filter((pairing) => pairing.id !== request.id);
  pairings.push({
    id: request.id, origin: request.origin, browser: request.browser, extensionPublicKey: request.extensionPublicKey,
    desktopPublicKey: request.desktopPublicKey, desktopPrivateKey: await crypto.subtle.exportKey("jwk", request.keys.privateKey),
    createdAt: new Date().toISOString(), lastUsedAt: null,
  });
  await savePairings(pairings);
  await send(request.connection, { type: "pair-result", ok: true });
}

async function pairingKey(pairing: BrowserPairing) {
  const privateKey = await crypto.subtle.importKey("jwk", pairing.desktopPrivateKey, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return (await pairingSecrets(privateKey, fromBase64Url(pairing.extensionPublicKey), pairing.id)).key;
}

async function handle({ connection, origin, message }: Incoming) {
  if (!ORIGIN_PATTERN.test(origin)) return;
  const type = typeof message.type === "string" ? message.type : "";
  const requestId = typeof message.id === "string" ? message.id.slice(0, 64) : null;
  if (type === "disconnected") { connections.delete(connection); return; }
  connections.add(connection);
  const settings = await desktop.settings().catch(() => null);
  if (!settings?.browserIntegration) { await send(connection, { type: "error", id: requestId, error: "browser_integration_off" }); return; }
  const pairingId = typeof message.pairingId === "string" && ID_PATTERN.test(message.pairingId) ? message.pairingId : "";
  const pairing = pairingId ? (await listPairings()).find((entry) => entry.id === pairingId && entry.origin === origin) : undefined;

  if (type === "hello") {
    await send(connection, { type: "hello", id: requestId, paired: Boolean(pairing), unlocked: Boolean(vault) });
    return;
  }

  if (type === "pair") {
    const publicKey = typeof message.publicKey === "string" ? message.publicKey : "";
    if (!pairingId || !/^[A-Za-z0-9_-]{87}$/u.test(publicKey)) { await send(connection, { type: "pair-result", id: requestId, ok: false }); return; }
    if (pending) await send(pending.connection, { type: "pair-result", ok: false });
    const keys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const desktopPublicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
    const { code } = await pairingSecrets(keys.privateKey, fromBase64Url(publicKey), pairingId);
    pending = { connection, origin, browser: browserName(origin, message.browser), code, expiresAt: Date.now() + 120_000, id: pairingId, extensionPublicKey: publicKey, keys, desktopPublicKey };
    notify();
    // The extension shows the same code; the person approves here after comparing them.
    await send(connection, { type: "pair-started", id: requestId, publicKey: desktopPublicKey });
    setTimeout(() => { if (pending?.id === pairingId && pending.expiresAt <= Date.now()) void answerPairing(false); }, 121_000);
    return;
  }

  if (type === "unlock") {
    if (!pairing) { await send(connection, { type: "unlock-result", id: requestId, ok: false, error: "not_paired" }); return; }
    const key = await pairingKey(pairing);
    let request: { identityId?: string; nonce?: string };
    try { request = await openLinkMessage(key, pairing.id, "unlock", message.payload); }
    catch { await send(connection, { type: "unlock-result", id: requestId, ok: false, error: "not_paired" }); return; }
    if (!vault) { await send(connection, { type: "unlock-result", id: requestId, ok: false, error: "desktop_locked" }); return; }
    if (request.identityId !== vault.identityId) { await send(connection, { type: "unlock-result", id: requestId, ok: false, error: "different_account" }); return; }
    const nonce = typeof request.nonce === "string" ? request.nonce.slice(0, 64) : "";
    const root = toBase64Url(vault.rootKey);
    const payload = await sealLinkMessage(key, pairing.id, "unlock-result", { identityId: vault.identityId, root, nonce });
    await send(connection, { type: "unlock-result", id: requestId, ok: true, payload });
    await savePairings((await listPairings()).map((entry) => entry.id === pairing.id ? { ...entry, lastUsedAt: new Date().toISOString() } : entry));
    return;
  }

  await send(connection, { type: "error", id: requestId, error: "unsupported" });
}

let installed = false;
/** Starts answering the browser extension (desktop app only; once). */
export function installBrowserLinkHost() {
  if (installed || !isDesktopApp()) return;
  installed = true;
  window.addEventListener("passkey-x:browser-link", (event) => {
    const detail = (event as CustomEvent<Incoming>).detail;
    if (!detail || typeof detail.connection !== "number" || typeof detail.origin !== "string" || !detail.message || typeof detail.message !== "object") return;
    void handle(detail).catch(() => undefined);
  });
}
