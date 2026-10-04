/**
 * Offline vault access for the desktop app.
 *
 * After each successful sync the app keeps a copy of what the server returned, in the app's own
 * IndexedDB (inside the app's data folder):
 * * the account's crypto profile (salt and wrapped key; the same public-to-the-account data the
 *   server stores), so the vault password can unlock without internet;
 * * workspace rows and key envelopes, encrypted with a key derived from the account root key;
 * * item ciphertext (already encrypted under each workspace key), encrypted again with a key
 *   derived from that workspace key, so even item IDs and counts stay private.
 * Nothing is ever stored in plaintext. Without internet the vault opens read-only from this copy.
 * Organizations can turn this off (policy "offlineAccess"); turning it off deletes the copy.
 */

const DB = "passkey-x-offline";
const STORE = "records";
const VERSION = 1;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type OfflineProfile<T> = { userId: string; email: string; profile: T; savedAt: string };

function idb(): IDBFactory | null {
  return typeof indexedDB === "undefined" ? null : indexedDB;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const factory = idb();
    if (!factory) { reject(new Error("offline_unavailable")); return; }
    const request = factory.open(DB, VERSION);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("offline_unavailable"));
  });
}

async function run<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = action(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error ?? new Error("offline_unavailable"));
      transaction.onabort = () => reject(transaction.error ?? new Error("offline_unavailable"));
    });
  } finally { db.close(); }
}

const read = <T>(key: string) => run<T | undefined>("readonly", (store) => store.get(key) as IDBRequest<T | undefined>);
const write = (key: string, value: unknown) => run("readwrite", (store) => store.put(value, key));

function buffer(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }

async function cacheKey(secret: Uint8Array, context: string) {
  const material = await crypto.subtle.importKey("raw", buffer(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buffer(encoder.encode("passkey-x:offline-cache:v1")), info: buffer(encoder.encode(context)) },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

type Sealed = { nonce: Uint8Array; ciphertext: Uint8Array; savedAt: string };

async function sealJson(secret: Uint8Array, context: string, value: unknown): Promise<Sealed> {
  const key = await cacheKey(secret, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(encoder.encode(context)) }, key,
    buffer(encoder.encode(JSON.stringify(value)))));
  return { nonce, ciphertext, savedAt: new Date().toISOString() };
}

async function openJson<T>(secret: Uint8Array, context: string, sealed: Sealed | undefined): Promise<T | null> {
  if (!sealed?.nonce || !sealed.ciphertext) return null;
  try {
    const key = await cacheKey(secret, context);
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(sealed.nonce), additionalData: buffer(encoder.encode(context)) }, key, buffer(sealed.ciphertext)));
    try { return JSON.parse(decoder.decode(plaintext)) as T; } finally { plaintext.fill(0); }
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// When is the cache used
// ---------------------------------------------------------------------------

let enabled = false;
let ready: Promise<void> = Promise.resolve();
let offline = false;
const listeners = new Set<(value: boolean) => void>();

/**
 * Turned on by the desktop app when the person (and their organization) allow offline access.
 * Accepts the pending setting so early loads wait for it. Turning it off deletes the copy.
 */
export function configureOfflineCache(value: boolean | Promise<boolean>) {
  ready = Promise.resolve(value).then((next) => {
    enabled = next;
    if (!next) return clearOfflineCache();
  }, () => { enabled = false; });
  return ready;
}
export async function offlineCacheEnabled() { await ready; return enabled; }

/** True while the vault is showing the saved copy because the server could not be reached. */
export function isOffline() { return offline; }
export function onOfflineChange(listener: (value: boolean) => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
function setOffline(value: boolean) {
  if (offline === value) return;
  offline = value;
  for (const listener of listeners) listener(value);
}
export function markOnline() { setOffline(false); }

/** A failure caused by having no connection (as opposed to the server refusing). */
export function isNetworkError(reason: unknown) {
  if (typeof navigator !== "undefined" && navigator.onLine === false) return true;
  const message = reason && typeof reason === "object" && "message" in reason ? String((reason as { message: unknown }).message) : String(reason ?? "");
  return /failed to fetch|networkerror|network request failed|load failed|fetch failed|err_internet_disconnected|err_network/iu.test(message);
}

/** Checks whether the Passkey-X servers can be reached (any HTTP answer counts as online). */
export async function serverReachable(url: string, timeoutMs = 4000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { await fetch(url, { method: "GET", cache: "no-store", signal: controller.signal }); return true; }
  catch { return false; }
  finally { clearTimeout(timer); }
}

/**
 * Runs `load` against the server; on success saves the result, on a connection failure falls back
 * to the saved copy (and reports offline). Other errors are passed through unchanged.
 */
export async function withOfflineCopy<T>(load: () => Promise<T>, save: (value: T) => Promise<void>, restore: () => Promise<T | null>): Promise<T> {
  await ready;
  try {
    const value = await load();
    setOffline(false);
    if (enabled) await save(value).catch(() => undefined);
    return value;
  } catch (reason) {
    if (!enabled || !isNetworkError(reason)) throw reason;
    const saved = await restore().catch(() => null);
    if (saved === null) throw reason;
    setOffline(true);
    return saved;
  }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

export async function saveOfflineProfile<T>(userId: string, email: string, profile: T) {
  await ready;
  if (!enabled) return;
  await write(`profile:${userId}`, { userId, email, profile, savedAt: new Date().toISOString() } satisfies OfflineProfile<T>).catch(() => undefined);
  await write("last-user", userId).catch(() => undefined);
}

/** The profile of the last account that used this computer, for unlocking without internet. */
export async function lastOfflineProfile<T>(): Promise<OfflineProfile<T> | null> {
  try {
    const userId = await read<string>("last-user");
    return userId ? (await read<OfflineProfile<T>>(`profile:${userId}`)) ?? null : null;
  } catch { return null; }
}

export async function saveWorkspaceRows(identityId: string, rootKey: Uint8Array, rows: unknown) {
  const context = `workspaces:${identityId}`;
  await write(context, await sealJson(rootKey, context, rows));
}

export async function loadWorkspaceRows<T>(identityId: string, rootKey: Uint8Array): Promise<T | null> {
  const context = `workspaces:${identityId}`;
  return openJson<T>(rootKey, context, await read<Sealed>(context));
}

export async function saveItemRows(workspaceId: string, workspaceKey: Uint8Array, trash: boolean, rows: unknown) {
  const context = `items:${workspaceId}:${trash ? "trash" : "active"}`;
  await write(context, await sealJson(workspaceKey, context, rows));
}

export async function loadItemRows<T>(workspaceId: string, workspaceKey: Uint8Array, trash: boolean): Promise<T | null> {
  const context = `items:${workspaceId}:${trash ? "trash" : "active"}`;
  return openJson<T>(workspaceKey, context, await read<Sealed>(context));
}

/** Deletes every saved copy (sign-out, policy change, or offline access turned off). */
export async function clearOfflineCache() {
  const factory = idb();
  if (!factory) return;
  await new Promise<void>((resolve) => {
    const request = factory.deleteDatabase(DB);
    request.onsuccess = request.onerror = request.onblocked = () => resolve();
  });
}
