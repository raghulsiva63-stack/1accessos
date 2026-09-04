import { argon2id } from "hash-wasm";

const encoder = new TextEncoder();

export type WrappedKey = {
  algorithm: "AES-256-GCM";
  nonce: string;
  ciphertext: string;
};

export type KdfProfile = {
  algorithm: "ARGON2ID";
  memoryKib: number;
  iterations: number;
  parallelism: number;
  hashLength: 32;
};

export const WEB_KDF_PROFILE: KdfProfile = {
  algorithm: "ARGON2ID",
  memoryKib: 65_536,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
};

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

export function randomBytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64Url(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function fromBase64Url(value: string) {
  const base64 = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

export function toPostgresBytea(bytes: Uint8Array) {
  return `\\x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  profile = WEB_KDF_PROFILE,
) {
  if (password.length < 12) {
    throw new Error("Use at least 12 characters for the vault password.");
  }
  const result = await argon2id({
    password: password.normalize("NFKC"),
    salt,
    parallelism: profile.parallelism,
    iterations: profile.iterations,
    memorySize: profile.memoryKib,
    hashLength: profile.hashLength,
    outputType: "binary",
  });
  return new Uint8Array(result);
}

export async function wrapKey(
  wrappingKey: Uint8Array,
  keyToWrap: Uint8Array,
  context: string,
): Promise<WrappedKey> {
  const nonce = randomBytes(12);
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(wrappingKey),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(nonce),
      additionalData: asArrayBuffer(encoder.encode(context)),
      tagLength: 128,
    },
    key,
    asArrayBuffer(keyToWrap),
  );
  return {
    algorithm: "AES-256-GCM",
    nonce: toBase64Url(nonce),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function unwrapKey(
  wrappingKey: Uint8Array,
  wrapped: WrappedKey,
  context: string,
) {
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(wrappingKey),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(fromBase64Url(wrapped.nonce)),
        additionalData: asArrayBuffer(encoder.encode(context)),
        tagLength: 128,
      },
      key,
      asArrayBuffer(fromBase64Url(wrapped.ciphertext)),
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("Vault password is incorrect or the key record was changed.");
  }
}

export function createRecoveryKey() {
  const secret = randomBytes(32);
  return { secret, display: `1A-RK1-${toBase64Url(secret)}` };
}

export async function createDeviceKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
  return {
    publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

export async function saveProtectedDeviceKey(ciphertext: WrappedKey) {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.open("oneaccessos-device", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys");
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const transaction = request.result.transaction("keys", "readwrite");
      transaction.objectStore("keys").put(ciphertext, "device-private-key");
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    };
  });
}

export function recoveryFile(recoveryKey: string) {
  return new Blob([
    JSON.stringify({
      product: "1accessos",
      version: 1,
      recovery_key: recoveryKey,
      warning: "Store offline. Anyone with this key may recover your vault.",
    }, null, 2),
  ], { type: "application/json" });
}
