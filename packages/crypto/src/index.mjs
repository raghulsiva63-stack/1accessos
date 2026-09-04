import { argon2Sync, randomBytes, webcrypto } from 'node:crypto';

const cryptoApi = globalThis.crypto ?? webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const ENVELOPE_VERSION = 1;
export const ALGORITHM = 'AES-256-GCM';
export const KDF = 'ARGON2ID';

export const TEST_KDF_PROFILE = Object.freeze({
  memoryKib: 8192,
  passes: 1,
  parallelism: 1,
  tagLength: 32
});

export const REFERENCE_KDF_PROFILE = Object.freeze({
  memoryKib: 65536,
  passes: 3,
  parallelism: 1,
  tagLength: 32
});

function assertBytes(value, length, name) {
  if (!(value instanceof Uint8Array) || (length && value.byteLength !== length)) {
    throw new TypeError(`${name} must be a ${length ?? 'valid'}-byte Uint8Array`);
  }
}

export function base64urlEncode(value) {
  assertBytes(value, undefined, 'value');
  return Buffer.from(value).toString('base64url');
}

export function base64urlDecode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new TypeError('invalid base64url value');
  }
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function canonicalAad(aad) {
  const keys = ['tenant_id', 'workspace_id', 'item_id', 'revision', 'content_type', 'schema_version'];
  if (!aad || typeof aad !== 'object' || keys.some((key) => !(key in aad))) {
    throw new TypeError('AAD is incomplete');
  }
  const ordered = Object.fromEntries(keys.map((key) => [key, aad[key]]));
  if (!Number.isSafeInteger(ordered.revision) || ordered.revision < 1) throw new TypeError('invalid revision');
  if (!Number.isSafeInteger(ordered.schema_version) || ordered.schema_version < 1) throw new TypeError('invalid schema version');
  for (const key of ['tenant_id', 'workspace_id', 'item_id', 'content_type']) {
    if (typeof ordered[key] !== 'string' || ordered[key].length === 0) throw new TypeError(`invalid ${key}`);
  }
  return encoder.encode(JSON.stringify(ordered));
}

export function deriveMasterKey(masterPassword, salt, profile = REFERENCE_KDF_PROFILE) {
  if (typeof masterPassword !== 'string' || masterPassword.length < 12) {
    throw new TypeError('master password must contain at least 12 characters');
  }
  assertBytes(salt, 16, 'salt');
  return new Uint8Array(argon2Sync('argon2id', {
    message: encoder.encode(masterPassword.normalize('NFKC')),
    nonce: salt,
    parallelism: profile.parallelism,
    tagLength: profile.tagLength,
    memory: profile.memoryKib,
    passes: profile.passes,
    associatedData: encoder.encode('1accessos:master-key:v1')
  }));
}

export function generateKey() {
  return new Uint8Array(randomBytes(32));
}

export function generateSalt() {
  return new Uint8Array(randomBytes(16));
}

export async function encryptEnvelope(keyBytes, plaintext, aad, nonce = new Uint8Array(randomBytes(12))) {
  assertBytes(keyBytes, 32, 'key');
  assertBytes(nonce, 12, 'nonce');
  if (!(plaintext instanceof Uint8Array)) throw new TypeError('plaintext must be a Uint8Array');
  const key = await cryptoApi.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const ciphertext = await cryptoApi.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: canonicalAad(aad), tagLength: 128 },
    key,
    plaintext
  );
  return {
    envelope_version: ENVELOPE_VERSION,
    algorithm: ALGORITHM,
    key_version: 1,
    nonce: base64urlEncode(nonce),
    ciphertext: base64urlEncode(new Uint8Array(ciphertext)),
    aad
  };
}

export async function decryptEnvelope(keyBytes, envelope) {
  assertBytes(keyBytes, 32, 'key');
  if (envelope?.envelope_version !== ENVELOPE_VERSION || envelope?.algorithm !== ALGORITHM) {
    throw new Error('unsupported envelope');
  }
  const nonce = base64urlDecode(envelope.nonce);
  assertBytes(nonce, 12, 'nonce');
  const key = await cryptoApi.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  try {
    const plaintext = await cryptoApi.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: canonicalAad(envelope.aad), tagLength: 128 },
      key,
      base64urlDecode(envelope.ciphertext)
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error('decryption failed');
  }
}

export function encodeJson(value) {
  return encoder.encode(JSON.stringify(value));
}

export function decodeJson(value) {
  return JSON.parse(decoder.decode(value));
}

