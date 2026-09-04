import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TEST_KDF_PROFILE,
  base64urlDecode,
  base64urlEncode,
  decryptEnvelope,
  deriveMasterKey,
  encodeJson,
  decodeJson,
  encryptEnvelope,
  generateKey
} from '../src/index.mjs';

const aad = Object.freeze({
  tenant_id: '00000000-0000-4000-8000-000000000001',
  workspace_id: '00000000-0000-4000-8000-000000000002',
  item_id: '00000000-0000-4000-8000-000000000003',
  revision: 1,
  content_type: 'com.1accessos.login',
  schema_version: 1
});

test('round-trips a structured secret', async () => {
  const key = generateKey();
  const secret = { username: 'synthetic@example.invalid', password: 'synthetic-only' };
  const envelope = await encryptEnvelope(key, encodeJson(secret), aad);
  assert.deepEqual(decodeJson(await decryptEnvelope(key, envelope)), secret);
});

test('rejects ciphertext tampering', async () => {
  const key = generateKey();
  const envelope = await encryptEnvelope(key, encodeJson({ value: 'synthetic' }), aad);
  const bytes = base64urlDecode(envelope.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decryptEnvelope(key, { ...envelope, ciphertext: base64urlEncode(bytes) }), /decryption failed/);
});

test('rejects AAD substitution', async () => {
  const key = generateKey();
  const envelope = await encryptEnvelope(key, encodeJson({ value: 'synthetic' }), aad);
  await assert.rejects(
    decryptEnvelope(key, { ...envelope, aad: { ...aad, item_id: '00000000-0000-4000-8000-000000000099' } }),
    /decryption failed/
  );
});

test('Argon2id derivation is deterministic and salt-bound', () => {
  const saltA = new Uint8Array(16).fill(1);
  const saltB = new Uint8Array(16).fill(2);
  const first = deriveMasterKey('synthetic master phrase', saltA, TEST_KDF_PROFILE);
  const second = deriveMasterKey('synthetic master phrase', saltA, TEST_KDF_PROFILE);
  const other = deriveMasterKey('synthetic master phrase', saltB, TEST_KDF_PROFILE);
  assert.deepEqual(first, second);
  assert.notDeepEqual(first, other);
});

