# Cryptographic Envelope Contract

Status: Phase 0 reference contract; independent review required before production.

## Principles

- The login password and vault master password are distinct.
- The master password never leaves the trusted client.
- Every algorithm and parameter set is versioned.
- One item key encrypts one immutable item revision.
- Associated data binds ciphertext to its tenant, workspace, item, revision, content type, and key version.

## Key hierarchy

1. `master_key` is derived client-side from the vault master password using Argon2id and a random account salt.
2. `account_root_key` is random and wrapped by `master_key`.
3. Each trusted device owns an asymmetric wrapping keypair; its private key is locally protected.
4. Each workspace has a random `workspace_key`, wrapped for authorized identities/devices.
5. Each item revision has a random `item_key`, wrapped by its workspace key.
6. Attachments use independent random keys and chunk nonces.
7. The downloadable recovery key wraps the account root key and is never uploaded in plaintext.

## Version 1 envelope

```json
{
  "envelope_version": 1,
  "algorithm": "XCHACHA20-POLY1305",
  "key_version": 1,
  "nonce": "base64url-no-padding",
  "ciphertext": "base64url-no-padding",
  "aad": {
    "tenant_id": "uuid",
    "workspace_id": "uuid",
    "item_id": "uuid",
    "revision": 1,
    "content_type": "com.1accessos.login",
    "schema_version": 1
  }
}
```

AAD is canonically encoded, not trusted from the stored JSON alone, and reconstructed from immutable database fields before decryption.

## KDF profile

Argon2id parameters are stored with the wrapped account-root-key record. Initial production parameters will be calibrated on supported clients and must meet the independent review gate. Tests use deliberately reduced parameters and synthetic secrets only.

## Failure behavior

- Unsupported versions fail closed.
- Authentication failure returns a generic decrypt error.
- Nonce length, key length, and canonical encoding are validated before use.
- A key/nonce pair is never reused.
- Decrypted buffers are released promptly; clients avoid persistent plaintext caches.

## Recovery

The client generates a high-entropy recovery secret and displays/downloads it once. A recovery wrapping key derived from that secret unwraps the account root key. The server stores only the wrapped account root key and KDF metadata. Losing both the master password and recovery key makes recovery impossible by design.
