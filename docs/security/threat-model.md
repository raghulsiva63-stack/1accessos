# 1accessos Phase 0 Threat Model

Status: Draft for implementation validation  
Date: 2026-09-04

## Security objective

An attacker who obtains the database, object storage, API logs, backups, or ordinary administrator access must not be able to recover vault plaintext. Authorized clients decrypt locally after account authentication and vault unlock.

## Trust boundaries

1. **Trusted client runtime:** performs key derivation, encryption, decryption, local search, and display.
2. **Supabase Auth:** authenticates an account; it never receives the vault master password or root key.
3. **REST control plane:** validates identity, authorization, versions, quotas, and idempotency; it accepts ciphertext only.
4. **Postgres and Storage:** hold control metadata and versioned encrypted objects.
5. **Operations:** can deploy and administer infrastructure but cannot decrypt user vaults.

## Protected assets

- Vault plaintext and encrypted attachments
- Master-derived account root keys
- Device private keys and recovery keys
- Workspace and item keys
- Sessions, personal access tokens, and connector credentials
- Tenant membership, audit integrity, and availability

## Threats and required controls

| ID | Threat | Required controls | Verification |
|---|---|---|---|
| T01 | Database or backup theft | AEAD ciphertext; password-hardening KDF; no plaintext columns | Dump/schema inspection and known-plaintext scan |
| T02 | Service compromise | Server never receives decrypting keys; log redaction | API contract tests and log canaries |
| T03 | Cross-tenant IDOR/BOLA | Mandatory tenant/workspace predicates and RLS | Negative tests with two tenants |
| T04 | Malicious administrator | Zero-knowledge design; append-only audit trail | Recovery/admin tests cannot decrypt |
| T05 | Stolen device | Local lock, wrapped device key, revocation, short sessions | Revoked-device and locked-client tests |
| T06 | Offline master-password guessing | Argon2id with versioned parameters and unique salt | KDF test vectors and performance calibration |
| T07 | Ciphertext tampering/substitution | AEAD and canonical associated data binding identity/version | Mutation and item-swap tests fail closed |
| T08 | Replay or lost update | Item version, idempotency keys, expected-version checks | Duplicate and stale-write tests |
| T09 | Token database theft | Store only token prefix and cryptographic hash | Database inspection; token shown once |
| T10 | Membership revocation delay | Database membership lookup for sensitive actions; key rotation | Revocation test with stale JWT |
| T11 | Dependency compromise | Pinned dependencies, lockfile, audit, SBOM, review | CI dependency and provenance gates |
| T12 | Browser injection | CSP, Trusted Types where supported, no secret telemetry | E2E CSP tests and sink review |
| T13 | Clipboard/screenshot leakage | Timed clearing and explicit reveal UX | Client behavior tests |
| T14 | Attachment disclosure | Client encryption before private-bucket upload | Storage inspection and policy tests |
| T15 | Recovery abuse | Recovery key generated client-side; no admin escrow | Recovery flow and negative admin test |

## Explicit non-goals for Phase 0

- Protection after an authorized user deliberately reveals or exports plaintext
- Protection from a fully compromised client OS while the vault is unlocked
- Enterprise SSO, SCIM, PAM relays, and regional residency

## Release blockers

Production data is prohibited until T01-T12 controls have executable tests, an independent cryptographic design review is complete, and tenant-isolation testing passes.
