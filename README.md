# 1accessos

Zero-knowledge credential and access management platform.

> **Phase 0 status:** security architecture and implementation contracts are in progress. This repository is not ready to store production secrets.

## Confirmed product decisions

- Supabase is the centralized development control plane.
- Vault payloads are encrypted and decrypted only by trusted clients.
- Supabase stores ciphertext envelopes and non-secret control metadata.
- Account authentication and vault unlocking are separate security boundaries.
- Recovery uses a downloadable recovery key; administrators cannot decrypt or reset a user's vault.
- The web application is the first client.
- Chrome and Edge extensions follow in Phase 1.
- The current Supabase project is development-only. Production will use a separate project before beta.

## Security invariants

1. Login credentials and vault master passwords must be different.
2. Plaintext vault secrets must never reach the API, database, storage, logs, telemetry, or analytics.
3. Service-role and secret keys must never be included in public clients.
4. Every tenant-scoped operation must enforce identity, tenant, workspace, and membership authorization.
5. Every exposed database table must use Row Level Security and explicit grants.
6. Cryptographic formats are versioned and use established, reviewed primitives.
7. Recovery is zero-knowledge and cannot be performed by an administrator.
8. Destructive and replayable mutations require auditability and idempotency controls.

## Phase 0 workstreams

- Architecture Decision Records
- Threat model and trust boundaries
- Cryptographic envelope and key hierarchy
- Identity, tenant, workspace, and device model
- Supabase schema and RLS authorization matrix
- Encrypted sync, revisions, conflicts, and tombstones
- REST API and OpenAPI 3.1 contract
- Security and acceptance test matrix
- CI quality and secret-leak gates

## Repository layout

```text
apps/                 Product clients and API façade
packages/             Shared crypto, schemas, and API client packages
supabase/             Migrations, functions, tests, and local configuration
docs/architecture/    Architecture records and trust model
docs/security/        Threat model, crypto specification, and test matrix
docs/api/             REST/OpenAPI contract
.github/workflows/    Automated quality and security checks
```

## Development safety

- Use synthetic secrets only.
- Never commit environment files, database passwords, service-role keys, recovery keys, or real credentials.
- All package versions and lockfiles will be pinned.
- Database migrations require RLS tests and Supabase advisor checks before acceptance.
