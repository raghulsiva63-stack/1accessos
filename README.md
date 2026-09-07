# Passkey-X

Passkey-X by Vlightsoft is a zero-knowledge password, passkey, credential, and
recovery vault. This repository contains the hosted web client, Chromium
extension, Tauri desktop shell, shared cryptography reference, Supabase
migrations/tests, and the ciphertext-only API contract.

> **Release status:** Phase 0 engineering controls, the Phase 1 product build,
> and the Phase 2 collaboration implementation are present in the development environment. Production use remains blocked
> until the independent cryptographic review, external penetration test, final
> Auth configuration, and signed release gates are complete.

## Security invariants

1. Login credentials and the vault master password are separate.
2. Plaintext vault secrets never reach Supabase, Storage, logs, telemetry, ads, or analytics.
3. Service-role and secret keys never appear in public clients.
4. Every tenant-scoped operation enforces identity, tenant, workspace, and membership authorization.
5. Every exposed table uses Row Level Security and explicit grants.
6. Cryptographic formats are versioned and use reviewed standard primitives.
7. Recovery is user-controlled; administrators cannot decrypt or reset a vault.
8. Sponsor cards are first-party, Home-only, and never targeted from vault content.

## Clients

- `apps/web` — responsive Next.js static client for Netlify.
- `apps/extension` — Manifest V3 Chrome/Edge explicit save-and-fill client.
- `apps/desktop` — Tauri 2 wrapper around the same static web client.
- `apps/cli` — ciphertext-only Phase 2 workspace, Mission, request, and grant client.
- `packages/crypto` — Node reference implementation and compatibility tests.

## Development checks

```text
npm run check
npm --prefix apps/web ci
npm --prefix apps/web test
npm --prefix apps/web run lint
npm --prefix apps/extension ci
npm --prefix apps/extension test
npm --prefix apps/cli test
```

Only synthetic credentials may be used in development and automated tests.

## Production documentation

- [REST API quickstart and secure data-push examples](docs/api/README.md)
- [OpenAPI 3.1 production contract](docs/api/openapi.yaml)
- [Production configuration and release checklist](docs/operations/production-configuration.md)
