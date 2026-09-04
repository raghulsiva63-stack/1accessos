# Phase 1 — Web Vault Checkpoint 01

> Historical checkpoint. Superseded by `phase-1-exit-gates.md`.

Date: 2026-09-04

Status: implemented and verified in the development Supabase project. This is the first Phase 1 vertical slice, not the Phase 1 completion gate.

## Working capabilities

- Supabase email/password registration and sign-in.
- Separate vault master password; the login password is not used as a vault key.
- Argon2id client key derivation and AES-256-GCM key envelopes.
- Atomic personal identity, tenant, workspace, device and key-envelope bootstrap.
- Downloadable 256-bit recovery key. Administrators cannot reset or decrypt the vault.
- Encrypted Login, API Key, Secure Note and Custom Secret items.
- Client-side encryption/decryption and client-side search.
- Immutable revisions, optimistic concurrency and soft deletion.
- Durable create/update/delete sync-change records.
- Lock and sign-out controls; the account-root and workspace keys are cleared when their UI lifetimes end.
- Generated Supabase TypeScript schema definitions.

## Development environment

The current Supabase project is development-only. The web application needs only these public values:

```text
NEXT_PUBLIC_SUPABASE_URL=https://PROJECT_REF.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_REPLACE_ME
```

No secret/service-role key belongs in the web build.

## Netlify deployment

The repository includes a root `netlify.toml` that sets `apps/web` as the build base and runs the standard Next.js production build. Netlify's maintained OpenNext adapter handles the Next.js deployment automatically; no legacy Next.js plugin is pinned.

Set both public Supabase variables in Netlify for Production and Deploy Preview contexts. After the first deploy, set the Supabase Auth Site URL to the stable Netlify URL (or custom domain) and add the exact production URL plus the Netlify preview wildcard to the additional redirect allow-list.

## Verification evidence

- Standard Next.js production build passes.
- ESLint passes.
- Browser crypto round-trip and authenticated-AAD tamper tests pass.
- Recovery-key format/entropy test passes.
- Live rollback database test passes for two synthetic users.
- Cross-tenant encrypted-item insertion is denied by RLS.
- Create/update/delete produce immutable revisions and three ordered sync changes.
- Supabase performance advisor has no non-informational findings.

This historical warning was removed by migration
`00000000000006_invoker_bootstrap_and_recovery.sql`. Bootstrap and recovery
functions now run as `SECURITY INVOKER` with narrowly granted columns and RLS.

## Remaining Phase 1 gates

- Configure a real hosting environment and Auth redirect URLs.
- Run browser end-to-end registration, email verification, setup, recovery download, lock/unlock and CRUD tests.
- Add recovery-key restore UX and trusted-device management.
- Add importers and encrypted attachment MVP.
- Add the dedicated `/v1` API façade, scoped personal access tokens and SDK baseline.
- Build and test the Chrome/Edge extension after the web E2E gate.
- Complete independent cryptographic design review before any production vault data.
