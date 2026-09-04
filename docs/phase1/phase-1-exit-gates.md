# Passkey-X Phase 1 exit gates

Date: 2026-09-04

This matrix distinguishes implemented engineering work from release approvals
that cannot be self-certified by the development agent.

## Implemented and testable in development

- [x] Passkey-X visual identity across web, PWA, extension, and desktop manifests.
- [x] Email registration/sign-in with a separate vault password.
- [x] Argon2id key derivation and AES-256-GCM authenticated envelopes.
- [x] Downloadable 256-bit recovery key and recovery-driven vault-password rotation.
- [x] Personal identity, tenant, workspace, entitlement, and device bootstrap.
- [x] Thirteen personal vault item types from the product specification.
- [x] Encrypted create/update, immutable history, favorite, archive, soft-delete, and restore.
- [x] Local search, local password-health scoring, password/passphrase generator, and timed clipboard clearing.
- [x] Client-only CSV parsing/import and reauthenticated encrypted export.
- [x] Private encrypted attachment upload/download with tenant/workspace Storage policies, atomic metadata registration, and sync events.
- [x] Free entitlement counters and two-device enforcement; one-way device revocation.
- [x] First-party Home-only sponsor card with no third-party script or vault targeting.
- [x] Local automation recipes and an honest local-only Security Concierge state.
- [x] Manifest V3 Chromium extension with Save/Update/Never, keyboard fill, exact-origin checks, 60-second candidate expiry, strict CSP, and in-memory vault keys.
- [x] Tauri 2 desktop packaging configuration for the static Next.js client.
- [x] Negative cross-tenant, recovery-proof, entitlement, device-revocation, and attachment-path tests.
- [x] Web production build, lint, crypto/export tests, extension build, and extension security tests.

## External release gates

- [ ] Independent cryptographic design and implementation review.
- [ ] Independent web/extension penetration test.
- [ ] Supabase leaked-password protection enabled in the Auth dashboard.
- [ ] Final custom domain and exact Supabase Auth redirect allow-list.
- [ ] Full hosted-browser email-confirmation and authenticated vault E2E on that final origin.
- [ ] Authorized billing provider for the Personal subscription.
- [ ] Authorized hosted-AI provider if remote AI credits are sold; local-only mode is complete without it.
- [ ] Vlightsoft desktop signing/notarization identities and Chrome/Edge store publisher accounts.

Phase 1 is **engineering-complete** only after all automated checks in this
repository pass. It is **production-release-complete** only after every external
gate above has evidence and sign-off.
