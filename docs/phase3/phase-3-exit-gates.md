# Passkey-X Phase 3 exit gates

Date: 2026-09-04

Phase 3 is the passwordless and policy-controlled platform workstream. Status is
split between the production passkey checkpoint and the wider enterprise scope
so a deployed UI is never mistaken for a completed security release.

## Production passkey checkpoint

- [x] Canonical relying-party ID is permanently fixed as `passkey-x.com`.
- [x] Production origin is permanently fixed as `https://passkey-x.com`.
- [x] The project owner confirmed the Site URL, redirect allow-list, RP ID, and
  origin in the account-authentication configuration.
- [x] Production Netlify builds enable passkeys deterministically.
- [x] Deploy previews and branch deploys keep passkey enrolment disabled.
- [x] Registration, sign-in, list, rename, and removal use the maintained client
  passkey API.
- [x] Account authentication remains separate from vault decryption.
- [x] Customer UI and errors do not expose Supabase or deployment configuration.
- [x] Login-password recovery is branded and cannot reset the vault password.
- [x] Static checks, lint, TypeScript, crypto tests, and production build pass.
- [ ] A disposable user has completed register, sign-in, rename, remove, password
  fallback, and vault-recovery ceremonies on the production origin.

## Wider Phase 3 platform scope

These items remain outside the completed passkey checkpoint:

- [x] Organization groups, policy-inheritance data, and tenant-scoped administrator controls (Phase 5 foundation).
- [ ] SAML SSO and directory lifecycle integration for paid environments.
- [ ] Public-key machine, workload, and agent identities.
- [ ] Approval-bound secret leases, rotation, rollback, and attribution.
- [ ] Signed webhooks, replay protection, delivery retry, and SIEM export.
- [ ] Deprovisioning, lease-expiry, rotation-failure, and webhook replay tests.

## Production security gates

- [ ] Independent cryptographic design and implementation review.
- [ ] External penetration test of web, extension, API, and authorization rules.
- [ ] Separate production data project with backups, restore evidence, custom
  SMTP, rate-limit review, and incident-response ownership.
- [ ] Leaked-password protection enabled for public signup.
- [ ] Signed and reviewed browser-extension release.

The passkey checkpoint is engineering-complete. The complete Phase 3 platform
and the production security release are not complete until the unchecked gates
have evidence and approval.
