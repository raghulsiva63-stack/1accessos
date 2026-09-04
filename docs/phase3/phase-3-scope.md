# Phase 3 scope

Phase 3 turns Passkey-X into a passwordless, policy-controlled platform for
business users, machines, workloads, and AI agents.

## Workstreams

1. Production domain, SMTP, Auth hardening, backups, and environment separation.
2. Feature-flagged account passkey registration, sign-in, naming, and revocation.
3. Organization groups, policy inheritance, and administrator controls.
4. SAML SSO and directory lifecycle integration for paid environments.
5. Public-key machine and agent identities with short-lived scoped credentials.
6. Approval-bound secret leases, rotation, rollback, and immutable attribution.
7. Signed webhooks, idempotent delivery, CLI exchange, and SIEM audit export.
8. RLS, replay, deprovisioning, WebAuthn, lease-expiry, and rotation-failure tests.

## First checkpoint

- Canonical RP ID fixed as `passkey-x.com`.
- Primary application origin fixed as `https://passkey-x.com`.
- Passkey API opt-in is wired through a disabled-by-default public flag.
- Passwordless account sign-in is available only when the flag is enabled.
- Signed-in users can list, register, rename, and revoke their own passkeys.
- UI states explicitly preserve the separate vault-unlock boundary.

## Activation gates

Passkey enrolment must not be enabled until all of these pass:

- `passkey-x.com` resolves to the intended Netlify production site.
- TLS is valid and HTTP redirects to HTTPS.
- Supabase Site URL and redirect allowlist use the custom origin.
- Supabase Auth RP ID is `passkey-x.com` and its origin is exactly
  `https://passkey-x.com`.
- A disposable-account register/sign-in/revoke browser test passes.
- Existing password login and recovery remain functional.

The experimental passkey API is not considered an independent vault recovery
method and is not a substitute for cryptographic review.

## Production activation

- Activated on 2026-09-04 for the production Netlify build only.
- Production origin: `https://passkey-x.com`.
- Relying-party ID: `passkey-x.com`.
- Supabase Auth configuration was confirmed by the project owner before the
  client feature flag was enabled.
- Netlify previews remain excluded from the allowed production origins.
- A real authenticator ceremony on the production domain remains an explicit
  rollout verification gate.
