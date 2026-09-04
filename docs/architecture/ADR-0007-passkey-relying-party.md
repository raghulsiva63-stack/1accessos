# ADR-0007: Passkey relying-party boundary

- Status: Accepted
- Date: 2026-09-04

## Decision

Passkey-X uses `passkey-x.com` as the permanent WebAuthn relying-party ID and
`https://passkey-x.com` as the primary application origin. Passkey
enrolment stays disabled until that origin resolves to the production Netlify
application and the identical values are configured in Supabase Auth.

The web client exposes passkey authentication only when
`NEXT_PUBLIC_PASSKEYS_ENABLED=true`. The default is `false` in source control.
This flag is an availability control, not an authorization boundary.

Passkeys authenticate the Supabase account. They do not derive, unwrap, replace,
or recover the vault root key. A user must still unlock encrypted vault material
with the separate vault password or the downloadable recovery key.

## Rationale

WebAuthn credentials are cryptographically scoped to a relying-party ID.
Enrolling against the temporary `passkey-x.netlify.app` hostname would make
those credentials unusable after moving to the product domain. Using the
registrable product domain also permits explicitly approved HTTPS subdomains.

Supabase passkey support is experimental. Keeping password login available and
placing passkeys behind a reversible feature flag limits rollout risk without
weakening the zero-knowledge boundary.

## Consequences

- DNS and TLS for `passkey-x.com` must be complete before enrolment.
- Changing the RP ID after enrolment is a breaking credential migration.
- Preview deploys cannot enrol production passkeys unless explicitly added as
  valid origins; Phase 3 does not allow this.
- SAML SSO and passkey authentication remain separate login paths.
- Vault unlock always remains a second client-side step.
