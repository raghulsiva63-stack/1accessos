# Phase 2 exit gates

Phase 2 is the collaboration and professional-workflow release for Passkey-X.
This checklist distinguishes engineering completion from permission to store
real production secrets.

## Engineering gates

- [x] Family, professional, and team workspaces use isolated client-generated keys.
- [x] Workspace invitations bind a verified email to a one-time fragment secret.
- [x] Owner, manager, editor, and viewer authorization is enforced by RLS.
- [x] Revocation disables membership and key envelopes and flags key rotation.
- [x] Access Capsules support expiry, reveal/fill-only policy, revocation, and use limits.
- [x] Access requests create an attributable approval and timeboxed grant atomically.
- [x] Mission definitions and request purposes are client-encrypted.
- [x] `/v1` exposes collaboration metadata and ciphertext without a service-role key.
- [x] The CLI reads tokens only from the environment and never accepts vault plaintext.
- [x] Synthetic recipient, outsider, bad-token, one-time-use, anonymous, and revocation tests roll back cleanly.
- [x] Final repository, web, extension, CLI, API, and live-advisor verification recorded below.

## Production release gates

These are deliberately separate and remain required before customers store real
secrets:

- [ ] Independent cryptographic design and implementation review.
- [ ] External penetration test of the hosted web app, extension, API, and RLS.
- [ ] Production Supabase project with final Auth, backup, SMTP, and domain configuration.
- [ ] Supabase Auth leaked-password protection enabled for production accounts.
- [ ] Signed Chrome/Edge extension release and verified store origin.
- [ ] Operational incident response, key-rotation runbook, and recovery exercise.

## Verification record

Verified on 2026-09-04:

- Release code commit: `3c0ee7c11b8d3f10c45930dab16ab71e918514fb`.
- GitHub Actions run `33905880452` completed successfully.
- Netlify production deploy `6a9b10ec6a5b933acd74a318` is ready at
  `https://passkey-x.netlify.app` with all four configured header rules applied.
- Public browser readback confirmed the Passkey-X title, Vlightsoft branding,
  account-login form, and no application-origin console errors.
- The web and extension production builds, crypto/API/CLI tests, Phase 0/1/2
  static checks, OpenAPI parsing, secret scan, and dependency audits passed.
- Live collaboration/RLS rollback tests passed against `1accessos-dev`.
- All 27 public tables have RLS enabled. The security advisor reports no
  database/RLS exposure findings.
- The remaining Auth leaked-password-protection warning is an operator setting
  tracked as a production release gate; unused-index notices are informational
  in the near-empty development database.
