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
- [ ] Final repository, web, extension, CLI, API, and live-advisor verification recorded below.

## Production release gates

These are deliberately separate and remain required before customers store real
secrets:

- [ ] Independent cryptographic design and implementation review.
- [ ] External penetration test of the hosted web app, extension, API, and RLS.
- [ ] Production Supabase project with final Auth, backup, SMTP, and domain configuration.
- [ ] Signed Chrome/Edge extension release and verified store origin.
- [ ] Operational incident response, key-rotation runbook, and recovery exercise.

## Verification record

Pending final Phase 2 verification run.
