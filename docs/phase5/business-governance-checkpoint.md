# Passkey-X Business governance checkpoint

Date: 2026-09-05

This checkpoint completes the next safe Business-office slice without activating
PAM/runtime credentials or deploying to Netlify.

## Delivered

- PostgreSQL-enforced tenant, department and team administrator scopes.
- Owner-managed assignments for organization, security, billing, helpdesk and
  auditor roles.
- Verified-email-bound, expiring and replay-resistant organization invitations.
- Browser-local CSV onboarding for up to 200 people.
- Directory/team provisioning that deliberately grants no encrypted vault access.
- Team > department > tenant effective-policy resolution.
- Device-policy readiness with source and verification provenance.
- Bounded NDJSON export of authorized, hash-chained audit evidence.
- Responsive organization governance screens and invitation acceptance ceremony.

## Security invariants

1. The database rechecks every scoped mutation; hiding a UI control is not treated
   as authorization.
2. Invitation records contain hashes, not the raw email address or bearer token.
3. An organization invitation cannot issue a workspace key envelope.
4. Self-reported posture cannot satisfy a strict device-approval policy.
5. The public invitation acceptance function is callable only by authenticated
   users and validates the verified email, 256-bit token, state and expiry.
6. Audit export is tenant-authorized, ordered and limited to 1,000 rows per call.

## Verification

The rollback suite covers descendant-scope administration, cross-department
denial, email-bound acceptance, replay denial, no-vault-access provisioning,
policy precedence, device evidence provenance, lifecycle bypass denial and audit
authorization. Apply the migration to `1accessos-dev`, rerun the rollback suite,
then require clean Supabase security and performance advisor results before a
repository checkpoint is published.

## Still gated

- Branded SMTP and monitored invitation delivery.
- SAML SSO and SCIM provisioning.
- Global device enforcement through reviewed device-bound session claims.
- Automatic SIEM streaming, retention and legal-hold policy.
- Approved Stripe Business prices and billing lifecycle E2E tests.
- Independent authorization/cryptography review and external penetration test.
- Requirements-v2.2 PAM, Secretless Relay and runtime credentials.
