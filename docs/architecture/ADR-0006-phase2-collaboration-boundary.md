# ADR-0006: Phase 2 collaboration boundary

- Status: Accepted
- Date: 2026-09-04

## Decision

Passkey-X collaboration uses a separate client-generated workspace key for each
personal, family, professional, or team workspace. Workspace names, Mission
definitions, access-request purposes, and Access Capsule payloads are encrypted
before leaving the client.

Workspace invitations and Access Capsules bind delivery to both a verified email
hash and a random 256-bit secret carried only in the URL fragment. The server
stores the secret verifier, never the raw secret. Role checks, expiry, use limits,
approval decisions, and revocation are enforced by PostgreSQL RLS and atomic
`SECURITY INVOKER` functions using the caller's JWT.

Member revocation disables membership and key-envelope access immediately and
marks the workspace as requiring key rotation. Revocation cannot erase a secret
that a formerly authorized endpoint already captured; the user interface states
this limitation explicitly.

Fill-only sharing is a user-interface and workflow control, not digital-rights
management. A compromised recipient device or destination site can capture a
filled credential.

## Consequences

- Supabase and Netlify never receive collaboration plaintext or URL-fragment secrets.
- Cross-tenant authorization is tested with synthetic users in a rollback transaction.
- Sharing links must be sent through a trusted channel and expire by default.
- The extension will remain the trusted fill surface; web reveal is disabled for fill-only capsules.
- Independent cryptographic review and external penetration testing remain release gates for real production secrets.
