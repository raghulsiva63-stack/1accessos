# ADR-0002: Delivery order and environment isolation

- Status: Accepted
- Date: 2026-09-04

## Decision

The web client is delivered first. Chrome and Edge extensions follow in Phase 1 and reuse the shared cryptography, schema, and API-client packages.

The existing Supabase project is the development environment for Phase 0. A separate production project is mandatory before beta. Production data must never be copied into development.

## Repository convention

The public product brand changed from `1accessos` to `Passkey-X` on 2026-09-04. See ADR-0005 for the compatibility boundary.

## Consequences

- Environment configuration is explicit and validated at startup.
- Development, staging, and production credentials are never interchangeable.
- Production deployment and data acceptance remain blocked until security exit gates pass.
