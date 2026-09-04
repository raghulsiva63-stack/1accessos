# ADR-0002: Delivery order and environment isolation

- Status: Accepted
- Date: 2026-09-04

## Decision

The web client is delivered first. Chrome and Edge extensions follow in Phase 1 and reuse the shared cryptography, schema, and API-client packages.

The existing Supabase project is the development environment for Phase 0. A separate production project is mandatory before beta. Production data must never be copied into development.

## Repository convention

The product brand is `1accessos`. Package names and code identifiers use `oneaccessos` where an identifier cannot safely begin with a digit.

## Consequences

- Environment configuration is explicit and validated at startup.
- Development, staging, and production credentials are never interchangeable.
- Production deployment and data acceptance remain blocked until security exit gates pass.
