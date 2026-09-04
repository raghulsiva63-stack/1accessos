# ADR-0004: REST API boundary

- Status: Accepted
- Date: 2026-09-04

## Decision

Public product operations use a versioned `/v1` API façade. Direct Data API access is limited to explicitly approved bootstrap or read paths and is never the authorization shortcut for sensitive mutations.

The API validates the Supabase JWT or a hashed scoped personal access token, resolves the live identity and membership, validates envelope metadata, enforces expected versions and idempotency, and writes audit/outbox records transactionally.

## Rules

- Responses never include infrastructure secrets.
- APIs never accept a plaintext-secret field.
- Mutations support `Idempotency-Key`.
- Updates require an expected item version.
- Lists use opaque cursors, not unbounded offsets.
- Webhooks contain identifiers and event metadata only, never vault ciphertext or plaintext.
- API errors use stable codes and do not reveal authorization internals.

