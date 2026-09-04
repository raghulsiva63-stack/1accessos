# ADR-0001: Zero-knowledge vault boundary

- Status: Accepted
- Date: 2026-09-04

## Decision

Trusted Passkey-X clients encrypt and decrypt vault content locally. Supabase and the REST API receive only versioned ciphertext envelopes plus the minimum control metadata required for authorization, synchronization, and abuse prevention.

Supabase authentication proves the account identity but does not derive, receive, or recover the vault master key.

## Consequences

- Account login and vault unlock are separate operations.
- Administrators cannot decrypt or reset vault content.
- Recovery uses a user-controlled downloadable recovery key.
- Search over protected fields is performed locally unless a separately reviewed privacy-preserving index is introduced.
- Server logs, analytics, email, webhooks, and AI integrations are prohibited from receiving plaintext vault content.
- Item formats and key envelopes must be versioned to support safe migration.
