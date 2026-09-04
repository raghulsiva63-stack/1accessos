# ADR-0005: Passkey-X brand and protocol compatibility

Status: accepted
Date: 2026-09-04

## Decision

The customer-facing product name is **Passkey-X by Vlightsoft**. Web metadata,
recovery filenames, extension and desktop manifests, package names, documentation,
and visual assets use Passkey-X.

The strings beginning with `1accessos:` remain the cryptographic protocol
namespace for envelope version 1. They are authenticated associated data, not a
customer-facing brand. Changing them in place would make already-created
ciphertext undecryptable. Database migration filenames and historical test
fixtures also retain the original identifier as immutable history.

New recovery keys use the `PX-RK1-` prefix. The parser accepts the legacy
`1A-RK1-` prefix so a brand change cannot strand a valid recovery key.

## Consequences

- Brand changes cannot silently invalidate encrypted data.
- Any future protocol namespace change requires a new envelope version and an
  explicit client-side re-encryption migration.
- UI copy must not expose the historical namespace.
