# Connector contract checks

`runConnectorCertification({ manifest, adapter, context, grantedScopes })`
requires actual grants from the server's verified connection record. Omitting
`grantedScopes` fails before any adapter method is called. Never populate this
argument from the manifest or an untrusted browser payload.

A successful result is explicitly `validationLevel: "adapter_contract"` and
`certifiedForProduction: false`. It establishes the observed contract checks
only; it does not certify a real provider, tenant isolation, logs, permissions
at the provider, or absence of side effects inside arbitrary adapter code.

The harness requires healthy status, JSON discovery data and an explicit
reconciliation result `{ dryRun: true, sideEffects: 0, proposals: [] }`.
It compares two dry runs after canonical object ordering. Its SHA-256 evidence
binds the manifest, grants, invocation scope and observations rather than just
a checklist of booleans. This digest is an integrity reference, not a signature
or an independent review.

Result validation rejects secret/content-shaped field names, non-JSON values,
accessors, hidden fields, cycles and excessive nesting. It does not establish
that arbitrary strings under permitted keys contain no personal data. Each
real adapter must project a reviewed field allowlist and pass provider-specific
privacy, isolation, retry, rate-limit and revocation tests.

## Verification and rollback

Run `npm test` at the repository root. Regression cases include absent grants,
degraded health, dry runs with side effects, evidence substitutions, reordered
JSON, getters, non-JSON objects and cyclic/deep results.

The API now fails closed if an existing caller omits grants. The repository's
only current caller is the contract test; no deployed connector runtime calls
this helper. A future runner must supply verified grants and keep production
activation disabled until real-provider acceptance. Do not recover from a
failure by substituting the manifest's scopes.
