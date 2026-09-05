# Phase 5 SaaS/AI platform checkpoint

## Security boundary

Phase 5 is separated from encrypted vault storage. Discovery may consume
approved identity, SSO, SCIM, expense, license, usage-API, or managed-browser
domain metadata. It cannot consume DOM content, form content, decrypted vault
content, credential values, or raw prompts.

Connector tokens are never accepted by the browser data model. The database
stores an opaque `kms://` envelope reference, key version, and ciphertext hash
in a backend-only table. The user-visible connector record exposes only health,
minimum/granted scopes, rotation status, expiry, and sync timestamps.

## Control flow

1. An administrator creates an inventory record or a connector draft.
2. A future server-side vendor adapter completes authorization and stores the
   token in the service KMS, not Supabase browser-readable storage.
3. Discovery writes privacy-minimized application, account, license, contract,
   and usage facts with tenant IDs on every row.
4. Deterministic analysis creates proposals. It performs no vendor mutation.
5. An administrator reviews a proposal. Destructive execution remains a
   separate policy, approval, adapter, audit, and idempotency ceremony.
6. Realized savings require evidence hashes and a measurement interval.

## Connector maturity

The catalog contains 28 Phase 5 targets. Every row declares an authentication
scheme, capabilities, and minimum scopes. All are currently
`manifest / contract_validated`. Promotion requires a real adapter and stored
certification evidence; the UI does not call these production integrations.

## Verification

- Migration DDL passed a full development-database rollback validation.
- Live synthetic test passed entitlement, recommendation, budget, MSP, key
  isolation, credential-denial, catalog-mutation, and outsider-read cases.
- Connector SDK tests passed scope, privacy, redaction, health, and deterministic
  reconciliation cases.
- Authenticated development API `v1` version 4 exposes RLS-filtered Phase 5
  metadata and rejects manifest-only reconciliation.
- All 61 public development tables have RLS enabled; the performance advisor has
  no actionable Phase 5 findings.
- Supabase security advisor has no Phase 5 schema/RLS findings.
- Netlify production deployment was not attempted by request.

## Follow-up: provider error privacy

On 2026-09-05 the connector SDK stopped reflecting provider error text. Pattern-only masking could retain short credentials, URLs and personal data. Public errors now contain a fixed code/message and never stringify arbitrary provider objects. Regression tests cover these cases. This does not certify any provider adapter or prove discovery payloads safe; adapters still require typed allowlists and privacy review.
