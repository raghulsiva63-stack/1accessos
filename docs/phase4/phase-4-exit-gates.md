# Passkey-X Phase 4 exit gates

Date: 2026-09-05

Phase 4 is the commercial SaaS and production-operations release. The repository
and development database contain the first verified billing checkpoint; the
commercial release is not complete until every unchecked external gate has dated
evidence.

## Completed engineering gates

- [x] Tenant-scoped Free, Personal, Family, and Team entitlement model.
- [x] INR/USD and monthly/annual server-side Price matrix.
- [x] Personal, Family, and Team Product shells created in Stripe test mode.
- [x] Hosted Stripe Checkout and Customer Portal Edge Function.
- [x] Tenant-owner authorization before all billing actions.
- [x] Signed raw-body Stripe webhook handler with test/live-mode check.
- [x] Idempotent webhook transaction and duplicate-delivery counter.
- [x] No raw Stripe payloads, payment details, or vault data in billing tables.
- [x] Client read-only entitlement RLS and server-only billing tables.
- [x] Database-enforced member and workspace limits.
- [x] Upgrade, cancellation fallback, replay, and cross-tenant rollback tests.
- [x] Responsive plan UI for all tiers, currencies, and billing intervals.
- [x] Billing remains safely disabled when secrets or Prices are absent.
- [x] Supabase schema advisor has no billing/RLS findings.
- [x] Web, extension, crypto, API, CLI, and Phase 0–4 checks pass.

## Commercial activation gates

- [ ] Vlightsoft approves all twelve test and live Price amounts.
- [ ] Stripe test Prices and Customer Portal are configured.
- [ ] Test restricted key and signed webhook secret are stored in Supabase.
- [ ] Stripe test-mode checkout, 3DS, decline, retry, portal, and cancellation
  ceremonies pass through the deployed application.
- [ ] Qualified tax advice confirms registrations and product tax treatment;
  Stripe Tax remains off until then.

## Production and operations gates

- [ ] Separate staging and production Supabase projects with no development
  users or data copied between them.
- [ ] Paid Supabase production controls, leaked-password protection, backups,
  and a dated restore exercise.
- [ ] Branded transactional SMTP, abuse controls, recovery communications, and
  verified sending domain.
- [ ] Secret-scrubbed monitoring, SLOs, alerts, on-call ownership, incident
  response, and key-rotation exercises.
- [ ] Privacy policy, terms, DPA, retention schedule, subprocessors, and launch
  jurisdictions approved by qualified counsel.
- [ ] Independent cryptography review and external penetration test remediated.
- [ ] Chrome/Edge extension publisher identities and signed releases.
- [ ] Controlled beta uses synthetic credentials before real customer secrets.

The current milestone is **Phase 4 billing foundation complete; commercial and
production activation pending**. A browser redirect, Stripe metadata field, or
operator action cannot be used to grant a paid entitlement.
