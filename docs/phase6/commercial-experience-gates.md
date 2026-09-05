# Commercial experience exit gates

Date: 2026-09-05

## Passed

- [x] Seven-suite catalog is versioned in Postgres.
- [x] Public plan data is protected by RLS and explicit grants.
- [x] Published catalog rows are immutable.
- [x] Anonymous clients can read only published product metadata.
- [x] Stripe secrets, customer data, and vault data are absent from the catalog.
- [x] Public navigation includes Product, Teams, Business, Security, and Pricing.
- [x] Pricing supports INR/USD and monthly/yearly presentation.
- [x] Team and Business office use cases are differentiated.
- [x] Paid actions remain disabled without active Stripe Price mappings.
- [x] TypeScript, lint, production build, static assertions, and SQL rollback
  checks pass.

## Required before commercial activation

- [ ] Owner approves final prices, seat rules, trials, and refund/proration terms.
- [ ] Stripe test Price objects are created and mapped to the immutable catalog.
- [ ] Tax registrations and Stripe Tax usage are decided with a qualified adviser.
- [ ] Test-mode checkout, webhook, upgrade/downgrade, cancellation, dunning, and
  seat-quantity E2E tests pass.
- [ ] Legal terms, privacy policy, support policy, and billing disclosures are
  approved.
- [ ] Billing is explicitly enabled only after the previous checks pass.

## Actual Technical Phase 6 gate

PAM, Secretless Relay, runtime credentials, Access Time Machine, Blast-Radius
Twin, and Access Budget are not included in this checkpoint. Their work may
begin only after the independent Phase 0 cryptographic review has been recorded.
