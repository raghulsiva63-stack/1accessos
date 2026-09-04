# Passkey-X Phase 4 readiness

Date: 2026-09-04

Phase 4 is the commercial SaaS and production-operations release. Planning can
begin now; customer launch must wait for the Phase 3 and production-security
gates recorded in `docs/phase3/phase-3-exit-gates.md`.

## Phase 4 implementation order

1. **Environment separation** — create staging and production projects, apply
   reviewed migrations, restrict operator access, configure backups, and prove a
   restore without copying development users.
2. **Commercial plans** — integrate an authorized billing provider through
   signed server-side webhooks, map subscriptions to server-owned entitlements,
   and test upgrade, downgrade, cancellation, retry, and refund behavior.
3. **Production identity** — configure branded SMTP, abuse controls, leaked-
   password checks, recovery communications, enterprise SSO, and directory
   deprovisioning without exposing infrastructure providers to customers.
4. **Enterprise policy** — add groups, inherited policies, administrator roles,
   machine identities, short-lived secret leases, and cryptographic rotation.
5. **Operations** — add secret-scrubbed telemetry, SLOs, alerting, incident
   response, key-rotation procedures, audit export, and webhook replay controls.
6. **Release assurance** — complete independent cryptography review, external
   penetration test, remediation, browser-extension signing, and a controlled
   beta with synthetic credentials before permitting real customer secrets.

## Required owner decisions

- Billing provider and merchant account.
- Paid Supabase organization/project for production controls and leaked-password
  protection.
- Transactional email provider and verified sending domain.
- Monitoring/on-call owner and incident notification channel.
- Independent cryptography reviewer and penetration-testing supplier.
- Privacy policy, terms, data-processing agreement, retention policy, and target
  launch jurisdictions approved by qualified counsel.

## Non-negotiable release evidence

- Zero plaintext vault data in database, logs, email, analytics, billing, or
  support systems.
- Cross-tenant, anonymous, revoked-member, and replay tests pass in staging and
  production configuration.
- Backup restore, account recovery, workspace revocation, key rotation, and
  incident exercises have dated evidence.
- A signed release commit, successful CI run, immutable dependency inventory,
  and production deploy ID are recorded for every launch.

No Phase 4 integration receives a service-role key in the browser, and no vendor
is allowed to receive decrypted vault contents.
