# Passkey-X Phase 5 exit gates

Date: 2026-09-05

The requirements-v2.2 authority defines Phase 5 as **SaaS/AI Manager +
Integration Platform**. Older repository notes used “Phase 5” for the Business
office hierarchy; that work is retained as a prerequisite but does not replace
the authoritative Phase 5 scope.

## Engineering checkpoint complete

- [x] Privacy-minimized SaaS/AI application inventory with ownership, source,
  sanction state, risk, and first/last-seen metadata.
- [x] Identity/account correlation uses hashes and activity buckets; no page,
  form, DOM, raw-prompt, or vault plaintext fields exist.
- [x] Contract, seat, license, utilization, renewal, and currency models exist.
- [x] AI Spend Governor supports tenant, department, team, identity, and agent
  scopes with soft limit, hard limit, alert/approval/block behavior, and
  chargeback tags.
- [x] Backend-only atomic budget reservation blocks or requires approval without
  incrementing consumed spend past the hard cap.
- [x] SaaS Waste Autopilot proposes unused-seat, duplicate-tool, renewal,
  ghost-account, identity-drift, and budget findings.
- [x] Destructive recommendations never execute inside the analyzer.
- [x] Joiner, mover, leaver, access-review, reclaim, renewal, and budget workflow
  contracts exist; UI presets start disabled and proposal-first.
- [x] Connector SDK defines authorize, discover, provision, deprovision,
  ephemeral-credential, revoke, reconcile, health, and cost/license interfaces.
- [x] Connector certification harness checks minimum scopes, health result,
  privacy, secret-safe telemetry, and deterministic dry-run reconciliation.
- [x] Twenty-eight high-value target manifests cover identity, HRIS, ticketing,
  source control, CI/CD, cloud, Kubernetes, SaaS administration, messaging,
  finance/license, and SIEM categories.
- [x] Connector catalog visibly separates manifest, sandbox, certified, and
  production maturity; current targets are not mislabeled as production.
- [x] Connector credential references are backend-only KMS envelope references;
  browser roles cannot read or write them.
- [x] MSP access requires a provider request and customer-owner approval.
- [x] MSP context exposes derived SaaS/security metadata only and creates no
  customer tenant membership, vault grant, or key-envelope access.
- [x] All fifteen new Phase 5 tables have RLS, grants, tenant immutability, and
  live cross-tenant negative tests.
- [x] Responsive SaaS & AI navigation, dashboard, inventory, budget, workflow,
  connector, recommendation, and MSP context UI is implemented.
- [x] Development migrations `20260905070916`, `20260905071944`, and
  `20260905072509` are applied.

## Phase 5 release gates still open

- [ ] Implement and vendor-test the 25+ production adapters. The current 28
  entries are validated manifests, not working/certified vendor connections.
- [ ] Complete OAuth/SCIM/API-key authorization ceremonies against selected
  vendor sandboxes and provision the service-specific KMS hierarchy.
- [ ] Run the certification suite against each real adapter, record signed
  evidence, expiry, retry/rate-limit behavior, and vendor scope review.
- [ ] Validate spend, license, renewal, and utilization correctness against
  vendor invoices and source-of-truth exports.
- [ ] Measure realized SaaS/AI savings during a customer pilot; estimates alone
  do not satisfy the exit gate.
- [ ] Commission an independent tenant-isolation/authorization review and
  remediate its findings.
- [ ] Complete the earlier Phase 0-4 external security/pilot gates listed in the
  requirements traceability report.
- [ ] Enable Supabase leaked-password protection before public signup.

Netlify deployment is intentionally deferred. Stripe checkout remains disabled
until approved prices and billing test evidence exist.
