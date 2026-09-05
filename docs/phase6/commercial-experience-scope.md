# Passkey-X commercial experience checkpoint

Date: 2026-09-05

This checkpoint adds the public navigation, plan comparison, office-package
guidance, and versioned commercial catalog requested before the Phase 6 product
work begins. It is intentionally **not** a declaration that the v2.2 engineering
roadmap's Phase 6 privileged/runtime capabilities are complete.

## Delivered

- Public SaaS navigation for Product, Teams, Business, Security, and Pricing.
- Auth entry points remain on the first-party Passkey-X surface.
- Seven server-managed suites: Free, Personal, Family, Professional, Team,
  Business, and Enterprise.
- INR/USD and monthly/yearly display from catalog `2026-09-v2.2`.
- Team is positioned for one workgroup: shared encrypted workspaces, RBAC,
  requests/approvals, alerts, developer tools, and onboarding resources.
- Business is positioned for an office: departments, multiple teams, groups,
  delegated administration, employee lifecycle, policy, and organization-wide
  access intelligence.
- Published catalog rows are append-only, readable by anonymous/authenticated
  clients, and writable only through server administration.
- Stripe Price IDs remain null and paid checkout remains disabled until the
  recommended prices, tax treatment, and test-mode billing ceremonies are
  explicitly approved.

## Commercial decisions

The displayed figures are the recommended launch prices in the supplied v2.2
requirements package. They are proposals, not accounting commitments. The
user-supplied 1Password prices are competitive context and were not copied as
Passkey-X prices or seat constraints.

Passkey-X currently uses a three-seat minimum for Team and a five-seat minimum
for Business, following the supplied requirements. Business supports up to 500
users as a technical cap; Enterprise is contract-priced.

## Security boundary

The public catalog contains no user, customer, billing, vault, key, or secret
data. It does not grant an entitlement. Protected operations continue to use
tenant entitlements and RLS as their authority.

Privileged Access Management, Secretless Relay, agent/machine runtime
credentials, and recovery-mesh features remain blocked from production until an
independent cryptographic/security review is recorded.
