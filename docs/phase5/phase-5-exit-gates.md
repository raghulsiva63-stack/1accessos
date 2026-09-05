# Passkey-X Phase 5 exit gates

Date: 2026-09-05

Phase 5 is the Business office-control release. Engineering checkpoints are kept
separate from commercial and enterprise-production approval.

## Completed foundation gates

- [x] Business entitlement exists alongside Free, Personal, Family and Team.
- [x] Business supports 500 members and 500 workspaces as technical caps.
- [x] Departments support a tenant-safe parent hierarchy.
- [x] Teams belong to the same tenant and optionally to a department.
- [x] Reusable groups and group membership are tenant-bound.
- [x] Organization profiles map only to existing tenant members.
- [x] Organization, security, billing, helpdesk and auditor admin assignments exist.
- [x] Tenant/department/team policy scopes and precedence data are represented.
- [x] Joiner/mover/leaver history is append-only to browser roles.
- [x] Suspension/deprovisioning revokes old key envelopes and requires key rotation.
- [x] Business-only, cross-tenant, privilege-escalation and lifecycle rollback tests pass.
- [x] Responsive organization console and Business package comparison are implemented.
- [x] Stripe checkout/webhook code recognizes Business without inventing prices.

## Remaining Phase 5 enterprise gates

- [ ] Business INR/USD monthly/annual Price amounts approved and created in Stripe test mode.
- [ ] Scoped department/team administrator enforcement and UI assignment ceremonies completed.
- [ ] Organization invitation and bulk CSV onboarding ceremonies completed.
- [ ] SAML SSO and SCIM/directory lifecycle integration selected and implemented.
- [ ] Effective-policy resolver, conflict handling and device-policy enforcement completed.
- [ ] Production audit/SIEM export, retention and legal-hold rules approved.
- [ ] Business checkout, upgrade, downgrade, seat-limit and cancellation E2E tests pass.
- [ ] Independent authorization review and external penetration test remediated.

The current milestone is **Phase 5 Business foundation**, not a completed enterprise
production release. Phase 0 is complete; Phase 1 and 2 engineering are complete;
Phase 3 and 4 retain the external production/commercial gates recorded in their
respective checklists.

