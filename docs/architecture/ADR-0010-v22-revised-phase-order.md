# ADR-0010: Use the revised v2.2 phase order

Status: Accepted for implementation sequencing. Date: 2026-09-05.

## Evidence

The user resubmitted the complete v2.2 build package and asked that its additional requirements and earlier chat decisions be included. Its Functional DOCX, Technical DOCX and README are byte-identical to the original uploaded package.

The Technical specification contains two different roadmaps: §20 uses milestones M0–M7, while Appendix G is explicitly titled “Revised Engineering Phase Plan v2.2” and uses phases 0–8. Appendix H reiterates the Phase 6+ privileged/runtime review gate. The Functional signature expansion and revised builder addendum also place Access Time Machine in Phase 6. The previous traceability report incorrectly treated §20 alone as authoritative.

## Decision

Use Appendix G for phase numbering and Appendix H for mandatory implementation requirements. Preserve the stricter security gates from the earlier roadmap. Historical filenames and migrations keep their names to avoid breaking history; their labels do not demonstrate acceptance of a revised phase.

| Revised phase | Scope | Earlier §20 mapping |
|---|---|---|
| 0 | Crypto/identity/device/sync/policy/entitlement/audit foundation | M0 |
| 1 | Free/Personal, Chromium, sponsor isolation, basic AI/automation | M1 |
| 2 | Family/Professional, verified sharing, client/project workspaces, Missions | Part of M2 |
| 3 | Team, Access Capsule/Checkout, Consent Ledger, Work-Life Firewall, approvals | Part of M2 plus signature additions |
| 4 | Business governance, Access Graph/Twin, Policy Sandbox, lifecycle, Session Capsule | M3 plus signature additions |
| 5 | SaaS/AI Manager, Ghost Account Radar, Identity Drift, Risk Weather, 25+ connectors | M5 plus signature additions |
| 6 | PAM, Secretless Relay, agent/machine runtime, Blast-Radius Twin, Access Time Machine, Access Budget | M4 plus signature additions |
| 7 | Enterprise Device Trust, private AI/regions, SIEM depth, MSP, marketplace/procurement, ecosystem | M6 |
| 8 | Reviewed recovery/emergency controls and advanced adaptive controls | M7 plus additions |

## Unresolved source differences

Appendix G says “100+ then ecosystem expansion” for Phase 7; older text describes 400+ supported integrations in Phase 6. Plan 100+ as an intermediate milestone and preserve 400+ as the eventual ecosystem target, with supported/certified status distinguished. No connector count is considered achieved without actual evidence. Final commercial claims require an explicit acceptance decision.

## Security consequences

Do not implement privileged/runtime Phase 6 on an unreviewed cryptographic foundation. Digital Access Will, Recovery Mesh and Offline Emergency Capsule remain future-gated until independent review. Reclassification never closes an audit, pilot, privacy or test gate. Billing/catalog work is cross-cutting, not evidence of PAM or Business completion.

## Source fingerprints

- Functional DOCX SHA-256: `67477cae20145354e76bfe5baf4805fc1b2930bec5b76cb2e04427420ece7fe8`
- Technical DOCX SHA-256: `568371eaedb780a54ec0eb1727d24398d41a46f8ef72e45f0082b9104a5a16d6`
