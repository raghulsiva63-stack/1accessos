# Phase 7 kickoff — enterprise trust and ecosystem

Started: 2026-09-05. Status: planning and acceptance preparation.
Authority: Technical v2.2 Appendix G/H and ADR-0010.
This is not a Phase 0–6 completion declaration or authorization to activate
privileged capabilities. Appendix H §11 gates Phase 6+ privileged/runtime work
on independent crypto review; the preceding acceptance gates remain open.

## Verified baseline

GitHub main `6218ae9` contains the web candidate published to Netlify as
`6a9c08432b9919714ff03fc3`. Its GitHub verification passed 33 tests and the web
build/lint. This continuation adds seven connector regression tests and runs all
10 development database suites successfully; exact test-file hashes are in
`../security/database-acceptance-2026-09-05.json`.

The Phase 5 connector harness now checks supplied grants instead of checking
the manifest against itself. Contract evidence is explicitly not production
certification. Sent's connected organization has KYC completed, but the last
direct runtime-key request returned a gateway-style 403. SMS and billing remain
disabled. No independent review, signed client distribution or pilot completion
has been provided.

## Work packages and first acceptance slices

| Work package | First design slice | Required input | Acceptance evidence |
| --- | --- | --- | --- |
| Enterprise Device Trust | Attestation freshness, issuer/audience binding, deny/revoke decisions across clients | Reviewed Phase 4 policy engine, selected IdP/MDM sandbox | Unverified posture cannot satisfy trust; stale evidence and IdP outage fail closed; revocation propagates |
| Private AI and regions | Tenant region policy and allowed metadata flow; regional failure behavior | Approved regions, provider deployment and privacy review | Wrong-region requests denied; no vault plaintext or raw secrets; outage does not reroute silently |
| SIEM depth | Allowlisted versioned event envelope and delivery state machine | Selected receiver, retention policy, Phase 4 audit and Phase 6 attribution | Duplicate/out-of-order delivery, outage replay, cross-tenant denial, event integrity and bounded retention |
| MSP | Customer-approved metadata scopes and revocation | Consenting provider/customer test organizations | Metadata access never grants customer vault keys; removal and expiry immediately stop access |
| Marketplace/procurement | Product-to-entitlement mapping and idempotent usage reconciliation | Approved commercial terms and marketplace account | Duplicate metering, cancel/downgrade and refunds reconcile without deleting ciphertext |
| Connector ecosystem | Separate manifest, contract-tested, provider-verified and certified stages | Provider sandboxes and per-adapter reviewer | 25+ real adapters for Phase 5; 100+ Phase 7 milestone before expansion toward 400+. Manifests never count |
| Operations and trust | Incident response, recovery exercises and release evidence | Named security/SRE owners, reviewed candidate and recovery targets | Measured restore/recovery exercises, resolved findings and an explicit launch decision |

## SIEM design boundary

Proposed envelope fields: schema version, event ID, tenant ID, actor/owner
references, event type, occurred-at timestamp, resource reference, policy
version, outcome, correlation ID and previous-event digest when applicable.
Only fixed outcome/reason codes cross this boundary. Exclude email, phone,
provider response bodies, page content, plaintext item names, vault values,
access/recovery keys, raw prompts and authentication headers. Role-filtered
exports must not disclose inaccessible graph relationships.

Delivery design: pending -> in-flight -> acknowledged, or retryable/dead-letter.
A queued HTTP request is not a delivery acknowledgment. Tenant-scoped event and
destination IDs identify retries; sequence/cursor state must survive restarts.
Destination changes require authorization, HTTPS/SSRF controls and a test
receiver. This document defines the design only; it creates no network sender,
new credentials, production telemetry or persistent grants.

## Prerequisites still open

0: Independent cryptographic review and resolved findings.
1: Hosted account/recovery/device ceremonies, desktop parity and distribution,
sponsor/privacy acceptance, and basic AI/automation completion.
2: Complete Family/Professional handover, offline/conflict/expiry flows and pilots.
3: Complete Access Checkout, Consent Ledger, Work-Life Firewall and Team flows.
4: Shared authorization/simulation engine, Graph/Twin, Session Capsule and review.
5: Signature-domain completion, real provider adapters and certification,
measured savings and independent isolation review.
6: Reviewed privileged/runtime implementation, native credential expiry,
kill/revoke reconciliation, attribution and controlled pilot.

Each slice requires schema/API, authorization, audit, entitlements/metering,
UI/failure states, tests, threat note and rollback before its acceptance.
Start with the named independent reviewer and provider/device access from
`../security/phase-0-7-release-inputs.md`; existing authorizations remain valid.
