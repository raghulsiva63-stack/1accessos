> Phase 7 kickoff and current evidence: [../phase7/kickoff.md](../phase7/kickoff.md).

> Corrected 2026-09-05: enterprise work is Phase 7 under the revised appendix. Use `privileged-runtime-plan.md` for Phase 6. This draft is not an implementation authorization or release acceptance.

# Phase 7 — Enterprise trust and ecosystem draft (historical file path)

Planning checkpoint: 2026-09-05. Authority: Functional and Technical Specifications v2.2, Technical Appendix G/H; see ADR-0010.

Status: planning only. Commercial catalog and marketing navigation are separate work; their legacy Phase 6 labels do not establish enterprise readiness. No release date or completion claim is supported yet.

## Entry criteria and critical path

Phase 7 implementation depends on accepted Phase 0–6 evidence. The specification prohibits Phase 6+ privileged/runtime work on an unreviewed cryptographic foundation. Planning may proceed now.

| Prerequisite | Evidence required before acceptance | Current disposition |
|---|---|---|
| Phase 0 | Independent cryptographic design/implementation review, resolved findings, tenant/identity negative tests | Foundation exists; independent review pending |
| Phase 1 | Hosted disposable-user E2E; signed desktop parity; extension security; sponsor/privacy acceptance; personal automation/AI proof | Partial |
| Phase 2 | Sharing, revoke/expiry/offline/conflict tests; Family/Professional approved scope; customer pilot | Partial; future-gated recovery features require review |
| Phase 4 | SSO/SCIM lifecycle, Access Graph/Twin, SIEM delivery, device enforcement, business pilot, external penetration/discovery-privacy review | Partial |
| Phase 6 | Resource model, JIT/JEA broker, cloud/K8s/DB/SSH adapters, Agent Passport, leases, Task Capsule, Flight Recorder, kill switch | Release implementation remains; billing code does not satisfy this phase |
| Phase 5 | 25+ actual production adapters with per-adapter certification, measured usage/savings, independent tenant isolation audit | Control plane and target manifests exist; external/provider evidence pending |

Proposed execution order: close authentication and release-environment gaps; complete Phase 1 and 2 vertical slices; complete Team Phase 3 and Business Phase 4 enforcement; certify Phase 5 adapters; implement and verify Phase 6 runtime revocation; enter Phase 7 after prerequisite acceptance. Independent reviews should be commissioned alongside engineering so findings can affect design.

## Phase 7 work packages

Owners below are required roles, not assigned people. Estimates follow discovery and owner acceptance.

| Work package | Deliverables | Dependencies | Acceptance evidence | Owner role |
|---|---|---|---|---|
| Device Trust and IdP | Attested device posture, policy enforcement at session/API boundaries, expiry and revocation propagation, supported IdP integrations | Phase 4 baseline; Phase 6 revocation | Stale posture, compromised device, IdP outage, session revocation and bypass tests across clients | Identity/security |
| Private AI and regions | Regional data-flow inventory, tenant routing policy, private inference boundary, consent/retention controls | Reviewed zero-knowledge boundary; tenant isolation | No plaintext vault content in inference/telemetry; denied cross-region routing; fail-closed unavailable region tests | Platform/privacy |
| HSM/BYOK | ADR defining exact keys protected, custody model, rotation, revocation, backup/restore and failure behavior | Independent crypto review; selected deployment model | Review proves server cannot decrypt personal vault data; key outage/revoke/rotation/restore drills | Cryptography/platform |
| SIEM and evidence | Versioned event schemas, redaction, signed exports, retry/acknowledgment, tenant routing and evidence retention | Phase 4 audit delivery; Phase 6 attribution | Duplicate/out-of-order/outage recovery; cross-tenant denial; completeness and integrity checks | Security operations |
| Integration ecosystem | Supported-versus-certified registry, compatibility matrix, upgrade/deprecation process, expansion toward 400+ | Phase 5 certification program | Per-provider scope, privacy, isolation, rate-limit, retry, reconciliation and revoke evidence; manifests alone never count | Integrations |
| AWS Marketplace | Product/offer mapping, entitlement reconciliation, metering, cancellation/downgrade and support process | Reviewed billing ledger; approved commercial setup | Duplicate/out-of-order events, meter reconciliation, entitlement expiry, preserved customer ciphertext | Commerce/platform |
| Enterprise launch | External review, incident process, DR exercises, measured service targets and launch decision | All packages and Phase 0–6 acceptance | Signed review and remediations; measured recovery results; agreed SLA supported by monitoring | Security/SRE/product |

## Design constraints

- Keep plaintext vault items, recovery keys and decrypted attachments client-side. HSM/BYOK is not permission to move personal vault decryption to the server.
- Derive tenant and actor from verified authorization, never caller-selected scope alone. Enforce AAL/device policy at protected operations, not only in UI.
- Treat AI output as a proposal: schema validation, authorization, policy simulation, required human approval, deterministic execution.
- Preserve revoke, lock, recovery, export and delete paths when entitlements lapse. Never use billing downgrade to destroy encrypted customer data.
- Every capability requires schema/API, authorization, audit, entitlement/usage behavior, user/error states, automated tests, threat note and rollback plan.
- Separate development, test and production credentials and records. Runtime adapters start with provider sandbox accounts and least privilege.

## Delivery and review process

1. Assign accountable owners and reviewers; approve the prerequisites and target environments.
2. Write one ADR and abuse-case checklist per work package, including data fields and failure behavior.
3. Implement one complete vertical slice before adding providers or regions. Include negative authorization and outage tests.
4. Record evidence against the exact commit, deployment, provider configuration and test environment. Redact secrets and personal data.
5. Rehearse safe disable/rollback, credential revocation and recovery. Disabling new grants must not stop revocation or reconciliation.
6. Obtain independent review, close findings, run a controlled pilot and record the launch decision. Do not infer acceptance from passing static checks.

## Decisions needed at the relevant implementation gate

- Named independent reviewers and pilot organizations.
- Supported IdPs, device platforms, initial private-AI deployment and residency regions.
- Which key classes BYOK/HSM protects and which enterprise plans offer it.
- Initial SIEM destinations, retention periods, supported recovery objectives and measured SLA targets.
- AWS seller/product setup and commercial terms.
- Provider sandbox accounts, administrator consent and certification contacts for real connectors.

These are implementation inputs, not reasons to delay prerequisite engineering or this plan. No customer invitations, purchases or external review bookings have been made.
