# Phase 6 — Privileged access and agent/machine runtime

Date: 2026-09-05. Authority: Technical v2.2 Appendix G/H and F; Functional signature expansion. Planning only. ADR-0010 supersedes the earlier enterprise-labelled Phase 6 plan.

## Entry gate

Independent cryptographic review and preceding Phase 0–5 security acceptance must be recorded before privileged/runtime implementation or activation. The current release acceptance count is 0 of 6. Planning does not waive this requirement.

## Vertical slices and acceptance evidence

| Order | Slice | Required implementation | Security/failure evidence |
|---|---|---|---|
| 1 | Resource and subject model | Tenant-scoped privileged resources; HUMAN/AI_AGENT/SERVICE_ACCOUNT/WORKLOAD/MACHINE; responsible owner; adapter capability/security levels | Cross-tenant denial, disabled owner/subject, unsupported scope, no secret-valued metadata |
| 2 | Access Budget and request/approval | Typed intent/resource/scope/duration; policy evaluation; immutable approval binding; reserve usage at the broker | No self-approval where separation is required; changed scope invalidates approval; concurrent budget exhaustion; retries do not double charge |
| 3 | JIT/JEA grant and credential lease | Idempotent issue/start/end/revoke; provider-native expiry; durable reconciliation; backend credential custody | Crash between issue and receipt, provider outage, duplicate worker, stale approval, expiry/revoke under outage; no residual standing grant |
| 4 | Agent Passport and Task Capsule | Actor/owner/provider/model/tool/data-class policy; task/resource/scope/expiry binding; attestation freshness | Wrong task/tool/environment rejected; killed identity cannot issue/renew; no long-lived vault secret exposure when dynamic adapter exists |
| 5 | Secretless Relay adapters | One reviewed cloud/K8s/DB/SSH adapter slice at a time; visible L0–L4 capability | L1 UI hiding never labelled protocol-secretless; L3 ephemeral credentials scoped/short-lived; L4 federation audience/issuer binding; downgrade is explicit |
| 6 | Kill Switch and Flight Recorder | Disable issuance, revoke active sessions/leases, reconcile failures; actor/owner/intent/policy/approval/resource/scope/time/revoke evidence | Kill/issue races, retry recovery, full attribution, redacted logs; acknowledge pending revocation honestly |
| 7 | Access Time Machine and Blast-Radius Twin | Versioned metadata snapshots and the same deterministic authorization engine; graph/policy/catalog/time context | Reproducible simulation; role-filtered graph inference; stale snapshots detected; no blind apply of simulation |
| 8 | Metering, UI and pilot | Idempotent usage ledger, entitlement gates, pending/denied/expired/revoke-failed states, safe disable and rollback | Downgrade preserves revoke/lock/recovery/delete; billing mismatch cannot grant privilege; external review and controlled pilot |

## API and data design inputs

Reconcile existing schema before creating migrations. Planned entities: privileged_resources, privilege_requests/sessions, credential_leases, agent_profiles, session_evidence, access_budgets, access_graph_snapshots, access_simulations and task/resource bindings. Store metadata and opaque credential references; never vault plaintext or provider token values in browser-readable records.

Use the specified identity/passport/kill, privileged request/approval/session/evidence, typed credential-lease, access-budget and simulation API families. Resolve duplicated runtime lease paths in an ADR with one canonical endpoint and explicit compatibility handling. Every endpoint derives actor and tenant from verified credentials, checks ownership/membership, entitlement and policy, and emits an allowlisted audit event.

## State-machine constraints

- Requests: pending → approved/denied/cancelled/expired. Approval is bound to an immutable request digest and policy version.
- Leases: issuing → active → revoking → revoked/expired; issuance/revocation failures remain explicit and reconcilable. Do not mark revoked based only on a local status update.
- Every provider effect has a durable idempotency key and recovery record. If the provider cannot guarantee expiry under outage, reject a zero-standing-privilege claim for that adapter.
- Re-check current authorization immediately before execution. AI proposals cannot call privileged executors directly.
- Simulations are read-only. Execution starts a new authorized transaction against current state.

## Required decisions at implementation time

Select initial provider sandbox and responsible admin, resource/scope allowlists, maximum session duration, budget policy, owner/approver roles, revocation objective, evidence retention and reviewer. Do not invent customer acceptance, purchased infrastructure or certified connectors.

## Rollback and release record

Disable new issuance first, retain revocation/reconciliation workers, revoke outstanding credentials, then retire adapters after evidence confirms closure. Keep audit and customer ciphertext according to policy. Record exact source commit, schema version, provider settings, tested failure cases, measured revocation results and reviewer acceptance before enabling a pilot. No Phase 6 privileged code was activated by creating this plan.
