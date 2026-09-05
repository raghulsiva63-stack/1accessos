# Phase 0–6 delivery and Phase 7 entry inputs

Date: 2026-09-05. Scope: revised Technical v2.2 Appendix G/H and ADR-0010. Existing authorization for development setup persists. No passwords, OTPs or runtime credentials should be pasted into this document.

## What can continue without new user input

Code fixes, deterministic policy and privacy checks, development-only schema/API/UI work permitted by the phase gates, failure-state tests, integration contracts, requirements reconciliation, Phase 6 planning, review evidence preparation and rollback plans. Current credentials and connected tools can be used within their authorized scope. Missing pilot/reviewer evidence must remain explicit.

## Inputs that cannot be manufactured

| Priority | Needed input | Why / release gate | Timing |
|---|---|---|---|
| 1 | Named independent cryptographic reviewer and engagement process; approved findings/sign-off when review completes | Phase 0 acceptance; required before Phase 6 privileged/runtime implementation | Start review while engineering proceeds |
| 2 | User-controlled email inbox and real SMS-capable phone for one approved development enrollment/sign-in/removal ceremony | Confirmation/recovery delivery, MFA behavior and device-delivery evidence | After provider sandbox and webhook validation |
| 3 | Provider test-account access and administrator consent for initial IdP, SIEM and connector targets | Prove real integrations; manifests and mocked adapters cannot be certified | Before each provider vertical slice |
| 4 | Two or more consenting pilot users and an organization/workgroup scenario | Family/Professional/Team/Business collaboration, sharing, offboarding and acceptance evidence | After internal negative and E2E tests |
| 5 | Windows/macOS test devices, Vlightsoft signing/notarization identities, Chrome/Edge publisher accounts | Desktop parity and signed distribution; real authenticator tests | Before client release |
| 6 | Approved billing rules/prices/tax/refund/trial terms and test-mode mappings if paid checkout is in the release | Prevent incorrect charges or entitlement grants | Before commercial activation |
| 7 | Independent web/extension/API/RLS penetration test, discovery-privacy and tenant-isolation reviews | External security acceptance for release; separate from developer tests | After reviewed candidate build |

No subscriptions, reviewer bookings, customer invitations or production charges are implied by preparing this register. Use secure forms or provider secret stores for access provisioning. A reviewer report must identify exact code/configuration scope; a reviewer name alone does not pass the gate.

## Current execution order

1. Close Phase 0 foundation findings and prepare the review evidence.
2. Phase 1: authentication delivery, extension security, desktop parity, sponsor privacy and typed AI/automation flows; hosted E2E.
3. Phase 2: complete Family/Professional workflows and revoke/expiry/offline/conflict evidence.
4. Phase 3: Team Capsule/Checkout, Consent Ledger, Work-Life Firewall and approvals.
5. Phase 4: Business governance, shared policy/Access Graph/Twin engine, lifecycle and Session Capsule.
6. Phase 5: SaaS/AI signature-domain completeness and real connector certification, usage/savings correctness and isolation evidence.
7. Phase 6: after prerequisite review acceptance, implement the privileged/runtime plan with provider-native expiry, kill/revoke reconciliation and attribution tests.
8. Phase 7 ready means every required Phase 0–6 exit gate has recorded acceptance; it does not mean enterprise features themselves are complete.

## Current blocker and limitations

Development Sent key, sandbox setting and SMS hook signing secret are saved. The Send SMS hook remains disabled. Direct Sent webhook-list validation returned HTTP 403 with a gateway/Cloudflare envelope. A successful authorized provider API path is needed before webhook registration and delivery validation. The response alone does not establish key validity or invalidity.

Only recoverable old-chat requirements can be accounted for; see `chat-requirements-register.md`. Keep unverified additions open rather than assuming the ZIP contains them.
