# Web requirements validation

Date: 2026-09-06

Authority: VLight Vault Suite Functional and Technical Specifications v2.2

Targets: `https://passkey-x.com`, Supabase `wkkmyacbhqloubtwvjom`, Stripe test mode

## Release decision

**HOLD — do not describe the complete v2.2 web product as production-ready.**

The reported recovery-key and package-selection defects are fixed in the
candidate source, and all local checks pass. The candidate is not yet published
because paid Checkout would still fail without its server-only Stripe restricted
key and Customer Portal configuration. The replacement webhook secret and all
20 Price IDs are installed, but the previous webhook endpoint still needs to be
removed to prevent rejected duplicate deliveries. Production custom SMTP is
saved as disabled, so `noreply@passkey-x.com` delivery cannot be claimed.

This report distinguishes source/schema foundations from production acceptance.
An unchecked external ceremony, provider connection, independent review, or
missing workflow is not converted into a pass by a successful build.

## Reported defects

| Area | Candidate result | Production state |
|---|---|---|
| Recovery-key download during first vault setup | Fixed. The download anchor stays attached for the click, its object URL remains valid for 60 seconds, failures are shown, and vault bootstrap is impossible until download succeeds and the user confirms the saved file. | Awaiting publication and a disposable-user browser download/recovery ceremony. Existing vault recovery keys cannot be re-displayed because the service never stores their plaintext. |
| Package buttons | Fixed. A Personal, Family, Professional, Team or Business selection survives the sign-in/vault-unlock boundary and opens the selected plan in Plans & billing. | Public production still runs the previous deploy, which says paid plans are unavailable. Checkout activation is blocked by the runtime items below. |
| Package catalog | Seven published packages, 24 public price rows (four Free display rows plus 20 paid catalog rows), and 48 display entitlements are installed. Five Stripe test Products and all 20 paid recurring Prices were independently read back and matched for amount, currency, interval, lookup key and metadata. | Database/catalog and all 20 runtime Price-ID secrets are ready. The restricted Stripe test key and Customer Portal configuration are still missing; no billing customer or billing event exists yet. |
| Branded email | Signup, confirmation redirect, login-password reset, and account-security notification paths are wired to Supabase Auth. | Custom SMTP sender/domain delivery is not verified in production. A code path cannot prove that `noreply@passkey-x.com` is accepted, signed, delivered, bounced and recoverable. |
| Account deletion | Not implemented as a safe end-user workflow. | Requires ownership-transfer rules for shared tenants, recent reauthentication, transactional key/data cleanup, Auth-user deletion, confirmation UX and rollback-safe E2E before it can be tested. |

## Functional acceptance criteria

`Implemented internally` means the repository and synthetic tests contain the
required control. It does not mean an independent reviewer or a real production
user ceremony has accepted it.

| ID | Code status | Evidence and remaining work |
|---|---|---|
| F-001 | Partial | Email signup, client-encrypted vault CRUD, extension save/fill code and recovery setup exist. Production email, real authenticator, published extension and complete later-visit E2E are open. |
| F-002 | Partial | The first-party sponsor card is Free/Home-only and has no third-party script or vault-data input. Privacy/ad review and hosted observation are open. |
| F-003 | Partial | Verified-email, one-time-fragment workspace invitations and encrypted key envelopes exist. Invite-email delivery and unregistered-recipient E2E are open. |
| F-004 | Partial | Access Capsules model reveal/fill-only, expiry, uses and revocation. Recipient-extension proof that normal UI never exposes the password is open. |
| F-005 | Partial | Mission definitions and assigned items are client-encrypted and runnable. The current model is workspace-scoped; the complete configured workspace-set journey and E2E are open. |
| F-006 | Not implemented | Organization lifecycle foundations exist, but Access Twin impact preview before removal/project closure does not. |
| F-007 | Not implemented | Local security checks exist; no approved hosted-AI provider path, raw-secret egress blocker ceremony or hosted credit accounting exists. |
| F-008 | Partial | Access requests/approvals and deterministic budget/policy primitives exist. Critical automation execution is proposal-only or local; complete policy-plus-human approval workflows are open. |
| F-009 | Partial | Signed Stripe events drive exact entitlements and cancellation returns to Free without deleting data. Impact preview and downgrade grace-period UX are not implemented. |
| F-010 | Partial | Append-only audit primitives exist. A complete Trust Receipt artifact and every sensitive Business grant/revoke journey are not implemented. |
| F-011 | Partial | Suspension/deprovisioning revokes membership and key envelopes and flags rotation. Outstanding-share handling, device policy completion and the rotation recommendation list are open. |
| F-012 | Implemented internally | Vault fields are encrypted client-side; provider errors are reduced to fixed public codes; secret-shaped connector output is rejected/redacted. Independent log/telemetry inspection remains open. |
| F-013 | Partial | HUMAN/service/machine/workload/agent identity kinds and attributable grants exist. Responsible-owner explanation and full non-human UI/runtime flow are open. |
| F-014 | Partial | Privacy-minimized discovery tables reject page/form/prompt/vault content by design. No production connector has yet supplied and proven an unmanaged application signal. |
| F-015 | Implemented internally | Atomic Spend Governor reservations enforce soft/hard thresholds and alert/approval/block actions in rollback tests. Real provider usage reconciliation and pilot evidence are open. |
| F-016 | Not implemented | Zero-standing privileged resources, JIT/JEA issuance and expiry revocation runtime are Phase 6 plan only. |
| F-017 | Not implemented | Dynamic short-lived agent credential brokerage and production adapters are Phase 6 plan only. |
| F-018 | Partial | Verified posture policy evaluation and safe advisory UI exist. IdP/MDM attestation, enforced production denial and guided remediation are open. |
| F-019 | Partial | Customer-approved MSP metadata context is RLS-tested not to create tenant membership or expose key envelopes. Production context-switch/audit-mixing E2E and independent isolation review are open. |
| F-020 | Not implemented | Privilege Flight Recorder runtime attribution is Phase 6 plan only. |
| F-021 | Implemented internally | Waste Autopilot produces reviewable proposals and never performs deprovisioning in the analyzer. Real connector execution policy and pilot evidence are open. |
| F-022 | Partial | Connector health/scope/lifecycle contracts, encrypted-reference storage and 28 target manifests exist. The 25+ real adapters and certification evidence do not. |
| F-023 | Not implemented | Access Twin 2.0 cross-domain simulation is not implemented. |

## Verified candidate evidence

- Repository checks: 18 package tests, 3 CLI tests and 15 auth/security tests pass.
- Web checks: production Next.js build, TypeScript, lint and 23 web tests pass.
- Production database: 63 of 63 public tables have RLS enabled.
- Production catalog: 7 published plans, 24 price display rows and 48
  entitlement display rows.
- Production functions: `v1`, `billing`, `sent-sms-hook`, `sent-webhook` and
  `stripe-webhook` are active. Billing remains fail-closed until explicitly
  activated with complete server secrets.
- Production billing secrets/config: all 20 Stripe Price IDs, the replacement
  webhook signing secret, `STRIPE_LIVEMODE=false`, the production origin and
  `BILLING_ENABLED=false` are installed. The restricted key is not installed.
- Supabase security advisor: one open warning, leaked-password protection
  disabled; it requires an eligible Supabase plan. Performance findings are
  informational unused indexes in a near-empty database.
- Current Netlify deploy is healthy but is the earlier build. Browser readback
  shows the public catalog disabled, confirming that the candidate fixes are not
  live yet.

## Required runtime completion

1. Create a Stripe **test-mode restricted key** with only the application
   permissions required to read Products/Prices and create/read Customers,
   Checkout Sessions and Billing Portal Sessions. Enter it directly into the
   Supabase production secret store as `STRIPE_RESTRICTED_KEY`; never paste it
   into chat.
2. Configure the Stripe test Customer Portal for subscription cancellation and
   payment-method management. The connected Stripe API exposes portal reads but
   not portal configuration writes.
3. The replacement Stripe test webhook and its signing secret are installed,
   together with all 20 verified Price IDs, `STRIPE_LIVEMODE=false` and the
   production origin. Remove the previous webhook endpoint in Stripe Dashboard,
   then enable `BILLING_ENABLED=true` only after an authenticated catalog
   request passes.
4. Finish production custom SMTP with a verified sending domain, SMTP host,
   port, username and password, sender `noreply@passkey-x.com`, and sender name
   `Passkey-X`. Verify SPF, DKIM and DMARC, then run confirmation, password-reset,
   security-notification and bounce tests with a disposable inbox.
5. Supply and enable matching Turnstile site/secret keys if CAPTCHA is required.
6. Complete Sent onboarding beyond `KYC_COMPLETED`, securely install a rotated
   production API key, register the signed provider hook, and explicitly approve
   one real-device delivery ceremony before setting `SENT_DM_SMS_ENABLED=true`
   or exposing phone MFA. A fresh production-only Auth-hook secret and the
   fail-closed production flags are already installed. SMS is verification only
   and never decrypts or recovers a vault.
7. Implement the criteria marked Partial/Not implemented and obtain the listed
   independent reviews and device/provider/pilot evidence before a complete
   v2.2 production claim.

## Safe deployment order

1. Complete Stripe and SMTP secret/configuration steps through secure provider
   forms.
2. Deploy the candidate to Netlify production.
3. Verify public catalog/readback and response headers.
4. Run disposable-user signup, confirmation, recovery-key download, vault
   recovery and deletion tests.
5. Run Stripe test Checkout success, 3DS, decline, webhook replay, portal and
   cancellation tests.
6. Keep production activation flags off for any ceremony that has not passed.
