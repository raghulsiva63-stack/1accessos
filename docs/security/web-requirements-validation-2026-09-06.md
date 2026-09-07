# Web requirements validation

Date: 2026-09-06

Updated: 2026-09-07

Authority: VLight Vault Suite Functional and Technical Specifications v2.2

Targets: `https://passkey-x.com`, Supabase `wkkmyacbhqloubtwvjom`, Stripe test mode

## Release decision

**UAT CANDIDATE — suitable for controlled web acceptance testing, not a GA
production claim.**

The reported recovery-key and package-selection defects are fixed in the
current production source. The onboarding state machine preserves recovery
material during same-account reauthentication instead of remounting vault
setup. The Stripe test restricted key, replacement webhook secret and all 20
Price IDs are installed, and billing is activated for the production-site
deployment. Customer Portal and old-webhook cleanup were reported complete by
the account owner but could not be read back through the connected Stripe
capability. Supabase production now has Turnstile enabled with the matching
secret and has a tenant-credential encryption master key. Custom SMTP is
enabled, but Supabase requires the SMTP password to be re-entered before the
sender address and standard ZeptoMail username can be saved; branded delivery
from `noreply@passkey-x.com` therefore remains unverified.

This report distinguishes source/schema foundations from production acceptance.
An unchecked external ceremony, provider connection, independent review, or
missing workflow is not converted into a pass by a successful build.

## Reported defects

| Area | Candidate result | Production state |
|---|---|---|
| Recovery-key download during first vault setup | Fixed. Same-user `SIGNED_IN` and token-refresh events preserve the pending setup; the download anchor stays attached for the click, its object URL remains valid for 60 seconds, failures are shown, and vault bootstrap is impossible until download succeeds and the user confirms the saved file. | Awaiting a disposable-user browser download/recovery ceremony after UAT publication. Existing vault recovery keys cannot be re-displayed because the service never stores their plaintext. |
| Login, signup and forgot-password | Reworked into distinct, CAPTCHA-ready flows with normalized email, password confirmation, enumeration-safe reset messaging and an explicit account-login/vault-password boundary. | Awaiting real confirmation and password-reset email ceremonies after UAT publication. |
| Package buttons | Fixed. A Personal, Family, Professional, Team or Business selection survives the sign-in/vault-unlock boundary and opens the selected plan in Plans & billing. | The current production deployment contains the candidate source and billing is activated in Stripe test mode. Authenticated Checkout/Portal/webhook acceptance remains open. |
| Package catalog | Seven published packages, 24 public price rows (four Free display rows plus 20 paid catalog rows), and 48 display entitlements are installed. Five Stripe test Products and all 20 paid recurring Prices were independently read back and matched for amount, currency, interval, lookup key and metadata. | Database/catalog, restricted test key, webhook secret and all 20 runtime Price-ID secrets are ready; billing is active. No billing customer or billing event exists yet, so Checkout/Portal/webhook E2E remains open. |
| Branded email | Signup, confirmation redirect, login-password reset, and account-security notification paths are wired to Supabase Auth. Custom SMTP is enabled with the configured ZeptoMail host, SSL port and sender name. | The saved sender address and SMTP username remain empty because Supabase requires the SMTP password for the update. Real delivery is not verified. A code path cannot prove that `noreply@passkey-x.com` is accepted, signed, delivered, bounced and recoverable. |
| Account deletion | Implemented internally with typed confirmation, fresh-session enforcement, retryable request state, storage/database cleanup and Auth-user deletion. | Personal-account UAT is ready. Shared-tenant owner transfer/blocking and rollback/retry ceremonies still require disposable users. |
| Customer SMS notifications | Implemented internally as opt-in, write-only tenant credential setup, organization/profile scoping, phone verification, idempotent production sends and signed delivery-state ingestion. | Requires one consenting phone and a Sent sender profile that is authorized to deliver to it. The global Supabase Auth SMS hook remains separate and disabled. |

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
| F-006 | Implemented internally | Access Twin simulations cover identity/resource removal and project closure against tenant-scoped graph snapshots. Real organization lifecycle acceptance remains open. |
| F-007 | Implemented internally | Hosted AI runs server-side through Netlify AI Gateway, sends aggregate counts only, rate-limits requests and persists request metadata without raw prompts or output. Provider observation, credit reconciliation and independent egress review remain open. |
| F-008 | Partial | Access requests/approvals and deterministic budget/policy primitives exist. Critical automation execution is proposal-only or local; complete policy-plus-human approval workflows are open. |
| F-009 | Partial | Signed Stripe events drive exact entitlements and cancellation returns to Free without deleting data. Impact preview and downgrade grace-period UX are not implemented. |
| F-010 | Partial | Append-only audit primitives exist. A complete Trust Receipt artifact and every sensitive Business grant/revoke journey are not implemented. |
| F-011 | Partial | Suspension/deprovisioning revokes membership and key envelopes and flags rotation. Outstanding-share handling, device policy completion and the rotation recommendation list are open. |
| F-012 | Implemented internally | Vault fields are encrypted client-side; provider errors are reduced to fixed public codes; secret-shaped connector output is rejected/redacted. Independent log/telemetry inspection remains open. |
| F-013 | Partial | HUMAN/service/machine/workload/agent identity kinds and attributable grants exist. Responsible-owner explanation and full non-human UI/runtime flow are open. |
| F-014 | Partial | Privacy-minimized discovery tables reject page/form/prompt/vault content by design. No production connector has yet supplied and proven an unmanaged application signal. |
| F-015 | Implemented internally | Atomic Spend Governor reservations enforce soft/hard thresholds and alert/approval/block actions in rollback tests. Real provider usage reconciliation and pilot evidence are open. |
| F-016 | Partial | Zero-standing resources, requests, approvals, expiry, kill controls and evidence records are implemented. Credential issuance remains fail-closed until accepted review evidence and a production-certified adapter exist. |
| F-017 | Partial | Agent profiles and tenant-scoped task capsules are implemented with cross-tenant validation and suspended-by-default state. No dynamic credential is issued without the same review/adapter gates. |
| F-018 | Partial | Verified posture policy evaluation and safe advisory UI exist. IdP/MDM attestation, enforced production denial and guided remediation are open. |
| F-019 | Partial | Customer-approved MSP metadata context is RLS-tested not to create tenant membership or expose key envelopes. Production context-switch/audit-mixing E2E and independent isolation review are open. |
| F-020 | Implemented internally | Tenant-scoped Flight Recorder evidence is append-only and hash chained, with actor/session/resource attribution. Independent tamper-evidence review and live adapter evidence remain open. |
| F-021 | Implemented internally | Waste Autopilot produces reviewable proposals and never performs deprovisioning in the analyzer. Real connector execution policy and pilot evidence are open. |
| F-022 | Partial | Connector health/scope/lifecycle contracts, encrypted-reference storage and 28 target manifests exist. The 25+ real adapters and certification evidence do not. |
| F-023 | Implemented internally | Access Twin 2.0 stores versioned graph snapshots and produces reviewable cross-domain impact simulations. Live IdP/MDM/SIEM connector evidence remains open. |

## Verified candidate evidence

- Repository checks: 18 package tests, 3 CLI tests and 15 auth/security tests pass.
- Web checks: production Next.js build, TypeScript, lint and 23 web tests pass.
- Production database: the v2.2 web control-plane migrations are applied. All
  18 new tables have RLS; direct browser roles have no privileges on the five
  secret-bearing tables.
- Production catalog: 7 published plans, 24 price display rows and 48
  entitlement display rows.
- Production functions: `account-lifecycle` and `tenant-sms` are active with
  JWT verification; the signed `sent-webhook` handler is updated. Existing
  `v1`, `billing`, `sent-sms-hook` and `stripe-webhook` functions remain active.
  Billing is guarded by a server-side activation flag and uses Stripe test mode.
- Production billing secrets/config: all 20 Stripe Price IDs, the replacement
  webhook signing secret, restricted test key, `STRIPE_LIVEMODE=false`, the
  production origin and `BILLING_ENABLED=true` are installed.
- Production authentication: Turnstile is enabled in Supabase Auth with its
  matching secret. The public site key is present in the web deployment.
- Production tenant credentials: a generated `TENANT_CREDENTIAL_MASTER_KEY`
  is installed in Supabase Edge Function secrets; its value is not recorded in
  this report.
- Supabase security advisor: leaked-password protection is disabled and requires
  an eligible Supabase plan. It also reports five authenticated
  `SECURITY DEFINER` RPCs. Those RPCs are intentional transactional boundaries:
  each fixes `search_path`, derives the actor from the JWT, validates tenant
  manager/Business access (or ownership for AI audit completion), and exposes no
  underlying secret-table grant. The five no-policy notices are intentional
  fail-closed backend-only tables.
- Netlify production deploy `6a9d55de2aaf03fcfe3c9d7b` is ready at
  `https://passkey-x.com` and was published on 2026-09-06. Netlify processed
  the security headers and server function, and its deploy secret scan found no
  matches. The deploy is an API upload without a Git commit reference.
- Public-browser verification confirms the access page and Turnstile disclosure
  load. Authenticated signup/recovery download, email delivery and billing
  ceremonies remain open.

## Required runtime completion

1. Run authenticated Stripe test Checkout, Portal, webhook and cancellation
   ceremonies. Customer Portal and previous-webhook cleanup were reported
   complete by the account owner but still require observed end-to-end proof.
2. Finish production custom SMTP by re-entering the ZeptoMail SMTP password in
   the secure Supabase form, saving sender `noreply@passkey-x.com` and username
   `emailapikey`, and verifying SPF, DKIM and DMARC. Then run confirmation,
   password-reset, security-notification and bounce tests with a disposable
   inbox.
3. Turnstile is enabled in Supabase Auth and the matching public site key is in
   the web deployment. Complete one live challenge plus email/password ceremony
   before accepting end-to-end CAPTCHA enforcement.
4. The customer notifications panel accepts each tenant's own Sent credential,
   validates its organization/profile scope, verifies a notification phone and
   performs real production sends. Run one consenting-device ceremony before
   accepting it. The global Supabase Auth SMS hook remains disabled until its
   separate provider delivery proof. SMS is verification/notification only and
   never decrypts or recovers a vault.
5. Complete the criteria marked Partial and obtain the listed
   independent reviews and device/provider/pilot evidence before a complete
   v2.2 production claim.

## Safe deployment order

1. Netlify UAT publication is complete; preserve the ready production deploy
   until a newer source artifact is built from current GitHub `main`.
2. Verify the public catalog, function routing and response headers after every
   future deploy.
3. Complete the live Turnstile challenge and email/password ceremony.
4. Run disposable-user signup, confirmation, recovery-key download, vault
   recovery and deletion tests.
5. Run Stripe test Checkout success, 3DS, decline, webhook replay, portal and
   cancellation tests.
6. Keep production activation flags off for any ceremony that has not passed.
