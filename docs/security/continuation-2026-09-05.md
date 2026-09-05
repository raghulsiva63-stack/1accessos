# Development continuation — 2026-09-05

## Source and deployment distinction

Continued from the existing `passkey-x-src` working tree, based on commit `5b6d98a` with substantial pre-existing changes. Preserved those changes. The later deployment checkout at `9811651363b2a7fa8b3e35fa98c66757be323a41` lacks the newer SMS, governance and SaaS/AI implementation. Deployment history therefore does not establish that those features are live on the public website.

## Changes in this continuation

- Added executable tests of the actual Sent signature helper using independently generated Node HMAC fixtures. Database access is explicitly blocked by the test adapter.
- Covered valid signatures, payload/identifier/signature tampering, stale and future timestamps, missing/malformed headers, previous-key rotation/removal, missing configuration and public error redaction.
- Added `test:auth` to the root check and CI, plus the previously absent authentication static check in CI.
- Added the authoritative Phase 6 enterprise plan in `docs/phase6/enterprise-trust-plan.md`.

## Verification

- Existing root checks passed: phase-labelled static checks, 10 package tests and 3 CLI tests.
- Web production build passed, including TypeScript; 4 web crypto tests passed.
- New authentication runtime tests: 7 passed.
- Development database read-only inspection: 63 public tables, all 63 with RLS; latest migration `20260905080725`.
- Development Edge inspection: `sent-sms-hook` active version 2; `sent-webhook` active version 1.

These checks do not prove hosted signup/mail delivery, real SMS delivery, policy correctness of every table, browser E2E, external audit acceptance, or production connector certification.

## Remaining authentication activation

The dashboard is at GitHub sign-in for Supabase. The secure sign-in request was rejected by automatic approval review because GitHub account access for Supabase was not considered explicitly authorized. No credentials were submitted. Explicit approval is needed before another sign-in attempt. Runtime secret installation is unverified and was not performed in this continuation. No provided credential value is recorded in this file, fixtures or source.

After authenticated dashboard access, install the environment-scoped provider and signing secrets, keep sandbox mode enabled, verify signed sandbox delivery, register/verify the delivery webhook, then complete an approved real-device enrollment/sign-in/removal test. Keep Phone MFA hidden until this evidence exists. SMTP confirmation/recovery and DNS alignment evidence remain required.

## Release status

Strictly accepted Phase 0–5 releases: 0 of 6. The authoritative requirements traceability remains in effect. Independent reviews, pilots, provider accounts and real-device evidence cannot be replaced by generated fixtures or static source assertions.


## Follow-up with the resubmitted specification

The Functional and Technical DOCX files are byte-identical to the original upload. Corrected a substantive roadmap interpretation error: the explicitly revised Technical Appendix G/H governs phase numbering (0–8). Business governance is Phase 4, PAM/agent runtime is Phase 6, and enterprise work is Phase 7. ADR-0010, revised traceability and `privileged-runtime-plan.md` record the correction. Known chat additions are recorded separately; unseen messages were not recoverable in the context lookup.

GitHub verification and Supabase OAuth completed. The development dashboard positively identified `1accessos-dev` (`egqgzkirazabocqwdlfp`). `SENT_DM_API_KEY` and `SENT_DM_SMS_SANDBOX=true` were saved and their presence verified. Their values are not recorded here.

A read-only Sent webhook-list request returned HTTP 403 with a structured gateway/Cloudflare error envelope. This does not establish that the credential is invalid or that it has sufficient provider permissions. Webhook registration and provider validation remain blocked pending a successful authorized API request. No SMS was sent.

Connector SDK errors now use a constant public message, preventing short credentials, URLs and personal data from surviving pattern-only masking. Full root check passed: static checks, 11 package tests, 3 CLI tests and 7 authentication tests.

The HTTPS Send SMS hook was created in development with its enable switch off; the UI confirmed Disabled. The matching `SEND_SMS_HOOK_SECRET` was saved in Edge secrets. Provider webhook registration and signed delivery testing remain pending. No production configuration, customer messaging or deployment changed in this follow-up.

## Phase 1 extension sender-boundary fix

Added an executable authorization boundary for extension messages. Privileged commands now require the exact extension popup and extension ID; content scripts may only submit bounded login candidates from the browser-identified top frame with matching sender/tab/payload origins. Both fill paths target frame 0, and content-side fills reject subframes. Cross-origin navigation clears pending capture; same-origin login redirects retain the 60-second review window.

Extension production build and 8 tests passed (4 new executable boundary tests plus 4 existing security checks). This is a local verification result, not a browser E2E or independent security certification. Provider setup, pilots, client signing and independent reviews are detailed in `phase-0-7-release-inputs.md`.

The extension also had previously unchecked TypeScript configuration errors (DOM/worker duplicate globals, missing Vite/Node types and script-global collisions). These are fixed without suppressing type errors. Node build types are pinned and lockfile updated. The extension test command now gates bundling on `tsc --noEmit`; the final type check, build and all 8 tests passed.
