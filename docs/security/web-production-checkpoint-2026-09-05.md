# Web production checkpoint

Date: 2026-09-06
Target: `passkey-x.com` and Supabase project `wkkmyacbhqloubtwvjom`

This checkpoint records verified production infrastructure and remaining launch
dependencies. It is not a declaration that the complete v2.2 roadmap is
accepted.

## Installed and verified

- Applied 29 repository migrations, including the published v2.2 catalog and
  server-side billing-entitlement policy.
- Verified 63 of 63 public application tables have row-level security enabled.
- Supabase's production security advisor reports one Auth warning: leaked
  password protection is disabled.
- Ran nine applicable SQL acceptance suites inside transactions; all passed and
  rolled back their fixtures.
- Deployed the authenticated `v1` API and the billing, Send SMS, Sent webhook,
  and Stripe webhook handlers. Billing and Send SMS have separate server-side
  activation flags and remain fail-closed without complete server secrets.
- Configured Netlify production builds with the production Supabase URL and its
  public browser key. No service-role key or provider secret is shipped to the
  browser.
- Added identity/tenant/workspace-isolated local review routines, stronger
  passphrase generation, activation-gate tests, and stale-response protection
  when switching workspaces.
- Added conditional Cloudflare Turnstile support to sign-in, sign-up, password
  recovery and passkey sign-in. The widget remains absent until the production
  site key and matching Supabase Auth secret are installed together.
- The current Netlify production deploy is `6a9c5832264b658653936b8d`; Netlify
  reported the deploy ready, processed all four header rules, and found no
  secret-scan matches.
- Enabled Supabase Passkeys Beta for display name `Passkey-X`, relying-party ID
  `passkey-x.com`, and origin `https://passkey-x.com`.
- Enabled secure password change and current-password verification, set the
  password minimum to 12 characters with lowercase, uppercase, digit and symbol
  requirements, and reduced email OTP lifetime to 600 seconds with eight
  digits.
- Enabled all seven available account-security notification emails.

## Candidate fixes awaiting publication

- Recovery-key download now uses an attached anchor and delayed object-URL
  revocation. Vault bootstrap is deferred until download succeeds and the user
  confirms the saved file.
- Paid package selection now survives authentication and opens the selected
  package in the authenticated billing view.
- Five Stripe test Products and 20 recurring Prices were created and read back
  against the v2.2 amount/currency/interval/metadata contract.
- Installed all 20 Stripe Price-ID secrets and a replacement test-webhook
  signing secret in Supabase production. Billing remains disabled until the
  restricted key and Customer Portal are ready and the earlier duplicate
  webhook endpoint is removed.
- See `web-requirements-validation-2026-09-06.md` for the F-001–F-023 audit.

## Deliberately inactive

- Stripe test Checkout: awaiting the server-only restricted key, Customer
  Portal configuration, duplicate-webhook cleanup and end-to-end test
  ceremonies. The replacement webhook signing secret and Price IDs are
  installed. The billing endpoint returns `billing_disabled` unless the
  server-only activation flag is exactly `true`.
- Phone MFA: production Auth has phone disabled. A fresh production-only hook
  secret plus `SENT_DM_SMS_SANDBOX=false` and `SENT_DM_SMS_ENABLED=false` are
  installed; the Sent API key and provider webhook registration are not. The
  Send SMS endpoint remains fail-closed until the activation flag is explicitly
  changed after provider acceptance.
- CAPTCHA enforcement: the deployed client integration is ready, but the
  production Turnstile site key and matching Supabase Auth secret are not
  installed.
- Provider OAuth: production Auth currently reports all external providers
  disabled.

## Production Auth audit

- Site URL and the only redirect allow-list entry are both
  `https://passkey-x.com`.
- Email confirmation, secure email change, secure password change,
  current-password verification, TOTP MFA, refresh-token replay detection and
  the 15-minute AAL1 MFA limit are enabled.
- Passwords require at least 12 characters and one lowercase letter, uppercase
  letter, digit and symbol. Email OTPs use eight digits and expire after 600
  seconds.
- Passkey authentication is enabled for the production relying-party domain,
  and all seven available account-security notification emails are enabled.
- Server-side CAPTCHA enforcement remains disabled until the provider key pair
  is installed.
- Production custom SMTP is saved as disabled. The sender identity has been
  prepared as `Passkey-X <noreply@passkey-x.com>`, but SMTP host, port, username
  and password must be entered and saved before branded delivery can be tested.
- The project currently reports leaked-password protection unavailable/disabled.
  Leaked-password screening, configurable
  session timeboxes and SMS MFA require a paid plan.

## Evidence still required for a production-ready security product

- Independent cryptographic implementation review and resolved findings.
- Configure and verify production SMTP, SPF/DKIM/DMARC, email templates,
  password recovery, bounce handling, and security-notification ceremonies.
- One real production Sent delivery and signed delivery-webhook ceremony before
  phone MFA activation.
- Disposable-user end-to-end runs for account creation, recovery, vault CRUD,
  attachments, sharing, revocation, deletion and cross-tenant denial.
- Privacy/sponsor review and independent web/API/RLS penetration and isolation
  tests.
- Completion and acceptance of the remaining v2.2 named Phase 2-7 web workflows;
  schemas and UI foundations do not by themselves satisfy those exit gates.

Production currently contains two Auth users and two client-crypto profiles,
and no billing customers, billing events or SMS-delivery records. Transactional
acceptance suites did not leave fixtures behind.
