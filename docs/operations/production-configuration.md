# Passkey-X production configuration

This is the operator checklist for the current web production environment.

## Environments

| Surface | Production value |
|---|---|
| Web | `https://passkey-x.com` |
| Netlify site | `passkey-x` |
| Supabase project | `1accessosprod` / `wkkmyacbhqloubtwvjom` |
| REST root | `https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1` |
| Passkey relying-party ID | `passkey-x.com` |
| Billing | Stripe sandbox/test mode |
| CAPTCHA | Cloudflare Turnstile |

Never place secret values in this document, Git, browser bundles, screenshots, tickets, or logs.

## Netlify production build variables

Public variables may be present in the compiled browser bundle:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`
- `NEXT_PUBLIC_PASSKEYS_ENABLED=true`
- `NEXT_PUBLIC_PHONE_MFA_ENABLED=false` until a real-device ceremony passes
- `NEXT_PUBLIC_BILLING_ENABLED=true`
- `NEXT_PUBLIC_PLAN_CATALOG_ENABLED=true`
- `NEXT_PUBLIC_STRIPE_TEST_MODE=true`
- `NEXT_PUBLIC_TURNSTILE_SITE_KEY`

Production deployment must build from the current GitHub `main` tree or an independently hash-verified equivalent. Do not upload `node_modules`, `.next`, temporary archives, local reports, or secret files.

## Supabase Edge Function secrets

Verify names and digests only. Never attempt to read or print stored values.

Required categories:

- Stripe restricted key, webhook secret, environment/livemode flag, production origin, billing activation, and the complete Price-ID mapping.
- Sent API key, signed hook/webhook secrets, SMS activation flags, and provider profile identifiers where applicable.
- Tenant-credential 256-bit master encryption key.
- Supabase-provided URL and runtime keys.
- Hosted-AI provider/gateway configuration when enabled.

Customer-supplied Sent credentials are encrypted server-side, write-only after entry, tenant-isolated, and unavailable to browser roles.

## Supabase Auth

- Site URL: `https://passkey-x.com`.
- Allow only reviewed redirect URLs.
- Cloudflare Turnstile enabled; frontend passes `captchaToken`.
- Custom SMTP sender: `Passkey-X <noreply@passkey-x.com>`.
- Verify SPF, DKIM, DMARC, confirmation, password reset, bounce handling, and security notifications.
- Enable leaked-password protection when the Supabase plan supports it.
- Keep phone MFA disabled until Sent onboarding and one approved device test pass.

## Edge Functions

Expected active functions:

- `v1` — authenticated vault/access/SaaS API
- `billing` — authenticated Stripe catalog, Checkout, and Portal
- `tenant-sms` — authenticated tenant notification management
- `account-lifecycle` — authenticated deletion preflight/execution
- `stripe-webhook` — signed Stripe callback
- `sent-webhook` — signed Sent delivery callback
- `sent-sms-hook` — signed Supabase Auth SMS hook

User-facing functions require JWT verification. Provider callbacks implement their own signature validation and replay controls.

## Database

- Every exposed `public` table must have RLS.
- Tenant predicates must validate membership; `TO authenticated` alone is insufficient.
- Secret-bearing tables intentionally have no browser policies/grants.
- `SECURITY DEFINER` functions must revoke `PUBLIC` execute and explicitly grant only required roles.
- Run security and performance advisors after every migration.
- Apply migrations to development first, then apply the identical reviewed SQL to production.

## Stripe launch

Current launch mode is sandbox. Before accepting real payments:

1. Replace every test Product/Price mapping with reviewed live-mode IDs.
2. Install a least-privilege live restricted key.
3. Create and verify a live webhook endpoint/signing secret.
4. Configure Customer Portal cancellation and payment-method management.
5. Decide tax registrations, refund policy, proration, dunning, trial, and invoice behavior.
6. Run success, 3DS, decline, replay, duplicate, portal, cancellation, downgrade, and seat-limit tests.
7. Set live/test flags consistently in Supabase and Netlify and redeploy.
8. Obtain finance/product launch approval.

Never mix test Price IDs or customers with live mode.

## Release verification

1. Source and secret scan pass.
2. Web TypeScript, lint, production build, and tests pass.
3. Database migrations match source; RLS and grants pass.
4. Edge Functions are active at the expected versions.
5. Public health and pricing load.
6. Disposable-user signup, confirmation, recovery-key download/recovery, login reset, and deletion pass.
7. Business owner tests Organizations, SaaS & AI, Runtime & Twin, Automations, notifications, and billing.
8. Provider webhook replay and signature-negative cases pass.
9. Record deploy ID, source commit, function versions, migration versions, reviewer, and unresolved warnings.

