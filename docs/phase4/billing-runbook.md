# Passkey-X billing activation runbook

Date: 2026-09-05

This runbook activates the Phase 4 billing code after the merchant catalog and
secrets are ready. Development uses Stripe test mode only.

## Stripe catalog

The Stripe test account contains one Product for each paid tier:

- Passkey-X Personal — `prod_VCYZL7EUCyOkpY`
- Passkey-X Family — `prod_VCYaHEZFtm4PTH`
- Passkey-X Team — `prod_VCYa8pj66QxSMw`

Each Product has four recurring Prices: monthly INR, annual INR, monthly USD,
and annual USD. Free access is provisioned internally and has no Stripe Product.
Prices are flat-rate in this release. Do not substitute a browser-supplied Price
ID and do not place different tiers on one Product.

## Edge Function secrets

Configure these in the Supabase development project, never in GitHub, Netlify,
the web bundle, screenshots, or chat:

```text
STRIPE_RESTRICTED_KEY
STRIPE_WEBHOOK_SECRET
STRIPE_LIVEMODE=false
APP_ORIGINS=https://passkey-x.com

STRIPE_PRICE_PERSONAL_MONTH_INR
STRIPE_PRICE_PERSONAL_YEAR_INR
STRIPE_PRICE_PERSONAL_MONTH_USD
STRIPE_PRICE_PERSONAL_YEAR_USD
STRIPE_PRICE_FAMILY_MONTH_INR
STRIPE_PRICE_FAMILY_YEAR_INR
STRIPE_PRICE_FAMILY_MONTH_USD
STRIPE_PRICE_FAMILY_YEAR_USD
STRIPE_PRICE_TEAM_MONTH_INR
STRIPE_PRICE_TEAM_YEAR_INR
STRIPE_PRICE_TEAM_MONTH_USD
STRIPE_PRICE_TEAM_YEAR_USD
```

Prefer a Stripe restricted key. It needs only the Customer, Checkout Session,
Price-read, Subscription-read, and Billing Portal Session operations exercised
by the two functions. Use a separate key in every environment and restrict its
network access where the platform supports a stable egress policy.

## Webhook destination

Use this development endpoint:

```text
https://egqgzkirazabocqwdlfp.supabase.co/functions/v1/stripe-webhook
```

Subscribe to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.paid`
- `invoice.payment_failed`

The endpoint has Supabase JWT verification disabled because Stripe cannot send a
Supabase session. The handler itself requires a valid Stripe signature, checks
test/live mode, hashes the raw payload, maps only allowlisted Prices, and calls
an idempotent database transaction.

## Activation

1. Confirm the twelve amounts and create the test Prices on the existing Products.
2. Configure the Customer Portal for plan changes, payment-method updates, and
   cancellation at period end.
3. Create the test webhook destination and store its signing secret.
4. Store the restricted key, Price IDs, mode, origin, and signing secret in
   Supabase Edge Function secrets.
5. Exercise success, 3DS, decline, payment failure, retry, downgrade,
   cancellation, duplicate delivery, and invalid-signature scenarios.
6. Set `NEXT_PUBLIC_BILLING_ENABLED=true` for the Netlify production context
   only after all test scenarios pass, then redeploy.

## Tax boundary

`automatic_tax` is intentionally absent. Stripe Tax must not be enabled until
Vlightsoft has a head-office address configured and has confirmed each active
tax registration with qualified counsel or a tax adviser. A sandbox registration
does not carry into live mode, and test transactions do not count toward nexus
threshold monitoring.

## Production separation

Production requires a separate Supabase project, a live-mode Stripe restricted
key, separate live Price IDs, a separate webhook destination and signing secret,
and a production-only Netlify environment. Never copy development users or test
Stripe identifiers into production.
