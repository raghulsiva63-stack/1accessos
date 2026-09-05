# ADR-0008: Tenant billing and entitlement boundary

Status: Accepted  
Date: 2026-09-05

## Decision

Passkey-X subscriptions belong to a tenant, not to an individual identity.
Free, Personal, Family, and Team entitlements are stored in
`tenant_entitlements`. Browser clients may read the entitlement only through
RLS for a tenant where they have active membership; they cannot change it.

Stripe Checkout and the Customer Portal are hosted by Stripe. An authenticated
Supabase Edge Function validates that the caller is a tenant owner or admin,
maps the requested plan, interval, and currency to an allowlisted server-side
Price ID, and returns only a short-lived hosted URL. It never accepts a Price ID
from the browser.

A separate public Edge Function receives Stripe events because Stripe does not
possess a Supabase JWT. It must verify the raw request body with the endpoint
signing secret before parsing or applying it. The database records only the
event identifier, type, mode, payload hash, outcome, and tenant reference. Raw
event payloads are not persisted.

The application never grants an entitlement from a Checkout success URL.
Entitlements change only through the backend-only, idempotent
`apply_stripe_billing_event` transaction. Duplicate event IDs increment a
delivery counter and do not reapply state.

## Product catalog

- Free is internal and does not require a Stripe Product.
- Personal, Family, and Team are separate Stripe Products.
- Each Product has monthly and annual recurring Prices in INR and USD.
- The initial model is flat-rate. Seat-based and usage-based billing require a
  separate decision and migration.

## Security consequences

- Stripe and billing logs receive no vault ciphertext, plaintext fields, key
  material, recovery data, workspace names, or item metadata.
- Stripe restricted keys, webhook secrets, and Supabase backend keys exist only
  in Supabase Edge Function secrets.
- Test and live events cannot cross environments because every stored customer,
  subscription, and event records its Stripe mode.
- Automatic tax remains disabled until Vlightsoft confirms active tax
  registrations with qualified counsel or a tax adviser.
