# Passkey-X application deployment — 2026-09-05

This candidate reconciles the recovered development source with GitHub main
`9811651363b2a7fa8b3e35fa98c66757be323a41`. It preserves the existing public
catalog and adds the recovered organization governance, SaaS/AI control plane,
optional SMS transport, extension sender checks, and corrected v2.2 roadmap.

The website continues to use the authorized Supabase development project
`egqgzkirazabocqwdlfp`. Publishing the web candidate does not constitute a
production-data migration or Phase 0–6 acceptance. Phone MFA and paid billing
remain disabled. The existing domain-bound passkey configuration is preserved.

## Deployment corrections

- CI now lints every web component, including the previously omitted
  organization and SaaS/AI screens.
- Initial data loads use effect cleanup and request versions so obsolete
  responses cannot replace a newer organization or managed-tenant snapshot.
- Switching the SaaS tenant context clears the prior snapshot immediately;
  context switching is disabled while a mutation is in progress.
- Bulk invitations calculate one seven-day expiry for the user action.
- Source-only deployment packaging excludes dependencies, build output,
  environment files and temporary upload archives.

## Verification

The recovered source passed 11 package tests, 3 CLI tests, 7 SMS authentication
tests, 8 extension tests with TypeScript/build, and 4 web crypto tests.
The candidate is gated on the expanded web lint and production build before
publication. Development inspection confirms 63 of 63 public tables have RLS.
The security advisor reports leaked-password protection disabled; no other
security advisory was returned by that check. This does not prove every RLS
policy is correct.

## Remaining acceptance

See `phase-0-7-release-inputs.md` and `../phase6/requirements-traceability.md`.
Hosted account/recovery/device ceremonies, SMS provider validation, real
connector adapters and certification, desktop distribution, pilots, and
independent reviews remain open. Phase 6 privileged runtime retains the
specification's independent crypto-review entry gate. None of these are
represented as completed by a successful web deployment.
