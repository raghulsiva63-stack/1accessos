# Passkey-X Enterprise Web v3

Release date: 27 Sep 2026 · Scope: hosted web client (`apps/web`) and Supabase.

## What organisations get

| Area | Capability | Enforced by |
|---|---|---|
| Admin console | Overview KPIs (org health, members at risk, 2-step coverage, inactive members, baseline coverage), People, Policies, Access review, Audit log, Directory | RPCs gated by tenant role / org admin role |
| People | Search and filter members, change tenant role (last owner protected), grant admin roles, suspend / reactivate / offboard with key revocation, CSV export | `set_organization_member_role`, `manage_organization_member_lifecycle` |
| Policies | Passkey required, 2-step required, approved devices, vault password strength, auto-lock timeout, clipboard clearing, breach monitoring, sharing boundary, export control, organization recovery (flag) — plus one-click recommended baseline | DB validation trigger; sharing boundary server-side; other controls in every client |
| Security Center | Local strength estimate, reuse, age, `http://` sites, missing 2FA; k-anonymity breach check (5-char SHA-1 prefix, padded) | Device only; admins receive aggregate counts only |
| Access review | Every shared workspace, members, role, last activity, expiry; set just-in-time expiry; remove access (revokes key envelopes, flags rotation); CSV evidence | `organization_access_review`, `set_workspace_member_expiry`, `admin_revoke_workspace_member`, pg_cron expiry job |
| Audit | Hash-chained v2 log, filters, CSV (formula-safe) / JSON export, one-click chain verification, append-only for organisations | `append_audit_event`, `verify_organization_audit_chain`, immutability trigger |
| Secure Send | E2E encrypted text/file links, burn after N views, expiry ≤ 30 days, optional passphrase, revoke, sender opt-in | Key only in URL fragment; server stores ciphertext + SHA-256(access proof) |
| Sign-in | Authenticator-app (TOTP) enrollment and challenge alongside SMS | Supabase Auth MFA (AAL2) |
| Vault password | Change while unlocked, policy-aware strength meter | `rotate_master_with_session` (optimistic concurrency, strong KDF only) |

## Security design notes

- **Zero knowledge is preserved.** No new path exposes plaintext, titles, URLs or usernames to the server or admins. Health reports are integer counts.
- **Audit v2 hash** = SHA-256 over `px-audit-v2|tenant|actor|action|target_type|target|metadata|prev_hash|occurred_at(UTC µs)`; appends are serialised per tenant with an advisory lock, so the chain cannot fork. v1 rows are verified for linkage only.
- **Secure Send**: HKDF-SHA256(link key ‖ Argon2id(passphrase)) → AES-256-GCM content key and an independent 256-bit access proof. A view is consumed only when SHA-256(proof) matches, so a wrong passphrase never burns a one-time link; 10 failed attempts lock the link.
- **KDF bounds**: clients reject Argon2id profiles below 64 MiB / 3 iterations or above 1 GiB / 12 iterations / 4 lanes from servers or export files.
- **RLS fixes**: `approvals_create`, `mission_items_create` and `organization_device_posture_self_report` now qualify outer columns (they previously compared columns with themselves).
- **Vault item heads** can only advance by exactly one revision.
- **Function exposure** follows the project convention: `SECURITY DEFINER` implementations live in the non-API `private` schema; `public` exposes `SECURITY INVOKER` wrappers.
- **Headers**: adds HSTS (1 year, subdomains) and `X-Permitted-Cross-Domain-Policies: none`; `connect-src` adds only `api.pwnedpasswords.com`.

## Operational checklist

1. Supabase → Auth → enable **Leaked password protection** (advisor warning).
2. Supabase → Auth → MFA: confirm **TOTP** is enabled.
3. Stripe is still in test mode — switch keys before selling paid plans.
4. Create an organisation (Business plan) and use **Admin console → Apply recommended baseline**.
5. Schedule a quarterly access review and keep the exported CSV and audit head hash as evidence.

## Not yet included

Organisation-assisted account recovery (policy flag only), SAML/SCIM SSO, SIEM streaming, break-glass emergency access, browser-store extension and signed desktop builds.
