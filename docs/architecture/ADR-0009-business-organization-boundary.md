# ADR-0009: Business organization and office metadata boundary

Date: 2026-09-05  
Status: Accepted for Phase 5 development

## Decision

Passkey-X uses **Team** for a single small workgroup and **Business** for a
multi-department office. Business is tenant-scoped and adds departments, teams,
groups, an employee directory, delegated administrator roles, policy inheritance,
and joiner/mover/leaver controls.

Supabase Auth remains the account authentication provider. It does not receive a
vault password and cannot decrypt a vault. Tenant memberships connect authenticated
identities to an organization; workspace memberships and client-created key
envelopes independently control access to encrypted vaults.

## Administrative metadata

Department, team, group, employee display name, job title, role, status and policy
configuration are visible tenant administrative metadata. They must never contain
passwords, tokens, recovery material, vault item names or other secret content.
Vault/workspace names and all vault payloads retain the existing ciphertext-only
contract.

## Roles

- Tenant `owner` and `admin` can manage the whole organization.
- `organization_admin` manages office structure and people.
- `security_admin` manages security policy and security lifecycle actions.
- `billing_admin` is reserved for billing delegation without vault access.
- `helpdesk_admin` manages employee profiles and lifecycle without changing
  organization structure.
- `auditor` reads authorized administrative and audit records without mutation.

Assignments are explicit, tenant-bound, revocable and may carry tenant,
department or team scope. Database policies resolve department descendants and
team membership before every scoped mutation. The UI exposes only the assignments
and targets the current administrator can use, but PostgreSQL remains the
authorization boundary for direct API clients.

## Invitation boundary

Organization invitations store only the SHA-256 hashes of the verified recipient
email and random 256-bit link token. The raw token stays in the URL fragment. The
acceptance function checks the authenticated identity, verified email hash, token,
status and expiry under a row lock before making the token unusable. It provisions
directory membership only. It cannot add a workspace membership or issue a key
envelope; encrypted vault access requires the separate Phase 2 invitation ceremony.

Bulk CSV onboarding is parsed locally and is capped at 200 rows. Passkey-X returns
the individual one-time links to the administrator for controlled delivery. It
does not claim email delivery until branded SMTP and delivery monitoring are
configured.

## Policy and device boundary

Effective policy resolution is deterministic: a team policy overrides its
department policy, and a department policy overrides the tenant default. Device
posture reports have an explicit source and verification status. A self-report can
provide readiness information but cannot satisfy a strict approved-device policy.
Only non-expired, verified and compliant MDM, IdP or attestation evidence can do
so. This checkpoint does not globally block vault entry; that requires an
independently reviewed device-bound session claim across every client.

## Audit export boundary

Tenant owners, tenant administrators and tenant-scoped security/auditor roles may
export at most 1,000 ordered, hash-chained audit events per request. This is an
evidence-download foundation, not automatic SIEM delivery, a retention guarantee
or a legal hold.

## Lifecycle invariant

Suspending or deprovisioning an employee suspends or revokes tenant/workspace
membership, revokes recipient key envelopes, marks affected workspaces for key
rotation, and appends a lifecycle event. Reactivation restores no old workspace
membership or key envelope. A manager must re-invite the employee and issue fresh
key material.

## Commercial boundary

Office controls require an active, trialing or past-due Stripe Business entitlement,
or an explicit manual Business entitlement for controlled development. Browser
state and redirect parameters never activate the feature.
