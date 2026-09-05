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
department or team scope. Phase 5 initially exposes whole-tenant management in the
UI; scoped assignments are persisted now so later enforcement can be introduced
without changing the data model.

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

