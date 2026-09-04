# ADR-0003: Identity and tenancy model

- Status: Accepted
- Date: 2026-09-04

## Decision

Authorization subjects are represented by `identities`, not directly by user profiles. Phase 0 supports human identities linked to Supabase Auth users. Future machine, workload, service-account, and AI-agent identities can be added without changing tenant-owned records.

Every account receives a personal tenant and personal workspace. Organization tenants and additional workspaces use the same membership model.

## Invariants

- Every tenant-owned row has a non-null `tenant_id`.
- Every workspace-owned row has both `tenant_id` and `workspace_id`.
- Workspace foreign keys include the tenant to prevent mismatched references.
- Authorization uses live membership records for sensitive operations.
- User-editable JWT metadata is never an authorization source.
- Revoked identities, devices, memberships, and API tokens fail closed.

## Initial roles

- Tenant: `owner`, `admin`, `member`, `auditor`
- Workspace: `owner`, `manager`, `editor`, `viewer`

Roles are catalog keys constrained at the database boundary in Phase 0 and may evolve into policy records later.
