import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const migration = await readFile("supabase/migrations/20260905030000_phase5_business_organization.sql","utf8");
const advisorFixes = await readFile("supabase/migrations/20260905033000_phase5_advisor_fixes.sql","utf8");
const workspaceBootstrap = await readFile("supabase/migrations/20260905034500_phase5_business_workspace_bootstrap.sql","utf8");
const test = await readFile("supabase/tests/phase5_business_organization.sql","utf8");
const organization = await readFile("apps/web/lib/organization/phase5.ts","utf8");
const component = await readFile("apps/web/components/organization-view.tsx","utf8");
const page = await readFile("apps/web/app/page.tsx","utf8");
const shared = await readFile("supabase/functions/_shared/billing.ts","utf8");
const webhook = await readFile("supabase/functions/stripe-webhook/index.ts","utf8");
const adr = await readFile("docs/architecture/ADR-0009-business-organization-boundary.md","utf8");

for (const table of [
  "organization_departments","organization_teams","organization_groups",
  "organization_profiles","organization_team_memberships","organization_group_memberships",
  "organization_admin_assignments","organization_policies","identity_lifecycle_events",
]) {
  assert.match(migration,new RegExp(`create table public\\.${table}`,"u"));
  assert.match(migration,new RegExp(`alter table public\\.${table} enable row level security`,"u"));
}
assert.match(migration,/plan_code in \('free','personal','family','team','business'\)/u);
assert.match(migration,/private\.has_business_entitlement/u);
assert.match(migration,/private\.can_manage_organization/u);
assert.match(migration,/tenant_membership_business_key_revocation/u);
assert.match(migration,/key_rotation_required=true/u);
assert.match(migration,/Reactiva|Workspace membership and key access are deliberately not restored/iu);
assert.match(migration,/grant select,insert on public\.identity_lifecycle_events/u);
assert.doesNotMatch(migration,/grant (?:update|delete).*identity_lifecycle_events/iu);
assert.match(advisorFixes,/identity_lifecycle_events_subject_identity_idx/u);
assert.match(advisorFixes,/workspace_memberships_update/u);
assert.doesNotMatch(advisorFixes,/for all to authenticated/iu);
assert.match(workspaceBootstrap,/p_suite not in \('family','professional','team','business'\)/u);
assert.match(workspaceBootstrap,/security invoker/iu);
assert.match(test,/Phase 5 cross-tenant read failure/u);
assert.match(test,/Business entitlement was bypassed/u);
assert.match(test,/append-only history was mutable/u);
assert.match(test,/lifecycle revocation failure/u);
assert.match(organization,/onboard_organization_member/u);
assert.match(organization,/manage_organization_member_lifecycle/u);
assert.match(component,/Choose Business for a multi-department office/u);
assert.match(component,/Departments, teams, groups and directory/u);
assert.match(page,/OrganizationView/u);
assert.match(page,/Up to 500 members/u);
assert.match(shared,/"business"/u);
assert.match(webhook,/"business"/u);
assert.match(adr,/Supabase Auth remains the account authentication provider/u);
assert.doesNotMatch(`${organization}\n${component}`,/(?:master_password|recovery_key|service_role)/iu);

console.log("Phase 5 Business plan, office hierarchy, delegated roles, policy, lifecycle, RLS and UI checks passed.");
