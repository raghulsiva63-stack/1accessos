import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readAppShell } from "./lib/app-source.mjs";

const migration = await readFile("supabase/migrations/20260905030000_phase5_business_organization.sql","utf8");
const advisorFixes = await readFile("supabase/migrations/20260905033000_phase5_advisor_fixes.sql","utf8");
const workspaceBootstrap = await readFile("supabase/migrations/20260905034500_phase5_business_workspace_bootstrap.sql","utf8");
const test = await readFile("supabase/tests/phase5_business_organization.sql","utf8");
const governanceMigration = await readFile("supabase/migrations/20260905055943_phase5_business_governance.sql","utf8");
const governanceAdvisorFixes = await readFile("supabase/migrations/20260905063000_phase5_governance_advisor_fixes.sql","utf8");
const governanceTest = await readFile("supabase/tests/phase5_business_governance.sql","utf8");
const organization = await readFile("apps/web/lib/organization/phase5.ts","utf8");
const component = await readFile("apps/web/components/organization-view.tsx","utf8");
const governanceComponent = await readFile("apps/web/components/organization-governance.tsx","utf8");
const page = await readAppShell();
const shared = await readFile("supabase/functions/_shared/billing.ts","utf8");
const webhook = await readFile("supabase/functions/stripe-webhook/index.ts","utf8");
const adr = await readFile("docs/architecture/ADR-0009-business-organization-boundary.md","utf8");
const governanceCheckpoint = await readFile("docs/phase5/business-governance-checkpoint.md","utf8");
const saasMigration = await readFile("supabase/migrations/20260905070916_phase5_saas_ai_platform.sql","utf8");
const saasAdvisorFixes = await readFile("supabase/migrations/20260905071944_phase5_saas_ai_advisor_fixes.sql","utf8");
const saasIntegrity = await readFile("supabase/migrations/20260905072509_phase5_saas_ai_integrity.sql","utf8");
const saasTest = await readFile("supabase/tests/phase5_saas_ai_platform.sql","utf8");
const saasClient = await readFile("apps/web/lib/saas-ai/phase5.ts","utf8");
const saasComponent = await readFile("apps/web/components/saas-ai-manager.tsx","utf8");
const connectorSdk = await readFile("packages/connectors/src/index.mjs","utf8");
const connectorTest = await readFile("packages/connectors/test/certification.test.mjs","utf8");
const phase5Api = await readFile("supabase/functions/v1/index.ts","utf8");
const openapi = await readFile("docs/api/openapi.yaml","utf8");

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
assert.match(component,/Up to 500 members and 500 workspaces/u);
assert.match(shared,/"business"/u);
assert.match(webhook,/"business"/u);
assert.match(adr,/Supabase Auth remains the account authentication provider/u);
for (const table of ["organization_invitations","organization_device_posture_reports"]) {
  assert.match(governanceMigration,new RegExp(`create table public\\.${table}`,"u"));
  assert.match(governanceMigration,new RegExp(`alter table public\\.${table} enable row level security`,"u"));
}
assert.match(governanceMigration,/private\.can_manage_organization_scope/u);
assert.match(governanceMigration,/private\.department_scope_contains/u);
assert.match(governanceMigration,/create or replace function public\.accept_organization_invitation/u);
assert.match(governanceMigration,/recipient_email_hash = private\.current_verified_email_hash\(\)/u);
assert.match(governanceMigration,/octet_length\(p_token_hash\) <> 32/u);
assert.match(governanceMigration,/for update;/u);
assert.match(governanceMigration,/revoke all on function public\.accept_organization_invitation\(uuid,bytea\) from public,anon/u);
assert.match(governanceMigration,/create or replace function public\.resolve_organization_policies/u);
assert.match(governanceMigration,/create or replace function public\.evaluate_organization_device_readiness/u);
assert.match(governanceMigration,/v_report\.verification_status <> 'verified'/u);
assert.match(governanceMigration,/create or replace function public\.export_organization_audit/u);
assert.match(governanceMigration,/limit least\(greatest\(p_limit,1\),1000\)/u);
assert.match(governanceAdvisorFixes,/create or replace function public\.accept_organization_invitation[\s\S]*security invoker/u);
assert.match(governanceAdvisorFixes,/create or replace function private\.provision_accepted_organization_invitation/u);
assert.match(governanceAdvisorFixes,/revoke all on function private\.provision_accepted_organization_invitation\(\)[\s\S]*from public,anon,authenticated/u);
assert.match(governanceAdvisorFixes,/create policy organization_invitations_update/u);
assert.match(governanceAdvisorFixes,/coalesce\(\(select current_setting/u);
assert.match(governanceAdvisorFixes,/create policy devices_read_authorized/u);
assert.match(governanceAdvisorFixes,/create policy audit_events_read/u);
assert.match(governanceAdvisorFixes,/organization_device_posture_device_fk_idx/u);
assert.match(governanceTest,/Scoped administrator changed another department/u);
assert.match(governanceTest,/Organization invitation replay unexpectedly succeeded/u);
assert.match(governanceTest,/Unverified self-report satisfied strict device policy/u);
assert.match(governanceTest,/Owner audit export returned no events/u);
assert.match(organization,/parseOrganizationInviteCsv/u);
assert.match(organization,/acceptOrganizationInvitation/u);
assert.match(organization,/organizationScopeAllows/u);
assert.match(governanceComponent,/Vault access requires a separate encrypted workspace invitation/u);
assert.match(governanceComponent,/peopleDepartments/u);
assert.match(governanceComponent,/global vault blocking remains disabled/u);
assert.match(page,/Organization membership accepted\. Vault access arrives separately/u);
assert.match(governanceCheckpoint,/Requirements-v2\.2 PAM, Secretless Relay and runtime credentials/u);
assert.doesNotMatch(`${organization}\n${component}\n${governanceComponent}`,/(?:master_password|recovery_key|service_role)/iu);

for (const table of [
  "connector_catalog","connector_certifications","msp_tenant_access","tenant_connectors",
  "connector_credentials","saas_applications","saas_identity_accounts","saas_contracts",
  "saas_licenses","saas_usage_facts","spend_budgets","saas_recommendations",
  "lifecycle_workflows","lifecycle_workflow_runs","saas_savings_ledger",
]) {
  assert.match(saasMigration,new RegExp(`create table public\\.${table}`,"u"));
  assert.match(saasMigration,new RegExp(`alter table public\\.${table} enable row level security`,"u"));
}
assert.ok((saasMigration.match(/^\('\w[\w-]*','/gmu) ?? []).length >= 25,"Phase 5 connector target catalog has fewer than 25 manifests");
assert.match(saasMigration,/adapter_stage in \('manifest','sandbox','certified','production'\)/u);
assert.match(saasMigration,/catalog row is not a claim of live vendor certification/iu);
assert.match(saasMigration,/connector_credentials_deny_clients/u);
assert.doesNotMatch(saasMigration,/grant (?:select|insert|update|delete)[^;]*connector_credentials[^;]*authenticated/iu);
assert.match(saasMigration,/managed_browser_domain/u);
assert.match(saasMigration,/create or replace function public\.reserve_phase5_budget/u);
assert.match(saasMigration,/create or replace function public\.refresh_saas_recommendations/u);
assert.match(saasMigration,/Proposal-only SaaS optimization/iu);
assert.match(saasMigration,/private\.can_view_phase5_tenant/u);
assert.match(saasMigration,/workspace-membership, or key-envelope policy/iu);
assert.match(saasAdvisorFixes,/duplicate_tool/u);
assert.match(saasAdvisorFixes,/identity_drift/u);
assert.doesNotMatch(saasAdvisorFixes,/for all to authenticated/iu);
assert.match(saasIntegrity,/production-verified connector adapter required/u);
assert.match(saasIntegrity,/connector_credentials/u);
assert.match(saasIntegrity,/configuration_no_secret_keys/u);
assert.match(saasIntegrity,/budget identity scope is outside tenant/u);
assert.match(saasTest,/Hard-limit enforcement failed/u);
assert.match(saasTest,/Manifest-only connector was marked healthy/u);
assert.match(saasTest,/Secret-shaped connector configuration reached metadata storage/u);
assert.match(saasTest,/MSP metadata approval created customer tenant membership/u);
assert.match(saasTest,/MSP console exposed customer key envelopes/u);
assert.match(saasTest,/Phase 5 cross-tenant read failure/u);
assert.match(connectorSdk,/issueEphemeralCredential/u);
assert.match(connectorSdk,/FORBIDDEN_TELEMETRY_KEYS/u);
assert.match(connectorSdk,/FORBIDDEN_DISCOVERY_KEYS/u);
assert.match(connectorSdk,/runConnectorCertification/u);
assert.match(connectorTest,/deterministic reconciliation/u);
assert.match(saasClient,/loadPhase5Snapshot/u);
assert.match(saasClient,/createSpendBudget/u);
assert.match(saasClient,/requestMspTenantAccess/u);
assert.match(saasComponent,/SaaS & AI Manager/u);
assert.match(saasComponent,/AI Spend Governor/u);
assert.match(saasComponent,/Waste Autopilot/u);
assert.match(saasComponent,/Integration Hub/u);
assert.match(saasComponent,/MSP tenant console/u);
assert.match(page,/id: "saas-ai"/u);
assert.match(phase5Api,/eq\("auth_user_id", userData\.user\.id\)/u);
assert.match(phase5Api,/path === "\/connectors\/catalog"/u);
assert.match(phase5Api,/path === "\/saas\/dashboard"/u);
assert.match(phase5Api,/connector_not_certified/u);
assert.match(phase5Api,/access_token/u);
assert.match(openapi,/\/saas\/recommendations\/refresh:/u);
assert.match(openapi,/privacy-minimized SaaS metadata/iu);
assert.doesNotMatch(`${saasClient}\n${saasComponent}`,/(?:service_role|master_password|recovery_key|raw_prompt)/iu);

console.log("Phase 5 Business governance, SaaS/AI control plane, connector SDK, MSP isolation, RLS and UI checks passed.");
