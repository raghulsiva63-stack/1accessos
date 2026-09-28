-- Exported from production supabase_migrations.schema_migrations (20260907100811_enterprise_entitlement_constraint_reconcile).
begin;

-- Keep the catalog-backed billing policy and the contract-provisioned
-- Enterprise entitlement compatible regardless of environment migration
-- history. Enterprise remains excluded from self-service subscriptions.
alter table public.tenant_entitlements
  drop constraint if exists tenant_entitlements_plan_code_check;
alter table public.tenant_entitlements
  add constraint tenant_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','professional','team','business','enterprise'));

commit;
