begin;

-- Phase 5 SaaS/AI management is a metadata-only control plane. It never stores
-- vault plaintext, DOM/page content, raw connector tokens, or recovery material.
create table public.connector_catalog (
  connector_key text primary key check (connector_key ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
  display_name text not null check (length(display_name) between 2 and 120),
  category text not null check (category in (
    'identity','hris','ticketing','cloud','kubernetes','source_control','ci_cd',
    'saas_admin','finance_license','siem','messaging'
  )),
  auth_scheme text not null check (auth_scheme in ('oauth2','oidc','saml','scim','api_key','workload_identity')),
  capabilities text[] not null check (cardinality(capabilities) > 0),
  minimum_scopes text[] not null check (cardinality(minimum_scopes) > 0),
  adapter_stage text not null default 'manifest'
    check (adapter_stage in ('manifest','sandbox','certified','production')),
  quality_label text not null default 'contract_validated'
    check (quality_label in ('contract_validated','sandbox_tested','vendor_certified','production_verified')),
  phase5_target boolean not null default true,
  certification_version text,
  documentation_url text check (documentation_url is null or documentation_url ~ '^https://'),
  published boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((adapter_stage in ('certified','production')) = (certification_version is not null))
);

create table public.connector_certifications (
  id uuid primary key default gen_random_uuid(),
  connector_key text not null references public.connector_catalog(connector_key) on delete restrict,
  adapter_version text not null check (length(adapter_version) between 1 and 80),
  suite_version text not null check (length(suite_version) between 1 and 80),
  result text not null check (result in ('passed','failed','expired')),
  checks jsonb not null default '{}'::jsonb
    check (jsonb_typeof(checks) = 'object' and octet_length(convert_to(checks::text,'UTF8')) <= 32768),
  evidence_sha256 bytea not null check (octet_length(evidence_sha256) = 32),
  certified_at timestamptz not null default now(),
  expires_at timestamptz,
  unique (connector_key,adapter_version,suite_version),
  check (expires_at is null or expires_at > certified_at)
);

create table public.msp_tenant_access (
  id uuid primary key default gen_random_uuid(),
  provider_tenant_id uuid not null references public.tenants(id) on delete restrict,
  customer_tenant_id uuid not null references public.tenants(id) on delete restrict,
  permission text not null default 'view' check (permission in ('view','manage')),
  status text not null default 'pending' check (status in ('pending','active','revoked')),
  created_by uuid not null references public.identities(id) on delete restrict,
  approved_by uuid references public.identities(id) on delete restrict,
  approved_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (provider_tenant_id,customer_tenant_id),
  check (provider_tenant_id <> customer_tenant_id),
  check ((status = 'pending') = (approved_by is null and approved_at is null)),
  check ((status = 'revoked') = (revoked_at is not null))
);

create table public.tenant_connectors (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  connector_key text not null references public.connector_catalog(connector_key) on delete restrict,
  display_name text not null check (length(display_name) between 2 and 120),
  status text not null default 'draft'
    check (status in ('draft','authorizing','healthy','degraded','error','revoked')),
  granted_scopes text[] not null default '{}',
  configuration_summary jsonb not null default '{}'::jsonb
    check (jsonb_typeof(configuration_summary) = 'object' and octet_length(convert_to(configuration_summary::text,'UTF8')) <= 16384),
  token_expires_at timestamptz,
  token_rotation_state text not null default 'not_configured'
    check (token_rotation_state in ('not_configured','current','rotation_due','expired','revoked')),
  last_health_at timestamptz,
  last_sync_at timestamptz,
  next_sync_at timestamptz,
  discovered_records integer not null default 0 check (discovered_records >= 0),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,connector_key,display_name),
  unique (tenant_id,id)
);

-- Backend-only KMS envelope references. The browser cannot read this table.
create table public.connector_credentials (
  connector_id uuid primary key references public.tenant_connectors(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  encrypted_token_ref text not null check (encrypted_token_ref ~ '^kms://[A-Za-z0-9/_:.-]+$'),
  envelope_algorithm text not null default 'KMS_ENVELOPE' check (envelope_algorithm = 'KMS_ENVELOPE'),
  key_version integer not null check (key_version > 0),
  ciphertext_sha256 bytea not null check (octet_length(ciphertext_sha256) = 32),
  created_at timestamptz not null default now(),
  rotated_at timestamptz,
  revoked_at timestamptz,
  foreign key (tenant_id,connector_id) references public.tenant_connectors(tenant_id,id) on delete cascade
);

create table public.saas_applications (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  connector_id uuid,
  app_key text not null check (app_key ~ '^[a-z0-9][a-z0-9_.-]{1,119}$'),
  display_name text not null check (length(display_name) between 2 and 160),
  category text not null check (length(category) between 2 and 80),
  sanctioned_state text not null default 'unknown'
    check (sanctioned_state in ('unknown','sanctioned','unsanctioned','under_review','blocked')),
  data_risk text not null default 'unknown' check (data_risk in ('unknown','low','medium','high','restricted')),
  owner_identity_id uuid references public.identities(id) on delete set null,
  discovery_source text not null check (discovery_source in ('idp','sso','scim','expense','license','managed_browser_domain','manual')),
  external_ref_hash bytea check (external_ref_hash is null or octet_length(external_ref_hash) = 32),
  confidence numeric(5,4) check (confidence is null or confidence between 0 and 1),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,app_key),
  unique (tenant_id,id),
  foreign key (tenant_id,connector_id) references public.tenant_connectors(tenant_id,id) on delete set null (connector_id)
);

create table public.saas_identity_accounts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  application_id uuid not null,
  identity_id uuid references public.identities(id) on delete set null,
  account_ref_hash bytea not null check (octet_length(account_ref_hash) = 32),
  owner_state text not null default 'matched' check (owner_state in ('matched','unmatched','departed','shared','service')),
  account_status text not null default 'active' check (account_status in ('active','suspended','disabled','deleted','unknown')),
  privilege_tier text not null default 'standard' check (privilege_tier in ('standard','privileged','admin','unknown')),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  last_activity_bucket date,
  created_at timestamptz not null default now(),
  unique (tenant_id,application_id,account_ref_hash),
  unique (tenant_id,id),
  foreign key (tenant_id,application_id) references public.saas_applications(tenant_id,id) on delete cascade
);

create table public.saas_contracts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  application_id uuid not null,
  sku text not null check (length(sku) between 1 and 120),
  currency text not null check (currency in ('inr','usd')),
  unit_cost_minor bigint not null check (unit_cost_minor >= 0),
  billing_interval text not null check (billing_interval in ('month','year')),
  purchased_seats integer not null check (purchased_seats >= 0),
  renewal_at date,
  notice_days integer not null default 30 check (notice_days between 0 and 365),
  source text not null check (source in ('connector','invoice','expense','manual')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,application_id,sku),
  unique (tenant_id,id),
  foreign key (tenant_id,application_id) references public.saas_applications(tenant_id,id) on delete cascade
);

create table public.saas_licenses (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  contract_id uuid not null,
  account_id uuid,
  assigned_identity_id uuid references public.identities(id) on delete set null,
  status text not null default 'assigned' check (status in ('available','assigned','suspended','reclaim_proposed','reclaimed')),
  assigned_at timestamptz,
  last_used_on date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,id),
  foreign key (tenant_id,contract_id) references public.saas_contracts(tenant_id,id) on delete cascade,
  foreign key (tenant_id,account_id) references public.saas_identity_accounts(tenant_id,id) on delete set null (account_id)
);

create table public.saas_usage_facts (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  application_id uuid not null,
  identity_id uuid references public.identities(id) on delete set null,
  source text not null check (source in ('connector','usage_api','invoice','expense','manual')),
  activity_bucket date not null,
  metric text not null check (metric in ('active_identity','api_calls','ai_credits','cost_minor','license_use')),
  quantity bigint not null check (quantity >= 0),
  currency text check (currency is null or currency in ('inr','usd')),
  source_ref_hash bytea check (source_ref_hash is null or octet_length(source_ref_hash) = 32),
  created_at timestamptz not null default now(),
  unique nulls not distinct (tenant_id,application_id,identity_id,source,activity_bucket,metric,source_ref_hash),
  foreign key (tenant_id,application_id) references public.saas_applications(tenant_id,id) on delete cascade
);

create table public.spend_budgets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  scope_type text not null check (scope_type in ('tenant','department','team','identity','agent')),
  scope_id uuid,
  metric text not null check (metric in ('ai_cost_minor','ai_credits','saas_cost_minor')),
  currency text check (currency is null or currency in ('inr','usd')),
  soft_limit bigint not null check (soft_limit >= 0),
  hard_limit bigint not null check (hard_limit >= soft_limit),
  consumed bigint not null default 0 check (consumed >= 0),
  period_start date not null,
  period_end date not null,
  enforcement text not null default 'approval' check (enforcement in ('alert','approval','block')),
  chargeback_tag text check (chargeback_tag is null or length(chargeback_tag) between 1 and 80),
  approval_policy_id uuid,
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (tenant_id,scope_type,scope_id,metric,currency,period_start),
  check ((scope_type = 'tenant' and scope_id is null) or (scope_type <> 'tenant' and scope_id is not null)),
  check (period_end > period_start),
  check ((metric = 'ai_credits' and currency is null) or (metric <> 'ai_credits' and currency is not null))
);

create table public.saas_recommendations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  application_id uuid,
  recommendation_key text not null check (length(recommendation_key) between 8 and 200),
  kind text not null check (kind in ('unused_seats','duplicate_tool','renewal','ghost_account','identity_drift','budget_anomaly','owner_follow_up')),
  severity text not null check (severity in ('info','low','medium','high','critical')),
  title text not null check (length(title) between 3 and 180),
  explanation text not null check (length(explanation) between 3 and 1000),
  estimated_savings_minor bigint check (estimated_savings_minor is null or estimated_savings_minor >= 0),
  currency text check (currency is null or currency in ('inr','usd')),
  evidence jsonb not null default '{}'::jsonb
    check (jsonb_typeof(evidence) = 'object' and octet_length(convert_to(evidence::text,'UTF8')) <= 32768),
  destructive_action boolean not null default false,
  action_state text not null default 'proposed' check (action_state in ('proposed','approved','dismissed','completed','failed')),
  generated_at timestamptz not null default now(),
  reviewed_by uuid references public.identities(id) on delete set null,
  reviewed_at timestamptz,
  unique (tenant_id,recommendation_key),
  unique (tenant_id,id),
  foreign key (tenant_id,application_id) references public.saas_applications(tenant_id,id) on delete cascade
);

create table public.lifecycle_workflows (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  display_name text not null check (length(display_name) between 3 and 160),
  trigger_type text not null check (trigger_type in ('joiner','mover','leaver','access_review','license_reclaim','renewal_notice','budget_threshold')),
  action_type text not null check (action_type in ('notify','create_review','propose_reclaim','propose_deprovision','apply_tag','webhook')),
  execution_mode text not null default 'proposal' check (execution_mode in ('proposal','automatic')),
  destructive_action boolean not null default false,
  approval_required boolean not null default true,
  definition jsonb not null default '{}'::jsonb
    check (jsonb_typeof(definition) = 'object' and octet_length(convert_to(definition::text,'UTF8')) <= 32768),
  enabled boolean not null default false,
  version integer not null default 1 check (version > 0),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,id),
  check (not destructive_action or approval_required or execution_mode = 'proposal')
);

create table public.lifecycle_workflow_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workflow_id uuid not null,
  idempotency_key text not null check (length(idempotency_key) between 8 and 200),
  trigger_ref_hash bytea not null check (octet_length(trigger_ref_hash) = 32),
  status text not null default 'proposed' check (status in ('proposed','awaiting_approval','approved','running','completed','failed','cancelled')),
  result_summary jsonb not null default '{}'::jsonb
    check (jsonb_typeof(result_summary) = 'object' and octet_length(convert_to(result_summary::text,'UTF8')) <= 32768),
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  unique (tenant_id,idempotency_key),
  foreign key (tenant_id,workflow_id) references public.lifecycle_workflows(tenant_id,id) on delete restrict
);

create table public.saas_savings_ledger (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  recommendation_id uuid references public.saas_recommendations(id) on delete set null,
  application_id uuid,
  measurement text not null check (measurement in ('estimated','realized')),
  amount_minor bigint not null check (amount_minor >= 0),
  currency text not null check (currency in ('inr','usd')),
  period_start date not null,
  period_end date not null,
  evidence_ref_hash bytea not null check (octet_length(evidence_ref_hash) = 32),
  recorded_by uuid references public.identities(id) on delete set null,
  recorded_at timestamptz not null default now(),
  check (period_end > period_start),
  foreign key (tenant_id,application_id) references public.saas_applications(tenant_id,id) on delete cascade,
  foreign key (tenant_id,recommendation_id) references public.saas_recommendations(tenant_id,id) on delete set null (recommendation_id)
);

create index connector_certifications_result_idx on public.connector_certifications(result,expires_at);
create index msp_tenant_access_customer_idx on public.msp_tenant_access(customer_tenant_id,status);
create index msp_tenant_access_provider_idx on public.msp_tenant_access(provider_tenant_id,status);
create index tenant_connectors_health_idx on public.tenant_connectors(tenant_id,status,last_health_at);
create index tenant_connectors_created_by_idx on public.tenant_connectors(created_by);
create index connector_credentials_tenant_idx on public.connector_credentials(tenant_id);
create index saas_applications_owner_idx on public.saas_applications(owner_identity_id) where owner_identity_id is not null;
create index saas_applications_tenant_risk_idx on public.saas_applications(tenant_id,sanctioned_state,data_risk);
create index saas_identity_accounts_identity_idx on public.saas_identity_accounts(identity_id) where identity_id is not null;
create index saas_identity_accounts_ghost_idx on public.saas_identity_accounts(tenant_id,owner_state,account_status);
create index saas_contracts_renewal_idx on public.saas_contracts(tenant_id,renewal_at) where renewal_at is not null;
create index saas_licenses_contract_status_idx on public.saas_licenses(tenant_id,contract_id,status);
create index saas_licenses_identity_idx on public.saas_licenses(assigned_identity_id) where assigned_identity_id is not null;
create index saas_usage_facts_rollup_idx on public.saas_usage_facts(tenant_id,activity_bucket,metric);
create index spend_budgets_active_idx on public.spend_budgets(tenant_id,period_start,period_end);
create index spend_budgets_created_by_idx on public.spend_budgets(created_by);
create index saas_recommendations_queue_idx on public.saas_recommendations(tenant_id,action_state,severity,generated_at desc);
create index saas_recommendations_reviewer_idx on public.saas_recommendations(reviewed_by) where reviewed_by is not null;
create index lifecycle_workflows_tenant_enabled_idx on public.lifecycle_workflows(tenant_id,enabled,trigger_type);
create index lifecycle_workflows_created_by_idx on public.lifecycle_workflows(created_by);
create index lifecycle_workflow_runs_workflow_idx on public.lifecycle_workflow_runs(workflow_id,created_at desc);
create index saas_savings_rollup_idx on public.saas_savings_ledger(tenant_id,measurement,currency,period_end);
create index saas_savings_recommendation_idx on public.saas_savings_ledger(recommendation_id) where recommendation_id is not null;
create index saas_savings_recorded_by_idx on public.saas_savings_ledger(recorded_by) where recorded_by is not null;

create or replace function private.prevent_phase5_tenant_change()
returns trigger language plpgsql security invoker set search_path = ''
as $$
begin
  if new.tenant_id <> old.tenant_id then
    raise exception 'tenant assignment is immutable' using errcode = '42501';
  end if;
  return new;
end
$$;

create or replace function private.prevent_msp_tenant_change()
returns trigger language plpgsql security invoker set search_path = ''
as $$
begin
  if new.provider_tenant_id <> old.provider_tenant_id
    or new.customer_tenant_id <> old.customer_tenant_id then
    raise exception 'MSP tenant relationship is immutable' using errcode = '42501';
  end if;
  return new;
end
$$;

create or replace function private.prevent_connector_catalog_mutation()
returns trigger language plpgsql security invoker set search_path = ''
as $$
begin
  raise exception 'published connector catalog is immutable' using errcode = '42501';
end
$$;

create trigger connector_catalog_immutable before update or delete on public.connector_catalog
for each row execute function private.prevent_connector_catalog_mutation();

create trigger tenant_connectors_tenant_immutable before update on public.tenant_connectors
for each row execute function private.prevent_phase5_tenant_change();
create trigger saas_applications_tenant_immutable before update on public.saas_applications
for each row execute function private.prevent_phase5_tenant_change();
create trigger saas_identity_accounts_tenant_immutable before update on public.saas_identity_accounts
for each row execute function private.prevent_phase5_tenant_change();
create trigger saas_contracts_tenant_immutable before update on public.saas_contracts
for each row execute function private.prevent_phase5_tenant_change();
create trigger saas_licenses_tenant_immutable before update on public.saas_licenses
for each row execute function private.prevent_phase5_tenant_change();
create trigger spend_budgets_tenant_immutable before update on public.spend_budgets
for each row execute function private.prevent_phase5_tenant_change();
create trigger saas_recommendations_tenant_immutable before update on public.saas_recommendations
for each row execute function private.prevent_phase5_tenant_change();
create trigger lifecycle_workflows_tenant_immutable before update on public.lifecycle_workflows
for each row execute function private.prevent_phase5_tenant_change();
create trigger msp_tenant_access_tenants_immutable before update on public.msp_tenant_access
for each row execute function private.prevent_msp_tenant_change();

-- The MSP console grants access only to derived SaaS/security metadata. It does
-- not participate in any vault, workspace-membership, or key-envelope policy.
create or replace function private.can_view_phase5_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin','member','auditor']) or exists (
    select 1 from public.msp_tenant_access access
    where access.customer_tenant_id = target_tenant
      and access.status = 'active'
      and private.has_tenant_role(access.provider_tenant_id,array['owner','admin','member','auditor'])
  )
$$;

create or replace function private.can_manage_phase5_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin'])
    or private.can_manage_organization(target_tenant,array['organization_admin','security_admin','billing_admin'])
    or exists (
      select 1 from public.msp_tenant_access access
      where access.customer_tenant_id = target_tenant
        and access.status = 'active' and access.permission = 'manage'
        and private.has_tenant_role(access.provider_tenant_id,array['owner','admin'])
    )
$$;

create or replace function private.require_phase5_entitlement()
returns trigger language plpgsql security invoker set search_path = ''
as $$
begin
  if not private.has_business_entitlement(new.tenant_id) then
    raise exception 'Business SaaS and AI entitlement required' using errcode = '42501';
  end if;
  return new;
end
$$;

create trigger tenant_connectors_entitlement before insert on public.tenant_connectors
for each row execute function private.require_phase5_entitlement();
create trigger saas_applications_entitlement before insert on public.saas_applications
for each row execute function private.require_phase5_entitlement();
create trigger saas_contracts_entitlement before insert on public.saas_contracts
for each row execute function private.require_phase5_entitlement();
create trigger spend_budgets_entitlement before insert on public.spend_budgets
for each row execute function private.require_phase5_entitlement();
create trigger lifecycle_workflows_entitlement before insert on public.lifecycle_workflows
for each row execute function private.require_phase5_entitlement();

-- Deterministic recommendation generation. It proposes actions only and does not
-- call connector provision/deprovision methods.
create or replace function public.refresh_saas_recommendations(p_tenant_id uuid)
returns integer language plpgsql security invoker set search_path = ''
as $$
declare v_count integer := 0; v_rows integer := 0;
begin
  if not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_phase5_tenant(p_tenant_id) then
    raise exception 'SaaS manager permission required' using errcode = '42501';
  end if;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,
    estimated_savings_minor,currency,evidence,destructive_action
  )
  select contract.tenant_id,contract.application_id,
    'unused-seats:' || contract.id::text || ':' || current_date::text,
    'unused_seats','medium','Review unused ' || app.display_name || ' seats',
    (contract.purchased_seats - count(license.id))::text || ' purchased seats are currently unassigned.',
    (contract.purchased_seats - count(license.id)) * contract.unit_cost_minor,
    contract.currency,
    jsonb_build_object('contract_id',contract.id,'purchased',contract.purchased_seats,'assigned',count(license.id),'source','license_inventory'),
    true
  from public.saas_contracts contract
  join public.saas_applications app on app.tenant_id = contract.tenant_id and app.id = contract.application_id
  left join public.saas_licenses license on license.tenant_id = contract.tenant_id
    and license.contract_id = contract.id and license.status in ('assigned','suspended')
  where contract.tenant_id = p_tenant_id
  group by contract.id,app.display_name
  having contract.purchased_seats > count(license.id)
  on conflict (tenant_id,recommendation_key) do update set
    explanation = excluded.explanation, estimated_savings_minor = excluded.estimated_savings_minor,
    currency = excluded.currency, evidence = excluded.evidence, generated_at = now();
  get diagnostics v_rows = row_count;
  v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select account.tenant_id,account.application_id,
    'ghost:' || account.id::text,
    'ghost_account',case when account.privilege_tier in ('admin','privileged') then 'high' else 'medium' end,
    'Review unmatched ' || app.display_name || ' account',
    'The account has no confirmed active owner. Reconcile identity evidence before changing access.',
    jsonb_build_object('account_id',account.id,'owner_state',account.owner_state,'privilege_tier',account.privilege_tier,'source','approved_connector_metadata')
  from public.saas_identity_accounts account
  join public.saas_applications app on app.tenant_id = account.tenant_id and app.id = account.application_id
  where account.tenant_id = p_tenant_id and account.owner_state in ('unmatched','departed')
    and account.account_status = 'active'
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity, explanation = excluded.explanation,
    evidence = excluded.evidence, generated_at = now();
  get diagnostics v_rows = row_count;
  v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select contract.tenant_id,contract.application_id,
    'renewal:' || contract.id::text || ':' || contract.renewal_at::text,
    'renewal',case when contract.renewal_at <= current_date + 30 then 'high' else 'medium' end,
    app.display_name || ' renewal needs review',
    'Renewal is due on ' || contract.renewal_at::text || '. Confirm ownership, usage, notice period, and commercial terms.',
    jsonb_build_object('contract_id',contract.id,'renewal_at',contract.renewal_at,'notice_days',contract.notice_days)
  from public.saas_contracts contract
  join public.saas_applications app on app.tenant_id = contract.tenant_id and app.id = contract.application_id
  where contract.tenant_id = p_tenant_id
    and contract.renewal_at between current_date and current_date + 90
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity, explanation = excluded.explanation,
    evidence = excluded.evidence, generated_at = now();
  get diagnostics v_rows = row_count;
  v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select budget.tenant_id,'budget:' || budget.id::text || ':' || budget.period_start::text,
    'budget_anomaly',case when budget.consumed >= budget.hard_limit then 'critical' else 'high' end,
    'Spend budget threshold reached',
    'Usage reached ' || budget.consumed::text || ' of the ' || budget.hard_limit::text || ' hard limit. Enforcement is ' || budget.enforcement || '.',
    jsonb_build_object('budget_id',budget.id,'metric',budget.metric,'consumed',budget.consumed,'soft_limit',budget.soft_limit,'hard_limit',budget.hard_limit,'enforcement',budget.enforcement)
  from public.spend_budgets budget
  where budget.tenant_id = p_tenant_id and current_date between budget.period_start and budget.period_end
    and budget.consumed >= budget.soft_limit
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity, explanation = excluded.explanation,
    evidence = excluded.evidence, generated_at = now();
  get diagnostics v_rows = row_count;
  v_count := v_count + v_rows;
  return v_count;
end
$$;

create or replace function public.phase5_saas_dashboard(p_tenant_id uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$
  select case when private.can_view_phase5_tenant(p_tenant_id) then jsonb_build_object(
    'applications',(select count(*) from public.saas_applications app where app.tenant_id = p_tenant_id),
    'unsanctioned_apps',(select count(*) from public.saas_applications app where app.tenant_id = p_tenant_id and app.sanctioned_state = 'unsanctioned'),
    'ghost_accounts',(select count(*) from public.saas_identity_accounts account where account.tenant_id = p_tenant_id and account.owner_state in ('unmatched','departed') and account.account_status = 'active'),
    'active_connectors',(select count(*) from public.tenant_connectors connector where connector.tenant_id = p_tenant_id and connector.status = 'healthy'),
    'open_recommendations',(select count(*) from public.saas_recommendations recommendation where recommendation.tenant_id = p_tenant_id and recommendation.action_state = 'proposed'),
    'estimated_savings',(select coalesce(jsonb_object_agg(currency,total), '{}'::jsonb) from (
      select currency,sum(estimated_savings_minor) total from public.saas_recommendations
      where tenant_id = p_tenant_id and action_state = 'proposed' and estimated_savings_minor is not null group by currency
    ) savings),
    'realized_savings',(select coalesce(jsonb_object_agg(currency,total), '{}'::jsonb) from (
      select currency,sum(amount_minor) total from public.saas_savings_ledger
      where tenant_id = p_tenant_id and measurement = 'realized' group by currency
    ) savings)
  ) else null end
$$;

-- Backend-only atomic budget reservation. Browser input cannot self-credit or
-- bypass hard caps; external usage collectors call this with service_role.
create or replace function public.reserve_phase5_budget(
  p_tenant_id uuid,p_budget_id uuid,p_quantity bigint,p_source_ref_hash bytea
) returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare v_budget public.spend_budgets%rowtype; v_next bigint;
begin
  if p_quantity <= 0 or octet_length(p_source_ref_hash) <> 32 then
    raise exception 'invalid usage reservation' using errcode = '22023';
  end if;
  select * into v_budget from public.spend_budgets budget
  where budget.id = p_budget_id and budget.tenant_id = p_tenant_id
    and current_date between budget.period_start and budget.period_end for update;
  if not found then raise exception 'active budget not found' using errcode = 'P0002'; end if;
  v_next := v_budget.consumed + p_quantity;
  if v_next > v_budget.hard_limit and v_budget.enforcement in ('block','approval') then
    return jsonb_build_object('decision',case when v_budget.enforcement = 'block' then 'blocked' else 'approval_required' end,'consumed',v_budget.consumed,'requested',p_quantity,'hard_limit',v_budget.hard_limit);
  end if;
  update public.spend_budgets set consumed = v_next,updated_at = now() where id = v_budget.id;
  return jsonb_build_object('decision',case when v_next >= v_budget.soft_limit then 'allowed_with_alert' else 'allowed' end,'consumed',v_next,'hard_limit',v_budget.hard_limit);
end
$$;

alter table public.connector_catalog enable row level security;
alter table public.connector_certifications enable row level security;
alter table public.msp_tenant_access enable row level security;
alter table public.tenant_connectors enable row level security;
alter table public.connector_credentials enable row level security;
alter table public.saas_applications enable row level security;
alter table public.saas_identity_accounts enable row level security;
alter table public.saas_contracts enable row level security;
alter table public.saas_licenses enable row level security;
alter table public.saas_usage_facts enable row level security;
alter table public.spend_budgets enable row level security;
alter table public.saas_recommendations enable row level security;
alter table public.lifecycle_workflows enable row level security;
alter table public.lifecycle_workflow_runs enable row level security;
alter table public.saas_savings_ledger enable row level security;

revoke all on public.connector_catalog,public.connector_certifications,public.msp_tenant_access,
  public.tenant_connectors,public.connector_credentials,public.saas_applications,
  public.saas_identity_accounts,public.saas_contracts,public.saas_licenses,
  public.saas_usage_facts,public.spend_budgets,public.saas_recommendations,
  public.lifecycle_workflows,public.lifecycle_workflow_runs,public.saas_savings_ledger
  from public,anon,authenticated;
grant select on public.connector_catalog,public.connector_certifications to anon,authenticated;
grant select,insert,update on public.msp_tenant_access to authenticated;
grant select,insert,update,delete on public.tenant_connectors,public.saas_applications,
  public.saas_identity_accounts,public.saas_contracts,public.saas_licenses,
  public.spend_budgets,public.saas_recommendations,public.lifecycle_workflows,
  public.lifecycle_workflow_runs,public.saas_savings_ledger to authenticated;
grant select on public.saas_usage_facts to authenticated;
grant select,insert,update,delete on public.connector_catalog,public.connector_certifications,
  public.msp_tenant_access,public.tenant_connectors,public.connector_credentials,
  public.saas_applications,public.saas_identity_accounts,public.saas_contracts,
  public.saas_licenses,public.saas_usage_facts,public.spend_budgets,
  public.saas_recommendations,public.lifecycle_workflows,public.lifecycle_workflow_runs,
  public.saas_savings_ledger to service_role;

create policy connector_catalog_public_read on public.connector_catalog for select to anon,authenticated using (published);
create policy connector_certifications_public_read on public.connector_certifications for select to anon,authenticated
using (result = 'passed' and (expires_at is null or expires_at > now()));
create policy connector_credentials_deny_clients on public.connector_credentials for all to anon,authenticated using (false) with check (false);

create policy msp_tenant_access_read on public.msp_tenant_access for select to authenticated
using (private.has_tenant_role(provider_tenant_id,array['owner','admin','member','auditor']) or private.has_tenant_role(customer_tenant_id,array['owner','admin','member','auditor']));
create policy msp_tenant_access_request on public.msp_tenant_access for insert to authenticated
with check (private.has_tenant_role(provider_tenant_id,array['owner','admin']) and created_by = private.current_identity_id() and status = 'pending' and approved_by is null);
create policy msp_tenant_access_approve on public.msp_tenant_access for update to authenticated
using (private.has_tenant_role(customer_tenant_id,array['owner','admin']))
with check (private.has_tenant_role(customer_tenant_id,array['owner','admin']));

create policy tenant_connectors_read on public.tenant_connectors for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy tenant_connectors_manage on public.tenant_connectors for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_applications_read on public.saas_applications for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_applications_manage on public.saas_applications for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_identity_accounts_read on public.saas_identity_accounts for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_identity_accounts_manage on public.saas_identity_accounts for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_contracts_read on public.saas_contracts for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_contracts_manage on public.saas_contracts for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_licenses_read on public.saas_licenses for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_licenses_manage on public.saas_licenses for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_usage_facts_read on public.saas_usage_facts for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy spend_budgets_read on public.spend_budgets for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy spend_budgets_manage on public.spend_budgets for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_recommendations_read on public.saas_recommendations for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_recommendations_manage on public.saas_recommendations for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy lifecycle_workflows_read on public.lifecycle_workflows for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy lifecycle_workflows_manage on public.lifecycle_workflows for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy lifecycle_workflow_runs_read on public.lifecycle_workflow_runs for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy lifecycle_workflow_runs_manage on public.lifecycle_workflow_runs for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));
create policy saas_savings_ledger_read on public.saas_savings_ledger for select to authenticated using (private.can_view_phase5_tenant(tenant_id));
create policy saas_savings_ledger_manage on public.saas_savings_ledger for all to authenticated using (private.can_manage_phase5_tenant(tenant_id)) with check (private.can_manage_phase5_tenant(tenant_id));

revoke all on function private.prevent_phase5_tenant_change(),private.prevent_msp_tenant_change(),private.prevent_connector_catalog_mutation(),
  private.can_view_phase5_tenant(uuid),private.can_manage_phase5_tenant(uuid),private.require_phase5_entitlement()
  from public,anon,authenticated;
grant execute on function private.can_view_phase5_tenant(uuid),private.can_manage_phase5_tenant(uuid) to authenticated;
revoke all on function public.refresh_saas_recommendations(uuid),public.phase5_saas_dashboard(uuid),
  public.reserve_phase5_budget(uuid,uuid,bigint,bytea) from public,anon,authenticated;
grant execute on function public.refresh_saas_recommendations(uuid),public.phase5_saas_dashboard(uuid) to authenticated;
grant execute on function public.reserve_phase5_budget(uuid,uuid,bigint,bytea) to service_role;

insert into public.connector_catalog(
  connector_key,display_name,category,auth_scheme,capabilities,minimum_scopes,documentation_url
) values
('microsoft-entra-id','Microsoft Entra ID','identity','oauth2',array['authorize','discover','reconcile','health'],array['Directory.Read.All','AuditLog.Read.All'],'https://learn.microsoft.com/graph/permissions-reference'),
('okta','Okta','identity','oauth2',array['authorize','discover','reconcile','health'],array['okta.users.read','okta.apps.read'],'https://developer.okta.com/docs/guides/implement-oauth-for-okta/'),
('google-workspace','Google Workspace','identity','oauth2',array['authorize','discover','reconcile','health'],array['admin.directory.user.readonly','admin.directory.group.readonly'],'https://developers.google.com/admin-sdk/directory/v1/guides/authorizing'),
('onelogin','OneLogin','identity','oauth2',array['authorize','discover','reconcile','health'],array['Read users','Read apps'],'https://developers.onelogin.com/api-docs/2/getting-started/working-with-api-credentials'),
('duo','Duo','identity','api_key',array['authorize','discover','reconcile','health'],array['Admin API read'],'https://duo.com/docs/adminapi'),
('jumpcloud','JumpCloud','identity','api_key',array['authorize','discover','reconcile','health'],array['users.read','applications.read'],'https://docs.jumpcloud.com/api/2.0/index.html'),
('workday','Workday','hris','oauth2',array['authorize','discover','reconcile','health'],array['workers.read'],'https://community.workday.com/'),
('bamboohr','BambooHR','hris','api_key',array['authorize','discover','reconcile','health'],array['employees.read'],'https://documentation.bamboohr.com/docs'),
('rippling','Rippling','hris','oauth2',array['authorize','discover','reconcile','health'],array['employees.read'],'https://developer.rippling.com/'),
('hibob','HiBob','hris','api_key',array['authorize','discover','reconcile','health'],array['people.read'],'https://apidocs.hibob.com/'),
('servicenow','ServiceNow','ticketing','oauth2',array['authorize','discover','reconcile','health'],array['incident.read','request.read'],'https://developer.servicenow.com/'),
('jira-service-management','Jira Service Management','ticketing','oauth2',array['authorize','discover','reconcile','health'],array['read:jira-work','read:servicedesk-request'],'https://developer.atlassian.com/cloud/jira/service-desk/oauth-2-3lo-apps/'),
('github','GitHub','source_control','oauth2',array['authorize','discover','reconcile','health'],array['read:org'],'https://docs.github.com/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps'),
('gitlab','GitLab','source_control','oauth2',array['authorize','discover','reconcile','health'],array['read_api'],'https://docs.gitlab.com/integration/oauth_provider/'),
('bitbucket','Bitbucket Cloud','source_control','oauth2',array['authorize','discover','reconcile','health'],array['account','workspace','repository'],'https://developer.atlassian.com/cloud/bitbucket/oauth-2/'),
('circleci','CircleCI','ci_cd','api_key',array['authorize','discover','reconcile','health'],array['read'],'https://circleci.com/docs/managing-api-tokens/'),
('aws-iam-identity-center','AWS IAM Identity Center','cloud','workload_identity',array['authorize','discover','reconcile','health'],array['sso:ListInstances','identitystore:ListUsers'],'https://docs.aws.amazon.com/singlesignon/latest/APIReference/welcome.html'),
('microsoft-azure','Microsoft Azure','cloud','oauth2',array['authorize','discover','reconcile','health'],array['Reader'],'https://learn.microsoft.com/azure/role-based-access-control/built-in-roles'),
('google-cloud','Google Cloud','cloud','workload_identity',array['authorize','discover','reconcile','health'],array['resourcemanager.projects.get','iam.serviceAccounts.list'],'https://cloud.google.com/iam/docs/permissions-reference'),
('kubernetes','Kubernetes','kubernetes','workload_identity',array['authorize','discover','reconcile','health'],array['get','list','watch'],'https://kubernetes.io/docs/reference/access-authn-authz/rbac/'),
('slack','Slack','messaging','oauth2',array['authorize','discover','reconcile','health'],array['users:read','team:read'],'https://api.slack.com/scopes'),
('microsoft-365','Microsoft 365','saas_admin','oauth2',array['authorize','discover','reconcile','health','cost_license'],array['Organization.Read.All','Reports.Read.All'],'https://learn.microsoft.com/graph/permissions-reference'),
('salesforce','Salesforce','saas_admin','oauth2',array['authorize','discover','reconcile','health','cost_license'],array['api','id'],'https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_tokens_scopes.htm'),
('zoom','Zoom','saas_admin','oauth2',array['authorize','discover','reconcile','health','cost_license'],array['user:read:admin','account:read:admin'],'https://developers.zoom.us/docs/integrations/oauth-scopes/'),
('ramp','Ramp','finance_license','oauth2',array['authorize','discover','reconcile','health','cost_license'],array['transactions:read'],'https://docs.ramp.com/developer-api/v1/authorization'),
('coupa','Coupa','finance_license','oauth2',array['authorize','discover','reconcile','health','cost_license'],array['core.invoice.read'],'https://compass.coupa.com/en-us/products/product-documentation/integration-technical-documentation/the-coupa-core-api'),
('splunk','Splunk','siem','api_key',array['authorize','discover','reconcile','health'],array['search'],'https://dev.splunk.com/enterprise/docs/devtools/httpeventcollector/'),
('microsoft-sentinel','Microsoft Sentinel','siem','oauth2',array['authorize','discover','reconcile','health'],array['Microsoft.SecurityInsights/incidents/read'],'https://learn.microsoft.com/azure/sentinel/roles')
on conflict (connector_key) do nothing;

comment on table public.connector_catalog is 'Phase 5 connector contracts and honest maturity labels; a catalog row is not a claim of live vendor certification.';
comment on table public.connector_credentials is 'Backend-only opaque KMS references and integrity hashes; never browser-readable and never raw tokens.';
comment on table public.saas_usage_facts is 'Privacy-minimized activity buckets; no page content, form content, vault values, or raw prompts.';
comment on function public.refresh_saas_recommendations(uuid) is 'Proposal-only SaaS optimization. No connector mutation or destructive action is performed.';

commit;
