begin;

alter table public.saas_applications
  add constraint saas_applications_owner_membership_fkey
  foreign key (tenant_id,owner_identity_id)
  references public.tenant_memberships(tenant_id,identity_id)
  on delete set null (owner_identity_id);
alter table public.saas_identity_accounts
  add constraint saas_identity_accounts_membership_fkey
  foreign key (tenant_id,identity_id)
  references public.tenant_memberships(tenant_id,identity_id)
  on delete set null (identity_id);
alter table public.saas_licenses
  add constraint saas_licenses_membership_fkey
  foreign key (tenant_id,assigned_identity_id)
  references public.tenant_memberships(tenant_id,identity_id)
  on delete set null (assigned_identity_id);

create index saas_applications_owner_membership_fk_idx
  on public.saas_applications(tenant_id,owner_identity_id) where owner_identity_id is not null;
create index saas_identity_accounts_membership_fk_idx
  on public.saas_identity_accounts(tenant_id,identity_id) where identity_id is not null;
create index saas_licenses_membership_fk_idx
  on public.saas_licenses(tenant_id,assigned_identity_id) where assigned_identity_id is not null;

alter table public.tenant_connectors
  add constraint tenant_connectors_configuration_no_secret_keys check (
    not lower(configuration_summary::text) ~
      '"(access_token|refresh_token|connector_token|password|secret|private_key|recovery_key|page_content|form_content|dom_content|vault_content|raw_prompt)"[[:space:]]*:'
  );

create or replace function private.validate_phase5_connector_state()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_catalog public.connector_catalog%rowtype;
begin
  select * into v_catalog from public.connector_catalog catalog
  where catalog.connector_key = new.connector_key and catalog.published;
  if not found then raise exception 'published connector manifest required' using errcode = '23514'; end if;
  if new.status in ('healthy','degraded','error') then
    if v_catalog.adapter_stage <> 'production' or v_catalog.quality_label <> 'production_verified' then
      raise exception 'production-verified connector adapter required' using errcode = '23514';
    end if;
    if not (v_catalog.minimum_scopes <@ new.granted_scopes) then
      raise exception 'minimum connector scopes are missing' using errcode = '23514';
    end if;
    if not exists (
      select 1 from public.connector_credentials credential
      where credential.connector_id = new.id and credential.tenant_id = new.tenant_id
        and credential.revoked_at is null
    ) then
      raise exception 'active connector credential envelope required' using errcode = '23514';
    end if;
  end if;
  if new.status = 'revoked' and new.token_rotation_state <> 'revoked' then
    raise exception 'revoked connector must revoke token lifecycle state' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger tenant_connectors_state_integrity
before insert or update of connector_key,status,granted_scopes,token_rotation_state
on public.tenant_connectors for each row execute function private.validate_phase5_connector_state();

create or replace function private.validate_phase5_budget_scope()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.scope_type = 'department' and not exists (
    select 1 from public.organization_departments department
    where department.tenant_id = new.tenant_id and department.id = new.scope_id
  ) then raise exception 'budget department scope is outside tenant' using errcode = '23514';
  elsif new.scope_type = 'team' and not exists (
    select 1 from public.organization_teams team
    where team.tenant_id = new.tenant_id and team.id = new.scope_id
  ) then raise exception 'budget team scope is outside tenant' using errcode = '23514';
  elsif new.scope_type in ('identity','agent') and not exists (
    select 1 from public.tenant_memberships membership
    join public.identities identity on identity.id = membership.identity_id
    where membership.tenant_id = new.tenant_id and membership.identity_id = new.scope_id
      and membership.status = 'active'
      and (new.scope_type <> 'agent' or identity.kind = 'agent')
  ) then raise exception 'budget identity scope is outside tenant or has the wrong kind' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger spend_budgets_scope_integrity
before insert or update of tenant_id,scope_type,scope_id on public.spend_budgets
for each row execute function private.validate_phase5_budget_scope();

revoke all on function private.validate_phase5_connector_state(),private.validate_phase5_budget_scope()
  from public,anon,authenticated;

commit;
