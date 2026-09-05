begin;

create or replace function private.enforce_tenant_member_limit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_limit integer;
  v_active integer;
begin
  if new.status <> 'active' then return new; end if;
  select max_members into v_limit
  from public.tenant_entitlements
  where tenant_id = new.tenant_id;
  if v_limit is null then v_limit := 1; end if;
  select count(*) into v_active
  from public.tenant_memberships tm
  where tm.tenant_id = new.tenant_id
    and tm.status = 'active'
    and tm.identity_id <> new.identity_id;
  if v_active >= v_limit then
    raise exception 'tenant member limit reached' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger tenant_membership_plan_limit
before insert or update of status on public.tenant_memberships
for each row execute function private.enforce_tenant_member_limit();

create or replace function private.enforce_tenant_workspace_limit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_limit integer;
  v_active integer;
begin
  if new.status <> 'active' then return new; end if;
  select max_workspaces into v_limit
  from public.tenant_entitlements
  where tenant_id = new.tenant_id;
  if v_limit is null then v_limit := 1; end if;
  select count(*) into v_active
  from public.workspaces w
  where w.tenant_id = new.tenant_id
    and w.status = 'active'
    and w.id <> new.id;
  if v_active >= v_limit then
    raise exception 'tenant workspace limit reached' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger tenant_workspace_plan_limit
before insert or update of status on public.workspaces
for each row execute function private.enforce_tenant_workspace_limit();

revoke all on function private.enforce_tenant_member_limit()
from public, anon, authenticated;
revoke all on function private.enforce_tenant_workspace_limit()
from public, anon, authenticated;

commit;

