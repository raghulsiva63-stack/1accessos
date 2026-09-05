begin;

-- Phase 5: Business/office organization controls. Department, team, group,
-- role, policy and lifecycle records contain administrative metadata only.
-- Vault content, keys, recovery material and item metadata remain client-encrypted.

alter table public.tenant_entitlements
  drop constraint tenant_entitlements_plan_code_check;
alter table public.tenant_entitlements
  add constraint tenant_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','team','business'));

alter table public.billing_subscriptions
  drop constraint billing_subscriptions_plan_code_check;
alter table public.billing_subscriptions
  add constraint billing_subscriptions_plan_code_check
  check (plan_code in ('personal','family','team','business'));

alter table public.account_entitlements
  drop constraint account_entitlements_plan_code_check;
alter table public.account_entitlements
  add constraint account_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','professional','team','business'));

alter table public.workspaces drop constraint workspaces_suite_check;
alter table public.workspaces add constraint workspaces_suite_check
  check (suite in ('personal','family','professional','team','business'));

create table public.organization_departments (
  id uuid not null default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  parent_department_id uuid,
  display_name text not null check (length(trim(display_name)) between 1 and 120),
  slug text not null check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$' and length(slug) <= 80),
  status text not null default 'active' check (status in ('active','archived')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,id),
  unique (id),
  unique (tenant_id,slug),
  foreign key (tenant_id,parent_department_id)
    references public.organization_departments(tenant_id,id) on delete restrict,
  check (parent_department_id is null or parent_department_id <> id)
);

create table public.organization_teams (
  id uuid not null default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  department_id uuid,
  display_name text not null check (length(trim(display_name)) between 1 and 120),
  slug text not null check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$' and length(slug) <= 80),
  status text not null default 'active' check (status in ('active','archived')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,id),
  unique (id),
  unique (tenant_id,slug),
  foreign key (tenant_id,department_id)
    references public.organization_departments(tenant_id,id) on delete restrict
);

create table public.organization_groups (
  id uuid not null default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  display_name text not null check (length(trim(display_name)) between 1 and 120),
  slug text not null check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$' and length(slug) <= 80),
  description text check (description is null or length(description) <= 500),
  status text not null default 'active' check (status in ('active','archived')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,id),
  unique (id),
  unique (tenant_id,slug)
);

create table public.organization_profiles (
  tenant_id uuid not null,
  identity_id uuid not null,
  department_id uuid,
  manager_identity_id uuid,
  display_name text not null check (length(trim(display_name)) between 1 and 120),
  job_title text check (job_title is null or length(job_title) <= 120),
  employee_ref_hash bytea check (employee_ref_hash is null or octet_length(employee_ref_hash) = 32),
  lifecycle_status text not null default 'active'
    check (lifecycle_status in ('invited','active','leave','suspended','deprovisioned')),
  joined_on date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,identity_id),
  foreign key (tenant_id,identity_id)
    references public.tenant_memberships(tenant_id,identity_id) on delete cascade,
  foreign key (tenant_id,department_id)
    references public.organization_departments(tenant_id,id) on delete restrict,
  foreign key (tenant_id,manager_identity_id)
    references public.organization_profiles(tenant_id,identity_id) on delete restrict,
  check (manager_identity_id is null or manager_identity_id <> identity_id)
);

create table public.organization_team_memberships (
  tenant_id uuid not null,
  team_id uuid not null,
  identity_id uuid not null,
  role text not null default 'member' check (role in ('lead','member')),
  status text not null default 'active' check (status in ('active','suspended','revoked')),
  assigned_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (team_id,identity_id),
  foreign key (tenant_id,team_id)
    references public.organization_teams(tenant_id,id) on delete cascade,
  foreign key (tenant_id,identity_id)
    references public.organization_profiles(tenant_id,identity_id) on delete cascade
);

create table public.organization_group_memberships (
  tenant_id uuid not null,
  group_id uuid not null,
  identity_id uuid not null,
  assigned_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  primary key (group_id,identity_id),
  foreign key (tenant_id,group_id)
    references public.organization_groups(tenant_id,id) on delete cascade,
  foreign key (tenant_id,identity_id)
    references public.organization_profiles(tenant_id,identity_id) on delete cascade
);

create table public.organization_admin_assignments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null,
  role text not null check (role in ('organization_admin','security_admin','billing_admin','helpdesk_admin','auditor')),
  scope_type text not null check (scope_type in ('tenant','department','team')),
  scope_id uuid,
  status text not null default 'active' check (status in ('active','suspended','revoked')),
  assigned_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id,identity_id)
    references public.organization_profiles(tenant_id,identity_id) on delete cascade,
  check ((scope_type = 'tenant' and scope_id is null) or (scope_type <> 'tenant' and scope_id is not null)),
  unique nulls not distinct (tenant_id,identity_id,role,scope_type,scope_id)
);

create table public.organization_policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  scope_type text not null check (scope_type in ('tenant','department','team')),
  scope_id uuid,
  policy_type text not null check (policy_type in (
    'passkey_required','device_approval_required','minimum_vault_password',
    'sharing_mode','session_timeout_minutes','export_policy'
  )),
  configuration jsonb not null default '{}'::jsonb
    check (jsonb_typeof(configuration) = 'object' and octet_length(convert_to(configuration::text,'UTF8')) <= 16384),
  priority smallint not null default 100 check (priority between 0 and 1000),
  enforced boolean not null default true,
  version integer not null default 1 check (version > 0),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((scope_type = 'tenant' and scope_id is null) or (scope_type <> 'tenant' and scope_id is not null)),
  unique nulls not distinct (tenant_id,scope_type,scope_id,policy_type)
);

create table public.identity_lifecycle_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  subject_identity_id uuid not null references public.identities(id) on delete restrict,
  event_type text not null check (event_type in ('joined','moved','leave_started','suspended','reactivated','deprovisioned')),
  from_department_id uuid,
  to_department_id uuid,
  from_team_id uuid,
  to_team_id uuid,
  actor_identity_id uuid not null references public.identities(id) on delete restrict,
  reason_code text check (reason_code is null or reason_code in ('onboarding','transfer','leave','security','termination','contract_end','other')),
  occurred_at timestamptz not null default now(),
  foreign key (tenant_id,subject_identity_id)
    references public.tenant_memberships(tenant_id,identity_id) on delete restrict,
  foreign key (tenant_id,from_department_id)
    references public.organization_departments(tenant_id,id) on delete restrict,
  foreign key (tenant_id,to_department_id)
    references public.organization_departments(tenant_id,id) on delete restrict,
  foreign key (tenant_id,from_team_id)
    references public.organization_teams(tenant_id,id) on delete restrict,
  foreign key (tenant_id,to_team_id)
    references public.organization_teams(tenant_id,id) on delete restrict
);

create index organization_departments_parent_idx on public.organization_departments(tenant_id,parent_department_id) where parent_department_id is not null;
create index organization_departments_created_by_idx on public.organization_departments(created_by);
create index organization_teams_department_idx on public.organization_teams(tenant_id,department_id) where status = 'active';
create index organization_teams_created_by_idx on public.organization_teams(created_by);
create index organization_groups_created_by_idx on public.organization_groups(created_by);
create index organization_profiles_department_idx on public.organization_profiles(tenant_id,department_id) where lifecycle_status = 'active';
create index organization_profiles_manager_idx on public.organization_profiles(tenant_id,manager_identity_id) where manager_identity_id is not null;
create index organization_team_memberships_identity_idx on public.organization_team_memberships(tenant_id,identity_id) where status = 'active';
create index organization_team_memberships_assigned_by_idx on public.organization_team_memberships(assigned_by);
create index organization_group_memberships_identity_idx on public.organization_group_memberships(tenant_id,identity_id);
create index organization_group_memberships_assigned_by_idx on public.organization_group_memberships(assigned_by);
create index organization_admin_assignments_identity_idx on public.organization_admin_assignments(tenant_id,identity_id) where status = 'active';
create index organization_admin_assignments_assigned_by_idx on public.organization_admin_assignments(assigned_by);
create index organization_policies_scope_idx on public.organization_policies(tenant_id,scope_type,scope_id,priority desc) where enforced;
create index organization_policies_created_by_idx on public.organization_policies(created_by);
create index identity_lifecycle_events_subject_idx on public.identity_lifecycle_events(tenant_id,subject_identity_id,occurred_at desc);
create index identity_lifecycle_events_actor_idx on public.identity_lifecycle_events(actor_identity_id);

create or replace function private.has_business_entitlement(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1
    from public.tenant_entitlements te
    join public.tenants t on t.id = te.tenant_id
    where te.tenant_id = target_tenant
      and t.kind = 'organization'
      and te.plan_code = 'business'
      and (
        te.source = 'manual'
        or (te.source = 'stripe' and te.subscription_status in ('trialing','active','past_due'))
      )
  )
$$;

create or replace function private.can_manage_organization(target_tenant uuid, allowed_roles text[] default array['organization_admin'])
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin']) or exists (
    select 1 from public.organization_admin_assignments oa
    where oa.tenant_id = target_tenant
      and oa.identity_id = private.current_identity_id()
      and oa.status = 'active'
      and oa.scope_type = 'tenant'
      and oa.role = any(allowed_roles)
  )
$$;

create or replace function private.require_business_organization()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if not private.has_business_entitlement(new.tenant_id) then
    raise exception 'business organization entitlement required' using errcode = '23514';
  end if;
  return new;
end
$$;

create or replace function private.prevent_organization_tenant_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.tenant_id <> old.tenant_id then
    raise exception 'organization tenant cannot be changed' using errcode = '23514';
  end if;
  return new;
end
$$;

create or replace function private.validate_organization_scope()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.scope_type = 'department' and not exists (
    select 1 from public.organization_departments d where d.tenant_id = new.tenant_id and d.id = new.scope_id
  ) then raise exception 'invalid department scope' using errcode = '23514';
  elsif new.scope_type = 'team' and not exists (
    select 1 from public.organization_teams t where t.tenant_id = new.tenant_id and t.id = new.scope_id
  ) then raise exception 'invalid team scope' using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger organization_departments_business before insert on public.organization_departments for each row execute function private.require_business_organization();
create trigger organization_teams_business before insert on public.organization_teams for each row execute function private.require_business_organization();
create trigger organization_groups_business before insert on public.organization_groups for each row execute function private.require_business_organization();
create trigger organization_profiles_business before insert on public.organization_profiles for each row execute function private.require_business_organization();
create trigger organization_team_memberships_business before insert on public.organization_team_memberships for each row execute function private.require_business_organization();
create trigger organization_group_memberships_business before insert on public.organization_group_memberships for each row execute function private.require_business_organization();
create trigger organization_admin_assignments_business before insert on public.organization_admin_assignments for each row execute function private.require_business_organization();
create trigger organization_policies_business before insert on public.organization_policies for each row execute function private.require_business_organization();
create trigger identity_lifecycle_events_business before insert on public.identity_lifecycle_events for each row execute function private.require_business_organization();

create trigger organization_departments_tenant_immutable before update on public.organization_departments for each row execute function private.prevent_organization_tenant_change();
create trigger organization_teams_tenant_immutable before update on public.organization_teams for each row execute function private.prevent_organization_tenant_change();
create trigger organization_groups_tenant_immutable before update on public.organization_groups for each row execute function private.prevent_organization_tenant_change();
create trigger organization_profiles_tenant_immutable before update on public.organization_profiles for each row execute function private.prevent_organization_tenant_change();
create trigger organization_team_memberships_tenant_immutable before update on public.organization_team_memberships for each row execute function private.prevent_organization_tenant_change();
create trigger organization_admin_assignments_tenant_immutable before update on public.organization_admin_assignments for each row execute function private.prevent_organization_tenant_change();
create trigger organization_policies_tenant_immutable before update on public.organization_policies for each row execute function private.prevent_organization_tenant_change();

create trigger organization_admin_assignments_scope before insert or update on public.organization_admin_assignments for each row execute function private.validate_organization_scope();
create trigger organization_policies_scope before insert or update on public.organization_policies for each row execute function private.validate_organization_scope();

revoke all on function private.has_business_entitlement(uuid) from public,anon;
revoke all on function private.can_manage_organization(uuid,text[]) from public,anon;
revoke all on function private.require_business_organization() from public,anon,authenticated;
revoke all on function private.prevent_organization_tenant_change() from public,anon,authenticated;
revoke all on function private.validate_organization_scope() from public,anon,authenticated;
grant execute on function private.has_business_entitlement(uuid) to authenticated;
grant execute on function private.can_manage_organization(uuid,text[]) to authenticated;

alter table public.organization_departments enable row level security;
alter table public.organization_teams enable row level security;
alter table public.organization_groups enable row level security;
alter table public.organization_profiles enable row level security;
alter table public.organization_team_memberships enable row level security;
alter table public.organization_group_memberships enable row level security;
alter table public.organization_admin_assignments enable row level security;
alter table public.organization_policies enable row level security;
alter table public.identity_lifecycle_events enable row level security;

revoke all on public.organization_departments,public.organization_teams,public.organization_groups,
  public.organization_profiles,public.organization_team_memberships,public.organization_group_memberships,
  public.organization_admin_assignments,public.organization_policies,public.identity_lifecycle_events
  from anon,authenticated;
grant select,insert,update,delete on public.organization_departments,public.organization_teams,
  public.organization_groups,public.organization_profiles,public.organization_team_memberships,
  public.organization_group_memberships,public.organization_admin_assignments,public.organization_policies
  to authenticated;
grant select,insert on public.identity_lifecycle_events to authenticated;

create policy organization_departments_read on public.organization_departments for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_departments_manage on public.organization_departments for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

create policy organization_teams_read on public.organization_teams for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_teams_manage on public.organization_teams for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

create policy organization_groups_read on public.organization_groups for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_groups_manage on public.organization_groups for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

create policy organization_profiles_read on public.organization_profiles for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_profiles_manage on public.organization_profiles for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

create policy organization_team_memberships_read on public.organization_team_memberships for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_team_memberships_manage on public.organization_team_memberships for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

create policy organization_group_memberships_read on public.organization_group_memberships for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_group_memberships_manage on public.organization_group_memberships for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

create policy organization_admin_assignments_read on public.organization_admin_assignments for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin'])) or identity_id = (select private.current_identity_id()));
create policy organization_admin_assignments_manage on public.organization_admin_assignments for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])));

create policy organization_policies_read on public.organization_policies for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy organization_policies_manage on public.organization_policies for all to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])));

create policy identity_lifecycle_events_read on public.identity_lifecycle_events for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','auditor'])) or subject_identity_id = (select private.current_identity_id()));
create policy identity_lifecycle_events_create on public.identity_lifecycle_events for insert to authenticated
  with check (
    (select private.has_business_entitlement(tenant_id))
    and actor_identity_id = (select private.current_identity_id())
    and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
  );

grant update (status,updated_at) on public.tenant_memberships to authenticated;

create policy tenant_memberships_business_lifecycle_update
on public.tenant_memberships for update to authenticated
using (
  role <> 'owner'
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
)
with check (
  role <> 'owner'
  and status in ('active','suspended','revoked')
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
);

create policy workspace_memberships_business_lifecycle_update
on public.workspace_memberships for update to authenticated
using (
  role <> 'owner'
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
)
with check (
  role <> 'owner'
  and status in ('active','suspended','revoked')
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
);

create or replace function private.revoke_organization_member_keys()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if old.status = 'active' and new.status in ('suspended','revoked')
    and private.has_business_entitlement(new.tenant_id) then
    update public.key_envelopes
      set revoked_at=coalesce(revoked_at,now())
      where tenant_id=new.tenant_id and recipient_identity_id=new.identity_id;
    update public.workspaces
      set key_rotation_required=true,updated_at=now()
      where tenant_id=new.tenant_id and exists (
        select 1 from public.workspace_memberships wm
        where wm.workspace_id=workspaces.id and wm.identity_id=new.identity_id
      );
  end if;
  return new;
end
$$;

create trigger tenant_membership_business_key_revocation
after update of status on public.tenant_memberships
for each row execute function private.revoke_organization_member_keys();

revoke all on function private.revoke_organization_member_keys()
from public,anon,authenticated;

create or replace function public.onboard_organization_member(
  p_tenant_id uuid,
  p_identity_id uuid,
  p_display_name text,
  p_job_title text default null,
  p_department_id uuid default null
) returns void language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_organization(p_tenant_id,array['organization_admin','helpdesk_admin']) then
    raise exception 'organization management denied' using errcode = '42501';
  end if;
  insert into public.organization_profiles(
    tenant_id,identity_id,department_id,display_name,job_title,lifecycle_status,joined_on
  ) values (
    p_tenant_id,p_identity_id,p_department_id,trim(p_display_name),nullif(trim(p_job_title),''),'active',current_date
  );
  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,to_department_id,actor_identity_id,reason_code
  ) values (p_tenant_id,p_identity_id,'joined',p_department_id,v_actor,'onboarding');
end
$$;

create or replace function public.manage_organization_member_lifecycle(
  p_tenant_id uuid,
  p_identity_id uuid,
  p_event_type text,
  p_department_id uuid default null,
  p_reason_code text default null
) returns void language plpgsql security invoker set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_from_department uuid;
begin
  if p_event_type not in ('moved','leave_started','suspended','reactivated','deprovisioned') then
    raise exception 'invalid lifecycle event' using errcode = '22023';
  end if;
  if not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_organization(p_tenant_id,array['organization_admin','helpdesk_admin','security_admin']) then
    raise exception 'organization management denied' using errcode = '42501';
  end if;
  select department_id into strict v_from_department
  from public.organization_profiles
  where tenant_id=p_tenant_id and identity_id=p_identity_id;

  if p_event_type = 'moved' then
    update public.organization_profiles
      set department_id=p_department_id,updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id;
  elsif p_event_type in ('leave_started','suspended','deprovisioned') then
    update public.organization_profiles
      set lifecycle_status=case p_event_type
        when 'leave_started' then 'leave'
        when 'suspended' then 'suspended'
        else 'deprovisioned' end,
        updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id;
    update public.tenant_memberships
      set status=case when p_event_type='deprovisioned' then 'revoked' else 'suspended' end,updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id and role <> 'owner';
    update public.workspace_memberships
      set status=case when p_event_type='deprovisioned' then 'revoked' else 'suspended' end,updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id and role <> 'owner';
  else
    update public.organization_profiles set lifecycle_status='active',updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id;
    update public.tenant_memberships set status='active',updated_at=now()
      where tenant_id=p_tenant_id and identity_id=p_identity_id and role <> 'owner';
    -- Workspace membership and key access are deliberately not restored. A
    -- manager must re-invite the person and issue fresh key envelopes.
  end if;

  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,from_department_id,to_department_id,
    actor_identity_id,reason_code
  ) values (
    p_tenant_id,p_identity_id,p_event_type,v_from_department,
    case when p_event_type='moved' then p_department_id else null end,
    v_actor,p_reason_code
  );
end
$$;

revoke all on function public.onboard_organization_member(uuid,uuid,text,text,uuid) from public,anon;
revoke all on function public.manage_organization_member_lifecycle(uuid,uuid,text,uuid,text) from public,anon;
grant execute on function public.onboard_organization_member(uuid,uuid,text,text,uuid) to authenticated;
grant execute on function public.manage_organization_member_lifecycle(uuid,uuid,text,uuid,text) to authenticated;

create or replace function private.phase2_enabled()
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce((
    select e.phase2_preview_enabled or e.plan_code in ('family','professional','team','business')
    from public.account_entitlements e
    where e.identity_id = private.current_identity_id()
  ), false)
$$;

create or replace function private.owns_phase2_workspace(target_tenant uuid, target_workspace uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.workspaces w
    where w.tenant_id = target_tenant
      and w.id = target_workspace
      and w.created_by = private.current_identity_id()
      and w.suite in ('family','professional','team','business')
      and private.owns_phase2_tenant(target_tenant)
  )
$$;

drop policy workspaces_create on public.workspaces;
create policy workspaces_create on public.workspaces for insert to authenticated
with check (
  created_by = (select private.current_identity_id()) and (
    (kind = 'vault' and (select private.owns_personal_tenant(workspaces.tenant_id)))
    or (
      kind in ('project','client','shared')
      and suite in ('family','professional','team','business')
      and (select private.owns_phase2_tenant(workspaces.tenant_id))
      and (select private.phase2_enabled())
    )
  )
);

-- Extend the signed Stripe event transaction with the Business entitlement.
create or replace function public.apply_stripe_billing_event(
  p_event_id text,
  p_event_type text,
  p_api_version text,
  p_payload_sha256 bytea,
  p_livemode boolean,
  p_tenant_id uuid,
  p_customer_id text,
  p_subscription_id text default null,
  p_product_id text default null,
  p_price_id text default null,
  p_plan_code text default null,
  p_billing_interval text default null,
  p_currency text default null,
  p_status text default null,
  p_quantity integer default 1,
  p_period_started_at timestamptz default null,
  p_period_ends_at timestamptz default null,
  p_cancel_at_period_end boolean default false,
  p_canceled_at timestamptz default null
) returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_inserted integer;
  v_existing_customer text;
  v_effective_plan text := 'free';
  v_max_members integer := 1;
  v_max_workspaces integer := 1;
  v_max_devices integer := 2;
  v_ai_credits integer := 20;
  v_automation_runs integer := 50;
begin
  insert into public.billing_events(
    stripe_event_id,event_type,stripe_api_version,payload_sha256,livemode,tenant_id
  ) values (
    p_event_id,p_event_type,p_api_version,p_payload_sha256,p_livemode,p_tenant_id
  ) on conflict (stripe_event_id) do nothing;

  get diagnostics v_inserted = row_count;
  if v_inserted = 0 then
    update public.billing_events set delivery_count = delivery_count + 1
    where stripe_event_id = p_event_id;
    return false;
  end if;

  if p_tenant_id is null or p_customer_id is null then
    update public.billing_events set outcome = 'ignored',processed_at = now()
    where stripe_event_id = p_event_id;
    return true;
  end if;

  if p_customer_id !~ '^cus_[A-Za-z0-9]+$' then
    raise exception 'invalid billing customer identifier' using errcode = '22023';
  end if;

  select stripe_customer_id into v_existing_customer
  from public.billing_customers where tenant_id = p_tenant_id;

  if v_existing_customer is not null and v_existing_customer <> p_customer_id then
    raise exception 'tenant billing customer mismatch' using errcode = '23514';
  end if;
  if exists (
    select 1 from public.billing_customers
    where stripe_customer_id = p_customer_id and tenant_id <> p_tenant_id
  ) then
    raise exception 'billing customer already belongs to another tenant' using errcode = '23514';
  end if;

  insert into public.billing_customers(tenant_id,stripe_customer_id,livemode)
  values (p_tenant_id,p_customer_id,p_livemode)
  on conflict (tenant_id) do update set updated_at = now()
  where public.billing_customers.stripe_customer_id = excluded.stripe_customer_id
    and public.billing_customers.livemode = excluded.livemode;

  if p_subscription_id is not null then
    if p_subscription_id !~ '^sub_[A-Za-z0-9]+$'
      or p_product_id !~ '^prod_[A-Za-z0-9]+$'
      or p_price_id !~ '^price_[A-Za-z0-9]+$'
      or p_plan_code not in ('personal','family','team','business')
      or p_billing_interval not in ('month','year')
      or p_currency not in ('inr','usd')
      or p_status not in ('trialing','active','past_due','unpaid','canceled','incomplete','incomplete_expired','paused')
      or p_quantity < 1 then
      raise exception 'invalid subscription state' using errcode = '22023';
    end if;

    insert into public.billing_subscriptions(
      tenant_id,stripe_subscription_id,stripe_product_id,stripe_price_id,
      livemode,plan_code,billing_interval,currency,status,quantity,
      current_period_started_at,current_period_ends_at,cancel_at_period_end,canceled_at
    ) values (
      p_tenant_id,p_subscription_id,p_product_id,p_price_id,
      p_livemode,p_plan_code,p_billing_interval,p_currency,p_status,p_quantity,
      p_period_started_at,p_period_ends_at,p_cancel_at_period_end,p_canceled_at
    ) on conflict (tenant_id) do update set
      stripe_subscription_id=excluded.stripe_subscription_id,
      stripe_product_id=excluded.stripe_product_id,
      stripe_price_id=excluded.stripe_price_id,
      livemode=excluded.livemode,
      plan_code=excluded.plan_code,
      billing_interval=excluded.billing_interval,
      currency=excluded.currency,
      status=excluded.status,
      quantity=excluded.quantity,
      current_period_started_at=excluded.current_period_started_at,
      current_period_ends_at=excluded.current_period_ends_at,
      cancel_at_period_end=excluded.cancel_at_period_end,
      canceled_at=excluded.canceled_at,
      updated_at=now();

    if p_status in ('trialing','active','past_due') then
      v_effective_plan := p_plan_code;
      case p_plan_code
        when 'personal' then
          v_max_members:=1; v_max_workspaces:=5; v_max_devices:=null;
          v_ai_credits:=200; v_automation_runs:=500;
        when 'family' then
          v_max_members:=6; v_max_workspaces:=20; v_max_devices:=null;
          v_ai_credits:=500; v_automation_runs:=1500;
        when 'team' then
          v_max_members:=50; v_max_workspaces:=100; v_max_devices:=null;
          v_ai_credits:=2000; v_automation_runs:=10000;
        when 'business' then
          v_max_members:=500; v_max_workspaces:=500; v_max_devices:=null;
          v_ai_credits:=10000; v_automation_runs:=50000;
      end case;
    end if;

    insert into public.tenant_entitlements(
      tenant_id,plan_code,subscription_status,source,max_members,max_workspaces,
      max_devices,ai_credits_remaining,automation_runs_remaining,valid_until,updated_at
    ) values (
      p_tenant_id,v_effective_plan,p_status,
      case when v_effective_plan='free' then 'free' else 'stripe' end,
      v_max_members,v_max_workspaces,v_max_devices,v_ai_credits,v_automation_runs,
      p_period_ends_at,now()
    ) on conflict (tenant_id) do update set
      plan_code=excluded.plan_code,
      subscription_status=excluded.subscription_status,
      source=excluded.source,
      max_members=excluded.max_members,
      max_workspaces=excluded.max_workspaces,
      max_devices=excluded.max_devices,
      ai_credits_remaining=greatest(public.tenant_entitlements.ai_credits_remaining,excluded.ai_credits_remaining),
      automation_runs_remaining=greatest(public.tenant_entitlements.automation_runs_remaining,excluded.automation_runs_remaining),
      valid_until=excluded.valid_until,
      updated_at=now();
  end if;

  update public.billing_events set outcome='processed',processed_at=now()
  where stripe_event_id=p_event_id;
  return true;
end
$$;

revoke all on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) from public,anon,authenticated;
grant execute on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) to service_role;

comment on table public.organization_departments is 'Business directory labels are visible administrative metadata; secrets and vault item names are prohibited.';
comment on table public.organization_profiles is 'Tenant-scoped office directory profile; authentication remains in Supabase Auth and vault secrets remain client-encrypted.';
comment on table public.organization_policies is 'Non-secret policy configuration inherited tenant to department to team; never store vault material.';
comment on table public.identity_lifecycle_events is 'Append-only joiner/mover/leaver history; UPDATE and DELETE are intentionally not granted.';

commit;
