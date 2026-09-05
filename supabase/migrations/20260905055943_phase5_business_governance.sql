begin;

-- Phase 5 Business governance checkpoint.
-- This migration stores administrative metadata only. It must never receive
-- vault plaintext, passwords, recovery material, private keys, or decrypted
-- attachment content.

create table public.organization_invitations (
  id uuid primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  created_by uuid not null references public.identities(id) on delete restrict,
  recipient_email_hash bytea not null check (octet_length(recipient_email_hash) = 32),
  token_hash bytea not null unique check (octet_length(token_hash) = 32),
  display_name text not null check (length(trim(display_name)) between 1 and 120),
  job_title text check (job_title is null or length(job_title) <= 120),
  department_id uuid,
  team_id uuid,
  team_role text not null default 'member' check (team_role in ('lead','member')),
  status text not null default 'pending' check (status in ('pending','accepted','revoked','expired')),
  expires_at timestamptz not null,
  accepted_by uuid references public.identities(id) on delete set null,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id,department_id)
    references public.organization_departments(tenant_id,id) on delete restrict,
  foreign key (tenant_id,team_id)
    references public.organization_teams(tenant_id,id) on delete restrict,
  check (expires_at > created_at and expires_at <= created_at + interval '30 days'),
  check ((accepted_by is null) = (accepted_at is null)),
  check (status <> 'accepted' or (accepted_by is not null and accepted_at is not null)),
  check ((status = 'revoked') = (revoked_at is not null))
);

create table public.organization_device_posture_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  source text not null check (source in ('self_reported','mdm','idp','attested')),
  verification_status text not null default 'unverified'
    check (verification_status in ('unverified','verified','rejected')),
  evaluation text not null default 'unknown'
    check (evaluation in ('unknown','compliant','non_compliant')),
  os_family text not null default 'unknown'
    check (os_family in ('windows','macos','linux','ios','android','chromeos','unknown')),
  screen_lock boolean,
  disk_encrypted boolean,
  security_patch_current boolean,
  endpoint_protection boolean,
  evidence_hash bytea check (evidence_hash is null or octet_length(evidence_hash) = 32),
  observed_at timestamptz not null default now(),
  valid_until timestamptz not null,
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  foreign key (tenant_id,identity_id)
    references public.tenant_memberships(tenant_id,identity_id) on delete cascade,
  check (valid_until > observed_at and valid_until <= observed_at + interval '30 days')
);

create index organization_invitations_recipient_active_idx
  on public.organization_invitations(recipient_email_hash,expires_at)
  where status = 'pending';
create index organization_invitations_tenant_idx
  on public.organization_invitations(tenant_id,created_at desc);
create index organization_invitations_department_idx
  on public.organization_invitations(tenant_id,department_id)
  where department_id is not null;
create index organization_invitations_team_idx
  on public.organization_invitations(tenant_id,team_id)
  where team_id is not null;
create index organization_device_posture_device_idx
  on public.organization_device_posture_reports(tenant_id,device_id,observed_at desc);
create index organization_device_posture_identity_idx
  on public.organization_device_posture_reports(tenant_id,identity_id,observed_at desc);
create index organization_device_posture_created_by_idx
  on public.organization_device_posture_reports(created_by);

create or replace function private.department_scope_contains(
  target_tenant uuid,
  granted_department uuid,
  target_department uuid
) returns boolean language sql stable security definer set search_path = ''
as $$
  with recursive ancestors(id,parent_department_id) as (
    select d.id,d.parent_department_id
    from public.organization_departments d
    where d.tenant_id = target_tenant and d.id = target_department
    union all
    select parent.id,parent.parent_department_id
    from public.organization_departments parent
    join ancestors child on child.parent_department_id = parent.id
    where parent.tenant_id = target_tenant
  )
  select target_department is not null
    and granted_department is not null
    and exists (select 1 from ancestors where id = granted_department)
$$;

create or replace function private.organization_scope_covers(
  target_tenant uuid,
  granted_scope_type text,
  granted_scope_id uuid,
  target_department_id uuid default null,
  target_team_id uuid default null
) returns boolean language sql stable security definer set search_path = ''
as $$
  select case
    when granted_scope_type = 'tenant' then true
    when granted_scope_type = 'team' then granted_scope_id is not null
      and target_team_id = granted_scope_id
    when granted_scope_type = 'department' then private.department_scope_contains(
      target_tenant,
      granted_scope_id,
      coalesce(
        target_department_id,
        (select t.department_id from public.organization_teams t
          where t.tenant_id = target_tenant and t.id = target_team_id)
      )
    )
    else false
  end
$$;

create or replace function private.can_manage_organization_scope(
  target_tenant uuid,
  allowed_roles text[],
  target_department_id uuid default null,
  target_team_id uuid default null
) returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin']) or exists (
    select 1
    from public.organization_admin_assignments assignment
    where assignment.tenant_id = target_tenant
      and assignment.identity_id = private.current_identity_id()
      and assignment.status = 'active'
      and assignment.role = any(allowed_roles)
      and private.organization_scope_covers(
        target_tenant,assignment.scope_type,assignment.scope_id,
        target_department_id,target_team_id
      )
  )
$$;

create or replace function private.can_manage_organization_identity(
  target_tenant uuid,
  allowed_roles text[],
  target_identity uuid
) returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin']) or exists (
    select 1
    from public.organization_admin_assignments assignment
    join public.organization_profiles profile
      on profile.tenant_id = assignment.tenant_id
      and profile.identity_id = target_identity
    where assignment.tenant_id = target_tenant
      and assignment.identity_id = private.current_identity_id()
      and assignment.status = 'active'
      and assignment.role = any(allowed_roles)
      and (
        assignment.scope_type = 'tenant'
        or (
          assignment.scope_type = 'department'
          and private.department_scope_contains(
            target_tenant,assignment.scope_id,profile.department_id
          )
        )
        or (
          assignment.scope_type = 'team'
          and exists (
            select 1
            from public.organization_team_memberships membership
            where membership.tenant_id = target_tenant
              and membership.team_id = assignment.scope_id
              and membership.identity_id = target_identity
              and membership.status = 'active'
          )
        )
      )
  )
$$;

create or replace function private.can_export_organization_audit(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin','auditor']) or exists (
    select 1
    from public.organization_admin_assignments assignment
    where assignment.tenant_id = target_tenant
      and assignment.identity_id = private.current_identity_id()
      and assignment.status = 'active'
      and assignment.scope_type = 'tenant'
      and assignment.role in ('auditor','security_admin')
  )
$$;

create or replace function private.validate_organization_invitation_scope()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_team_department uuid;
begin
  if new.team_id is not null then
    select team.department_id into strict v_team_department
    from public.organization_teams team
    where team.tenant_id = new.tenant_id and team.id = new.team_id and team.status = 'active';
    if new.department_id is not null and v_team_department is distinct from new.department_id then
      raise exception 'invitation team is outside the selected department' using errcode = '23514';
    end if;
    new.department_id := coalesce(new.department_id,v_team_department);
  end if;
  return new;
end
$$;

create or replace function private.enforce_organization_profile_ceremony()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    if current_setting('request.passkey_x_profile_onboard',true) <> new.identity_id::text
      and not exists (
        select 1 from public.organization_invitations invitation
        where invitation.tenant_id = new.tenant_id
          and invitation.accepted_by = new.identity_id
          and invitation.status = 'accepted'
      ) then
      raise exception 'organization profile must use an onboarding ceremony' using errcode = '42501';
    end if;
  elsif new.department_id is distinct from old.department_id
    or new.lifecycle_status is distinct from old.lifecycle_status then
    if current_setting('request.passkey_x_profile_lifecycle',true) <> new.identity_id::text then
      raise exception 'organization lifecycle change must use the lifecycle ceremony' using errcode = '42501';
    end if;
  end if;
  return new;
end
$$;

revoke all on function private.department_scope_contains(uuid,uuid,uuid) from public,anon;
revoke all on function private.organization_scope_covers(uuid,text,uuid,uuid,uuid) from public,anon;
revoke all on function private.can_manage_organization_scope(uuid,text[],uuid,uuid) from public,anon;
revoke all on function private.can_manage_organization_identity(uuid,text[],uuid) from public,anon;
revoke all on function private.can_export_organization_audit(uuid) from public,anon;
revoke all on function private.validate_organization_invitation_scope() from public,anon,authenticated;
revoke all on function private.enforce_organization_profile_ceremony() from public,anon,authenticated;
grant execute on function private.department_scope_contains(uuid,uuid,uuid) to authenticated;
grant execute on function private.organization_scope_covers(uuid,text,uuid,uuid,uuid) to authenticated;
grant execute on function private.can_manage_organization_scope(uuid,text[],uuid,uuid) to authenticated;
grant execute on function private.can_manage_organization_identity(uuid,text[],uuid) to authenticated;
grant execute on function private.can_export_organization_audit(uuid) to authenticated;

create trigger organization_invitations_scope
before insert or update on public.organization_invitations
for each row execute function private.validate_organization_invitation_scope();
create trigger organization_invitations_business
before insert on public.organization_invitations
for each row execute function private.require_business_organization();
create trigger organization_device_posture_business
before insert on public.organization_device_posture_reports
for each row execute function private.require_business_organization();
create trigger organization_invitations_tenant_immutable
before update on public.organization_invitations
for each row execute function private.prevent_organization_tenant_change();
create trigger organization_device_posture_tenant_immutable
before update on public.organization_device_posture_reports
for each row execute function private.prevent_organization_tenant_change();
create trigger organization_profiles_ceremony
before insert or update on public.organization_profiles
for each row execute function private.enforce_organization_profile_ceremony();

alter table public.organization_invitations enable row level security;
alter table public.organization_device_posture_reports enable row level security;

revoke all on public.organization_invitations,public.organization_device_posture_reports
from anon,authenticated;
grant select on public.organization_invitations to authenticated;
grant insert (
  id,tenant_id,created_by,recipient_email_hash,token_hash,display_name,job_title,
  department_id,team_id,team_role,status,expires_at
) on public.organization_invitations to authenticated;
grant update (token_hash,status,accepted_by,accepted_at,revoked_at,updated_at)
on public.organization_invitations to authenticated;
grant select on public.organization_device_posture_reports to authenticated;
grant insert (
  tenant_id,device_id,identity_id,source,verification_status,evaluation,os_family,
  screen_lock,disk_encrypted,security_patch_current,endpoint_protection,
  evidence_hash,observed_at,valid_until,created_by
) on public.organization_device_posture_reports to authenticated;

create policy organization_invitations_read
on public.organization_invitations for select to authenticated
using (
  created_by = (select private.current_identity_id())
  or recipient_email_hash = (select private.current_verified_email_hash())
  or accepted_by = (select private.current_identity_id())
  or (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],department_id,team_id
  ))
);

create policy organization_invitations_create
on public.organization_invitations for insert to authenticated
with check (
  created_by = (select private.current_identity_id())
  and status = 'pending' and accepted_by is null and revoked_at is null
  and expires_at > now() and expires_at <= now() + interval '30 days'
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],department_id,team_id
  ))
);

create policy organization_invitations_accept
on public.organization_invitations for update to authenticated
using (
  status = 'pending' and expires_at > now()
  and recipient_email_hash = (select private.current_verified_email_hash())
  and token_hash = decode(
    coalesce(current_setting('request.passkey_x_org_invite_proof',true),''),'hex'
  )
)
with check (
  status = 'accepted'
  and accepted_by = (select private.current_identity_id())
  and accepted_at is not null and revoked_at is null
);

create policy organization_invitations_revoke
on public.organization_invitations for update to authenticated
using (
  (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],department_id,team_id
  ))
  and current_setting('request.passkey_x_org_invite_revoke',true) = id::text
)
with check (status = 'revoked' and revoked_at is not null);

create policy organization_device_posture_read
on public.organization_device_posture_reports for select to authenticated
using (
  identity_id = (select private.current_identity_id())
  or (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin','security_admin','auditor'],identity_id
  ))
);

create policy organization_device_posture_self_report
on public.organization_device_posture_reports for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and created_by = (select private.current_identity_id())
  and source = 'self_reported'
  and verification_status = 'unverified'
  and evaluation = 'unknown'
  and exists (
    select 1 from public.devices device
    where device.id = device_id and device.identity_id = identity_id and device.status = 'trusted'
  )
  and (select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor']))
);

drop policy if exists organization_departments_manage on public.organization_departments;
drop policy if exists organization_departments_insert on public.organization_departments;
drop policy if exists organization_departments_update on public.organization_departments;
drop policy if exists organization_departments_delete on public.organization_departments;
create policy organization_departments_insert
on public.organization_departments for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],coalesce(parent_department_id,id),null
  ))
);
create policy organization_departments_update
on public.organization_departments for update to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],coalesce(parent_department_id,id),null
  ))
)
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],coalesce(parent_department_id,id),null
  ))
);
create policy organization_departments_delete
on public.organization_departments for delete to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],coalesce(parent_department_id,id),null
  ))
);

drop policy if exists organization_teams_manage on public.organization_teams;
drop policy if exists organization_teams_insert on public.organization_teams;
drop policy if exists organization_teams_update on public.organization_teams;
drop policy if exists organization_teams_delete on public.organization_teams;
create policy organization_teams_insert
on public.organization_teams for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],department_id,id
  ))
);
create policy organization_teams_update
on public.organization_teams for update to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],department_id,id
  ))
)
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],department_id,id
  ))
);
create policy organization_teams_delete
on public.organization_teams for delete to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin'],department_id,id
  ))
);

drop policy if exists organization_profiles_manage on public.organization_profiles;
drop policy if exists organization_profiles_insert on public.organization_profiles;
drop policy if exists organization_profiles_update on public.organization_profiles;
drop policy if exists organization_profiles_delete on public.organization_profiles;
drop policy if exists organization_profiles_create on public.organization_profiles;
create policy organization_profiles_insert
on public.organization_profiles for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],department_id,null
  ))
);
create policy organization_profiles_update
on public.organization_profiles for update to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin','helpdesk_admin'],identity_id
  ))
)
with check (
  (select private.has_business_entitlement(tenant_id))
  and (
    (select private.can_manage_organization_identity(
      tenant_id,array['organization_admin','helpdesk_admin'],identity_id
    ))
    or (select private.can_manage_organization_scope(
      tenant_id,array['organization_admin','helpdesk_admin'],department_id,null
    ))
  )
);
create policy organization_profiles_delete
on public.organization_profiles for delete to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin'],identity_id
  ))
);

drop policy if exists organization_team_memberships_manage on public.organization_team_memberships;
drop policy if exists organization_team_memberships_insert on public.organization_team_memberships;
drop policy if exists organization_team_memberships_update on public.organization_team_memberships;
drop policy if exists organization_team_memberships_delete on public.organization_team_memberships;
create policy organization_team_memberships_insert
on public.organization_team_memberships for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],null,team_id
  ))
);
create policy organization_team_memberships_update
on public.organization_team_memberships for update to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],null,team_id
  ))
)
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],null,team_id
  ))
);
create policy organization_team_memberships_delete
on public.organization_team_memberships for delete to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','helpdesk_admin'],null,team_id
  ))
);

drop policy if exists organization_policies_manage on public.organization_policies;
drop policy if exists organization_policies_insert on public.organization_policies;
drop policy if exists organization_policies_update on public.organization_policies;
drop policy if exists organization_policies_delete on public.organization_policies;
create policy organization_policies_insert
on public.organization_policies for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','security_admin'],
    case when scope_type = 'department' then scope_id else null end,
    case when scope_type = 'team' then scope_id else null end
  ))
);
create policy organization_policies_update
on public.organization_policies for update to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','security_admin'],
    case when scope_type = 'department' then scope_id else null end,
    case when scope_type = 'team' then scope_id else null end
  ))
)
with check (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','security_admin'],
    case when scope_type = 'department' then scope_id else null end,
    case when scope_type = 'team' then scope_id else null end
  ))
);
create policy organization_policies_delete
on public.organization_policies for delete to authenticated
using (
  (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','security_admin'],
    case when scope_type = 'department' then scope_id else null end,
    case when scope_type = 'team' then scope_id else null end
  ))
);

drop policy if exists identity_lifecycle_events_create on public.identity_lifecycle_events;
create policy identity_lifecycle_events_create
on public.identity_lifecycle_events for insert to authenticated
with check (
  (select private.has_business_entitlement(tenant_id))
  and actor_identity_id = (select private.current_identity_id())
  and (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin','helpdesk_admin','security_admin'],subject_identity_id
  ))
);

drop policy if exists tenant_memberships_business_lifecycle_update on public.tenant_memberships;
create policy tenant_memberships_business_lifecycle_update
on public.tenant_memberships for update to authenticated
using (
  role <> 'owner'
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin','helpdesk_admin','security_admin'],identity_id
  ))
)
with check (
  role <> 'owner' and status in ('active','suspended','revoked')
  and (select private.has_business_entitlement(tenant_id))
  and (select private.can_manage_organization_identity(
    tenant_id,array['organization_admin','helpdesk_admin','security_admin'],identity_id
  ))
);

drop policy if exists workspace_memberships_business_lifecycle_update on public.workspace_memberships;
drop policy if exists workspace_memberships_update on public.workspace_memberships;
create policy workspace_memberships_update
on public.workspace_memberships for update to authenticated
using (
  (
    role <> 'owner'
    and (select private.can_manage_workspace(tenant_id,workspace_id))
    and (select current_setting('request.passkey_x_member_revoke',true)) = workspace_id::text || ':' || identity_id::text
  )
  or (
    role <> 'owner'
    and (select private.has_business_entitlement(tenant_id))
    and (select private.can_manage_organization_identity(
      tenant_id,array['organization_admin','helpdesk_admin','security_admin'],identity_id
    ))
  )
)
with check (
  (status = 'revoked' and role <> 'owner')
  or (
    role <> 'owner' and status in ('active','suspended','revoked')
    and (select private.has_business_entitlement(tenant_id))
    and (select private.can_manage_organization_identity(
      tenant_id,array['organization_admin','helpdesk_admin','security_admin'],identity_id
    ))
  )
);

create policy devices_organization_security_read
on public.devices for select to authenticated
using (
  exists (
    select 1
    from public.tenant_memberships membership
    where membership.identity_id = devices.identity_id
      and membership.status = 'active'
      and private.can_manage_organization_identity(
        membership.tenant_id,array['organization_admin','security_admin','auditor'],devices.identity_id
      )
  )
);

create policy audit_events_business_export_read
on public.audit_events for select to authenticated
using ((select private.can_export_organization_audit(tenant_id)));

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
    or not private.can_manage_organization_scope(
      p_tenant_id,array['organization_admin','helpdesk_admin'],p_department_id,null
    ) then
    raise exception 'organization management denied' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.tenant_memberships membership
    where membership.tenant_id = p_tenant_id
      and membership.identity_id = p_identity_id
      and membership.status = 'active'
  ) then
    raise exception 'active tenant member required' using errcode = '23514';
  end if;
  if p_department_id is not null and not exists (
    select 1 from public.organization_departments department
    where department.tenant_id = p_tenant_id
      and department.id = p_department_id
      and department.status = 'active'
  ) then
    raise exception 'active department required' using errcode = '23514';
  end if;
  perform set_config('request.passkey_x_profile_onboard',p_identity_id::text,true);
  insert into public.organization_profiles(
    tenant_id,identity_id,department_id,display_name,job_title,lifecycle_status,joined_on
  ) values (
    p_tenant_id,p_identity_id,p_department_id,trim(p_display_name),
    nullif(trim(p_job_title),''),'active',current_date
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
  select profile.department_id into strict v_from_department
  from public.organization_profiles profile
  where profile.tenant_id = p_tenant_id and profile.identity_id = p_identity_id;

  if not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_organization_identity(
      p_tenant_id,array['organization_admin','helpdesk_admin','security_admin'],p_identity_id
    ) then
    raise exception 'organization management denied' using errcode = '42501';
  end if;
  if p_event_type = 'moved' and not private.can_manage_organization_scope(
    p_tenant_id,array['organization_admin','helpdesk_admin'],p_department_id,null
  ) then
    raise exception 'destination department management denied' using errcode = '42501';
  end if;

  perform set_config('request.passkey_x_profile_lifecycle',p_identity_id::text,true);
  if p_event_type = 'moved' then
    update public.organization_profiles
    set department_id = p_department_id,updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
  elsif p_event_type in ('leave_started','suspended','deprovisioned') then
    update public.organization_profiles
    set lifecycle_status = case p_event_type
      when 'leave_started' then 'leave'
      when 'suspended' then 'suspended'
      else 'deprovisioned' end,
      updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
    update public.tenant_memberships
    set status = case when p_event_type = 'deprovisioned' then 'revoked' else 'suspended' end,
      updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id and role <> 'owner';
    update public.workspace_memberships
    set status = case when p_event_type = 'deprovisioned' then 'revoked' else 'suspended' end,
      updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id and role <> 'owner';
  else
    update public.organization_profiles
    set lifecycle_status = 'active',updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
    update public.tenant_memberships
    set status = 'active',updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id and role <> 'owner';
    -- Workspace membership and key access are deliberately not restored.
  end if;

  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,from_department_id,to_department_id,
    actor_identity_id,reason_code
  ) values (
    p_tenant_id,p_identity_id,p_event_type,v_from_department,
    case when p_event_type = 'moved' then p_department_id else null end,
    v_actor,p_reason_code
  );
end
$$;

create or replace function public.accept_organization_invitation(
  p_invitation_id uuid,
  p_token_hash bytea
) returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_invitation public.organization_invitations%rowtype;
  v_invalidated_hash bytea;
begin
  if v_identity is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_token_hash) <> 32 then
    raise exception 'invalid organization invitation proof' using errcode = '22023';
  end if;

  perform set_config('request.passkey_x_org_invite_proof',encode(p_token_hash,'hex'),true);
  select * into v_invitation
  from public.organization_invitations invitation
  where invitation.id = p_invitation_id
    and invitation.status = 'pending'
    and invitation.expires_at > now()
    and invitation.recipient_email_hash = private.current_verified_email_hash()
    and invitation.token_hash = p_token_hash
  for update;
  if not found then
    raise exception 'organization invitation is invalid or expired' using errcode = '28000';
  end if;

  v_invalidated_hash := extensions.digest(p_token_hash || uuid_send(p_invitation_id),'sha256');
  update public.organization_invitations
  set status = 'accepted',accepted_by = v_identity,accepted_at = now(),
      updated_at = now(),token_hash = v_invalidated_hash
  where id = p_invitation_id;

  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
  values (v_invitation.tenant_id,v_identity,'member','active')
  on conflict (tenant_id,identity_id) do nothing;

  insert into public.organization_profiles(
    tenant_id,identity_id,department_id,display_name,job_title,lifecycle_status,joined_on
  ) values (
    v_invitation.tenant_id,v_identity,v_invitation.department_id,
    v_invitation.display_name,v_invitation.job_title,'active',current_date
  );

  if v_invitation.team_id is not null then
    insert into public.organization_team_memberships(
      tenant_id,team_id,identity_id,role,status,assigned_by
    ) values (
      v_invitation.tenant_id,v_invitation.team_id,v_identity,
      v_invitation.team_role,'active',v_invitation.created_by
    );
  end if;

  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,to_department_id,to_team_id,
    actor_identity_id,reason_code
  ) values (
    v_invitation.tenant_id,v_identity,'joined',v_invitation.department_id,
    v_invitation.team_id,v_identity,'onboarding'
  );

  return jsonb_build_object(
    'tenant_id',v_invitation.tenant_id,
    'department_id',v_invitation.department_id,
    'team_id',v_invitation.team_id
  );
end
$$;

create or replace function public.revoke_organization_invitation(p_invitation_id uuid)
returns void language plpgsql security invoker set search_path = ''
as $$
begin
  perform set_config('request.passkey_x_org_invite_revoke',p_invitation_id::text,true);
  update public.organization_invitations
  set status = 'revoked',revoked_at = now(),updated_at = now()
  where id = p_invitation_id and status = 'pending';
  if not found then
    raise exception 'organization invitation cannot be revoked' using errcode = '40001';
  end if;
end
$$;

create or replace function public.resolve_organization_policies(
  p_tenant_id uuid,
  p_identity_id uuid
) returns table (
  policy_id uuid,
  policy_type text,
  configuration jsonb,
  source_scope_type text,
  source_scope_id uuid,
  priority smallint,
  version integer
) language plpgsql stable security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or (
    p_identity_id <> v_actor
    and not private.can_manage_organization_identity(
      p_tenant_id,array['organization_admin','security_admin','auditor'],p_identity_id
    )
  ) then
    raise exception 'effective policy access denied' using errcode = '42501';
  end if;

  return query
  with recursive profile_scope as (
    select profile.department_id
    from public.organization_profiles profile
    where profile.tenant_id = p_tenant_id and profile.identity_id = p_identity_id
  ), department_ancestors(id,parent_department_id) as (
    select department.id,department.parent_department_id
    from public.organization_departments department
    join profile_scope profile on profile.department_id = department.id
    where department.tenant_id = p_tenant_id
    union all
    select parent.id,parent.parent_department_id
    from public.organization_departments parent
    join department_ancestors child on child.parent_department_id = parent.id
    where parent.tenant_id = p_tenant_id
  ), team_scope as (
    select membership.team_id
    from public.organization_team_memberships membership
    where membership.tenant_id = p_tenant_id
      and membership.identity_id = p_identity_id
      and membership.status = 'active'
  ), candidates as (
    select policy.*,
      case policy.scope_type when 'team' then 3 when 'department' then 2 else 1 end as scope_rank
    from public.organization_policies policy
    where policy.tenant_id = p_tenant_id and policy.enforced
      and (
        (policy.scope_type = 'tenant' and policy.scope_id is null)
        or (policy.scope_type = 'department' and policy.scope_id in (select id from department_ancestors))
        or (policy.scope_type = 'team' and policy.scope_id in (select team_id from team_scope))
      )
  )
  select distinct on (candidate.policy_type)
    candidate.id,candidate.policy_type,candidate.configuration,candidate.scope_type,
    candidate.scope_id,candidate.priority,candidate.version
  from candidates candidate
  order by candidate.policy_type,candidate.scope_rank desc,candidate.priority desc,
    candidate.version desc,candidate.updated_at desc,candidate.id;
end
$$;

create or replace function public.evaluate_organization_device_readiness(
  p_tenant_id uuid,
  p_device_id uuid,
  p_identity_id uuid
) returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_device_trusted boolean := false;
  v_approval_required boolean := false;
  v_report public.organization_device_posture_reports%rowtype;
  v_allowed boolean;
begin
  if v_actor is null or (
    p_identity_id <> v_actor
    and not private.can_manage_organization_identity(
      p_tenant_id,array['organization_admin','security_admin','auditor'],p_identity_id
    )
  ) then
    raise exception 'device readiness access denied' using errcode = '42501';
  end if;

  select exists (
    select 1 from public.devices device
    where device.id = p_device_id and device.identity_id = p_identity_id
      and device.status = 'trusted'
  ) into v_device_trusted;

  select coalesce((resolved.configuration ->> 'required')::boolean,false)
  into v_approval_required
  from public.resolve_organization_policies(p_tenant_id,p_identity_id) resolved
  where resolved.policy_type = 'device_approval_required';
  v_approval_required := coalesce(v_approval_required,false);

  select report.* into v_report
  from public.organization_device_posture_reports report
  where report.tenant_id = p_tenant_id
    and report.device_id = p_device_id
    and report.identity_id = p_identity_id
  order by
    (report.verification_status = 'verified') desc,
    report.observed_at desc
  limit 1;

  v_allowed := v_device_trusted and (
    not v_approval_required
    or (
      v_report.verification_status = 'verified'
      and v_report.evaluation = 'compliant'
      and v_report.valid_until > now()
    )
  );

  return jsonb_build_object(
    'allowed',v_allowed,
    'device_trusted',v_device_trusted,
    'approval_required',v_approval_required,
    'posture',coalesce(v_report.evaluation,'unknown'),
    'verified',coalesce(v_report.verification_status = 'verified',false),
    'valid_until',v_report.valid_until,
    'mode','readiness_only',
    'reason',case
      when not v_device_trusted then 'device_not_trusted'
      when not v_approval_required then 'approval_not_required'
      when v_report.id is null then 'verified_posture_missing'
      when v_report.verification_status <> 'verified' then 'verification_required'
      when v_report.valid_until <= now() then 'posture_stale'
      when v_report.evaluation <> 'compliant' then 'posture_non_compliant'
      else 'ready'
    end
  );
end
$$;

create or replace function public.export_organization_audit(
  p_tenant_id uuid,
  p_after_sequence bigint default 0,
  p_limit integer default 500
) returns table (
  sequence bigint,
  occurred_at timestamptz,
  actor_identity_id uuid,
  action text,
  target_type text,
  target_id uuid,
  metadata jsonb,
  previous_hash bytea,
  event_hash bytea
) language plpgsql stable security invoker set search_path = ''
as $$
begin
  if not private.can_export_organization_audit(p_tenant_id) then
    raise exception 'organization audit export denied' using errcode = '42501';
  end if;
  return query
  select event.sequence,event.occurred_at,event.actor_identity_id,event.action,
    event.target_type,event.target_id,event.metadata,event.previous_hash,event.event_hash
  from public.audit_events event
  where event.tenant_id = p_tenant_id and event.sequence > greatest(p_after_sequence,0)
  order by event.sequence
  limit least(greatest(p_limit,1),1000);
end
$$;

revoke all on function public.accept_organization_invitation(uuid,bytea) from public,anon;
revoke all on function public.revoke_organization_invitation(uuid) from public,anon;
revoke all on function public.resolve_organization_policies(uuid,uuid) from public,anon;
revoke all on function public.evaluate_organization_device_readiness(uuid,uuid,uuid) from public,anon;
revoke all on function public.export_organization_audit(uuid,bigint,integer) from public,anon;
grant execute on function public.accept_organization_invitation(uuid,bytea) to authenticated;
grant execute on function public.revoke_organization_invitation(uuid) to authenticated;
grant execute on function public.resolve_organization_policies(uuid,uuid) to authenticated;
grant execute on function public.evaluate_organization_device_readiness(uuid,uuid,uuid) to authenticated;
grant execute on function public.export_organization_audit(uuid,bigint,integer) to authenticated;

create trigger organization_departments_audit
after insert or update or delete on public.organization_departments
for each row execute function private.phase2_audit_event();
create trigger organization_teams_audit
after insert or update or delete on public.organization_teams
for each row execute function private.phase2_audit_event();
create trigger organization_groups_audit
after insert or update or delete on public.organization_groups
for each row execute function private.phase2_audit_event();
create trigger organization_team_memberships_audit
after insert or update or delete on public.organization_team_memberships
for each row execute function private.phase2_audit_event();
create trigger organization_group_memberships_audit
after insert or update or delete on public.organization_group_memberships
for each row execute function private.phase2_audit_event();
create trigger organization_admin_assignments_audit
after insert or update on public.organization_admin_assignments
for each row execute function private.phase2_audit_event();
create trigger organization_policies_audit
after insert or update on public.organization_policies
for each row execute function private.phase2_audit_event();
create trigger organization_invitations_audit
after insert or update on public.organization_invitations
for each row execute function private.phase2_audit_event();
create trigger organization_device_posture_audit
after insert on public.organization_device_posture_reports
for each row execute function private.phase2_audit_event();

comment on table public.organization_invitations is
  'Email-bound one-time Business directory invitations. Raw invitation secrets and plaintext email addresses are prohibited.';
comment on table public.organization_device_posture_reports is
  'Administrative posture evidence only. Self-reported rows are advisory and cannot satisfy strict device approval.';
comment on function public.evaluate_organization_device_readiness(uuid,uuid,uuid) is
  'Readiness evaluation only. Global vault enforcement requires a reviewed device-bound session claim and remains gated.';
comment on function public.export_organization_audit(uuid,bigint,integer) is
  'Bounded, tenant-authorized audit export. Connector delivery, retention, and legal hold remain enterprise gates.';

commit;
