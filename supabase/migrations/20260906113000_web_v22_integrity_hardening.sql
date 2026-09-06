begin;

-- Runtime scopes are identifiers, never arbitrary descriptions or secrets.
create or replace function private.valid_runtime_scopes(
  p_scopes text[],
  p_allow_empty boolean default false
) returns boolean
language sql immutable strict set search_path = ''
as $$
  select cardinality(p_scopes) <= 50
    and (p_allow_empty or cardinality(p_scopes) > 0)
    and not exists (
      select 1 from unnest(p_scopes) as scope(value)
      where value !~ '^[a-z][a-z0-9_.:-]{0,79}$'
    )
$$;

alter table public.privileged_resources
  add constraint privileged_resources_scopes_valid
  check (private.valid_runtime_scopes(allowed_scopes,false));
alter table public.agent_profiles
  add constraint agent_profiles_scopes_valid
  check (private.valid_runtime_scopes(allowed_scopes,true));
alter table public.privilege_requests
  add constraint privilege_requests_scopes_valid
  check (private.valid_runtime_scopes(requested_scopes,false));
alter table public.agent_task_capsules
  add constraint agent_task_capsules_scopes_valid
  check (private.valid_runtime_scopes(allowed_scopes,false)),
  add constraint agent_task_capsules_resources_bounded
  check (cardinality(resource_ids) between 1 and 50);

create or replace function private.validate_agent_task_capsule()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare v_agent public.agent_profiles%rowtype;
begin
  if tg_op = 'UPDATE' and (
    new.tenant_id is distinct from old.tenant_id
    or new.agent_profile_id is distinct from old.agent_profile_id
    or new.created_by is distinct from old.created_by
    or new.definition_sha256 is distinct from old.definition_sha256
  ) then
    raise exception 'immutable task capsule fields cannot change' using errcode = '22023';
  end if;

  select * into v_agent from public.agent_profiles profile
  where profile.id = new.agent_profile_id and profile.tenant_id = new.tenant_id;
  if not found or v_agent.status not in ('draft','active') then
    raise exception 'agent is unavailable for task capsule' using errcode = '42501';
  end if;
  if not (new.allowed_scopes <@ v_agent.allowed_scopes) then
    raise exception 'task capsule exceeds agent scopes' using errcode = '42501';
  end if;
  if exists (
    select 1 from unnest(new.resource_ids) as requested(resource_id)
    where not exists (
      select 1 from public.privileged_resources resource
      where resource.id = requested.resource_id
        and resource.tenant_id = new.tenant_id
        and resource.status in ('draft','active')
    )
  ) then
    raise exception 'task capsule resource is outside tenant' using errcode = '42501';
  end if;
  return new;
end
$$;

create trigger agent_task_capsules_validate
before insert or update on public.agent_task_capsules
for each row execute function private.validate_agent_task_capsule();

create or replace function public.create_agent_task_capsule(
  p_agent_profile_id uuid,
  p_resource_ids uuid[],
  p_allowed_scopes text[],
  p_definition_sha256 bytea,
  p_expires_at timestamptz,
  p_max_uses integer default 1
) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_agent public.agent_profiles%rowtype; v_id uuid;
begin
  select * into v_agent from public.agent_profiles profile where profile.id = p_agent_profile_id;
  if not found or v_actor is null or not private.can_manage_runtime_tenant(v_agent.tenant_id)
    or not private.has_business_entitlement(v_agent.tenant_id) then
    raise exception 'Business runtime manager permission required' using errcode = '42501';
  end if;
  if p_expires_at <= now() or p_expires_at > now() + interval '30 days' then
    raise exception 'task capsule expiry is invalid' using errcode = '22023';
  end if;
  insert into public.agent_task_capsules(
    tenant_id,agent_profile_id,definition_sha256,resource_ids,allowed_scopes,
    expires_at,max_uses,created_by
  ) values (
    v_agent.tenant_id,v_agent.id,p_definition_sha256,p_resource_ids,p_allowed_scopes,
    p_expires_at,p_max_uses,v_actor
  ) returning id into v_id;
  return v_id;
end
$$;

-- A simulation is advisory evidence for the same tenant, subject, and action;
-- an unrelated or expired preview cannot be attached to an access request.
create or replace function public.create_privilege_request(
  p_resource_id uuid,p_subject_identity_id uuid,p_requested_scopes text[],
  p_duration_minutes integer,p_justification_sha256 bytea,p_simulation_id uuid default null
) returns uuid language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_resource public.privileged_resources%rowtype; v_id uuid;
begin
  if v_actor is null then raise exception 'active identity required' using errcode = '28000'; end if;
  select * into v_resource from public.privileged_resources resource where resource.id = p_resource_id;
  if not found or not private.has_tenant_role(v_resource.tenant_id,array['owner','admin','member']) then
    raise exception 'resource access denied' using errcode = '42501';
  end if;
  if v_resource.status <> 'active' or not private.valid_runtime_scopes(p_requested_scopes,false)
    or not (p_requested_scopes <@ v_resource.allowed_scopes)
    or p_duration_minutes < 1 or p_duration_minutes > v_resource.max_duration_minutes then
    raise exception 'request exceeds resource policy' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tenant_memberships membership
    where membership.tenant_id = v_resource.tenant_id and membership.identity_id = p_subject_identity_id
      and membership.status = 'active') then
    raise exception 'subject identity is outside tenant' using errcode = '42501';
  end if;
  if p_simulation_id is not null and not exists (
    select 1 from public.access_simulations simulation
    where simulation.id = p_simulation_id
      and simulation.tenant_id = v_resource.tenant_id
      and simulation.target_identity_id = p_subject_identity_id
      and simulation.action_type = 'grant'
      and simulation.expires_at > now()
  ) then
    raise exception 'valid same-tenant access simulation required' using errcode = '42501';
  end if;
  insert into public.privilege_requests(tenant_id,resource_id,subject_identity_id,requested_by,
    requested_scopes,requested_duration_minutes,justification_sha256,simulation_id)
  values (v_resource.tenant_id,v_resource.id,p_subject_identity_id,v_actor,p_requested_scopes,
    p_duration_minutes,p_justification_sha256,p_simulation_id) returning id into v_id;
  perform private.runtime_evidence_event(v_resource.tenant_id,null,v_actor,'requested',
    jsonb_build_object('request_id',v_id,'resource_id',v_resource.id,'subject_identity_id',p_subject_identity_id,
      'duration_minutes',p_duration_minutes,'scope_count',cardinality(p_requested_scopes)));
  return v_id;
end
$$;

-- Remove non-retained relationship rows and explicitly revoke retained ones
-- before unlinking the Auth user during account erasure.
create or replace function private.cleanup_deleted_identity_memberships(p_identity_id uuid)
returns void language plpgsql security definer set search_path = ''
as $$
begin
  delete from public.organization_group_memberships where identity_id = p_identity_id;
  update public.workspace_memberships set status = 'revoked',updated_at = now()
    where identity_id = p_identity_id and status <> 'revoked';
end
$$;

create or replace function private.cleanup_deleted_human_identity_trigger()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.kind = 'human' and new.status = 'revoked' and new.auth_user_id is null
    and old.auth_user_id is not null then
    perform private.cleanup_deleted_identity_memberships(new.id);
  end if;
  return new;
end
$$;

create trigger identities_cleanup_deleted_human_memberships
after update of status,auth_user_id on public.identities
for each row execute function private.cleanup_deleted_human_identity_trigger();

drop policy agent_task_capsules_manage on public.agent_task_capsules;
revoke insert,update,delete on public.agent_task_capsules from authenticated;

revoke all on function private.valid_runtime_scopes(text[],boolean),
  private.validate_agent_task_capsule(),private.cleanup_deleted_identity_memberships(uuid),
  private.cleanup_deleted_human_identity_trigger()
  from public,anon,authenticated;
revoke all on function public.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer)
  from public,anon;
grant execute on function public.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer)
  to authenticated;

commit;
