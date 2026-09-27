-- Passkey-X enterprise web v3 — security hardening and verifiable audit chain.
--
-- 1. Fix three RLS policies whose correlated sub-queries compared a column with
--    itself (unqualified names resolve to the innermost relation), which let a
--    caller link rows across tenants/workspaces.
-- 2. Make vault_items head revisions monotonic so direct column UPDATEs cannot
--    roll an item back to an older revision.
-- 3. Audit chain v2: serialised per tenant, hashes only stored fields so it can
--    be verified later, append-only for organisation tenants, plus a
--    verification RPC and metadata-only vault activity events.

-- ---------------------------------------------------------------------------
-- 1. RLS tautology fixes
-- ---------------------------------------------------------------------------
drop policy if exists approvals_create on public.approvals;
create policy approvals_create on public.approvals for insert to authenticated
with check (
  approver_identity_id = (select private.current_identity_id())
  and (select private.can_manage_workspace(approvals.tenant_id, approvals.workspace_id))
  and exists (
    select 1 from public.access_requests ar
    where ar.id = approvals.request_id and ar.status = 'pending'
      and ar.tenant_id = approvals.tenant_id and ar.workspace_id = approvals.workspace_id
  )
);

drop policy if exists mission_items_create on public.mission_items;
create policy mission_items_create on public.mission_items for insert to authenticated
with check (
  (select private.has_workspace_role(mission_items.tenant_id, mission_items.workspace_id, array['owner','manager','editor']))
  and exists (
    select 1 from public.missions m
    where m.id = mission_items.mission_id
      and m.tenant_id = mission_items.tenant_id
      and m.workspace_id = mission_items.workspace_id
  )
  and exists (
    select 1 from public.vault_items vi
    where vi.id = mission_items.item_id
      and vi.tenant_id = mission_items.tenant_id
      and vi.workspace_id = mission_items.workspace_id
  )
);

drop policy if exists organization_device_posture_self_report on public.organization_device_posture_reports;
create policy organization_device_posture_self_report
on public.organization_device_posture_reports for insert to authenticated
with check (
  organization_device_posture_reports.identity_id = (select private.current_identity_id())
  and organization_device_posture_reports.created_by = (select private.current_identity_id())
  and organization_device_posture_reports.source = 'self_reported'
  and organization_device_posture_reports.verification_status = 'unverified'
  and organization_device_posture_reports.evaluation = 'unknown'
  and exists (
    select 1 from public.devices device
    where device.id = organization_device_posture_reports.device_id
      and device.identity_id = organization_device_posture_reports.identity_id
      and device.status = 'trusted'
  )
  and (select private.has_tenant_role(organization_device_posture_reports.tenant_id,array['owner','admin','member','auditor']))
);

-- ---------------------------------------------------------------------------
-- 2. Monotonic vault item heads
-- ---------------------------------------------------------------------------
create or replace function private.enforce_vault_item_head_monotonic()
returns trigger language plpgsql set search_path = ''
as $$
begin
  if new.head_revision is distinct from old.head_revision
     and new.head_revision <> old.head_revision + 1 then
    raise exception 'vault item head revision must advance by exactly one' using errcode = '40001';
  end if;
  if new.tenant_id <> old.tenant_id or new.workspace_id <> old.workspace_id
     or new.content_type <> old.content_type then
    raise exception 'vault item identity columns are immutable' using errcode = '42501';
  end if;
  return new;
end
$$;
revoke all on function private.enforce_vault_item_head_monotonic() from public, anon, authenticated;

drop trigger if exists vault_items_head_monotonic on public.vault_items;
create trigger vault_items_head_monotonic before update on public.vault_items
  for each row execute function private.enforce_vault_item_head_monotonic();

-- ---------------------------------------------------------------------------
-- 3. Audit chain v2
-- ---------------------------------------------------------------------------
alter table public.audit_events
  add column if not exists hash_version smallint not null default 1
  check (hash_version in (1,2));

create index if not exists audit_events_actor_time_idx
  on public.audit_events(actor_identity_id, occurred_at desc);
create index if not exists audit_events_tenant_action_idx
  on public.audit_events(tenant_id, action, sequence desc);

-- Canonical v2 digest input. Every component is a stored column, so the chain
-- can be recomputed and verified at any time.
create or replace function private.audit_event_digest_v2(
  p_tenant uuid, p_actor uuid, p_action text, p_target_type text, p_target uuid,
  p_metadata jsonb, p_previous bytea, p_occurred_at timestamptz
) returns bytea language sql immutable set search_path = ''
as $$
  select extensions.digest(convert_to(concat_ws('|',
    'px-audit-v2',
    p_tenant::text,
    coalesce(p_actor::text,''),
    p_action,
    p_target_type,
    coalesce(p_target::text,''),
    coalesce(p_metadata,'{}'::jsonb)::text,
    coalesce(encode(p_previous,'hex'),''),
    to_char(p_occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ),'UTF8'),'sha256')
$$;

create or replace function private.append_audit_event(
  p_tenant uuid, p_actor uuid, p_action text, p_target_type text, p_target uuid, p_metadata jsonb
) returns bigint language plpgsql security definer set search_path = ''
as $$
declare
  v_previous bytea;
  v_now timestamptz := clock_timestamp();
  v_metadata jsonb := coalesce(p_metadata,'{}'::jsonb);
  v_sequence bigint;
begin
  if p_tenant is null then return null; end if;
  -- Serialise appends per tenant so concurrent writers cannot fork the chain.
  perform pg_advisory_xact_lock(hashtextextended('px-audit:' || p_tenant::text, 0));
  select event_hash into v_previous from public.audit_events
    where tenant_id = p_tenant order by sequence desc limit 1;
  insert into public.audit_events(tenant_id,actor_identity_id,action,target_type,target_id,
    metadata,previous_hash,event_hash,occurred_at,hash_version)
  values (p_tenant,p_actor,p_action,p_target_type,p_target,v_metadata,v_previous,
    private.audit_event_digest_v2(p_tenant,p_actor,p_action,p_target_type,p_target,v_metadata,v_previous,v_now),
    v_now,2)
  returning sequence into v_sequence;
  return v_sequence;
end
$$;
revoke all on function private.append_audit_event(uuid,uuid,text,text,uuid,jsonb) from public, anon, authenticated;
revoke all on function private.audit_event_digest_v2(uuid,uuid,text,text,uuid,jsonb,bytea,timestamptz) from public, anon;

-- Existing trigger function now delegates to the v2 appender (same metadata).
create or replace function private.phase2_audit_event()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_row jsonb := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
  v_tenant uuid := (v_row ->> 'tenant_id')::uuid;
  v_target uuid;
  v_metadata jsonb;
begin
  begin
    v_target := coalesce((v_row ->> 'id')::uuid, (v_row ->> 'workspace_id')::uuid);
  exception when invalid_text_representation then
    v_target := null;
  end;
  v_metadata := jsonb_strip_nulls(jsonb_build_object(
    'status', v_row ->> 'status', 'role', v_row ->> 'role',
    'reveal_policy', v_row ->> 'reveal_policy', 'expires_at', v_row ->> 'expires_at',
    'policy_type', v_row ->> 'policy_type', 'enforced', v_row ->> 'enforced'
  ));
  perform private.append_audit_event(v_tenant, private.current_identity_id(),
    tg_table_name || '.' || lower(tg_op), tg_table_name, v_target, v_metadata);
  return case when tg_op = 'DELETE' then old else new end;
end
$$;
revoke all on function private.phase2_audit_event() from public, anon, authenticated;

-- Organisation audit history is append-only. Personal tenants may still be
-- purged by the guarded account-deletion flow.
create or replace function private.protect_audit_events()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' then
    raise exception 'audit events are immutable' using errcode = '42501';
  end if;
  if exists (select 1 from public.tenants t where t.id = old.tenant_id and t.kind = 'organization') then
    raise exception 'organization audit events cannot be deleted' using errcode = '42501';
  end if;
  return old;
end
$$;
revoke all on function private.protect_audit_events() from public, anon, authenticated;

drop trigger if exists audit_events_append_only on public.audit_events;
create trigger audit_events_append_only before update or delete on public.audit_events
  for each row execute function private.protect_audit_events();

-- Metadata-only vault item lifecycle events (never content, titles or URLs).
create or replace function private.vault_item_audit_event()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_action text;
begin
  if tg_op = 'INSERT' then
    v_action := 'vault_item.created';
  elsif new.deleted_at is not null and old.deleted_at is null then
    v_action := 'vault_item.deleted';
  elsif new.deleted_at is null and old.deleted_at is not null then
    v_action := 'vault_item.restored';
  elsif new.head_revision <> old.head_revision then
    v_action := 'vault_item.updated';
  else
    return new;
  end if;
  perform private.append_audit_event(new.tenant_id, private.current_identity_id(), v_action,
    'vault_items', new.id, jsonb_build_object('workspace_id', new.workspace_id,
      'content_type', new.content_type, 'revision', new.head_revision));
  return new;
end
$$;
revoke all on function private.vault_item_audit_event() from public, anon, authenticated;

drop trigger if exists vault_items_audit on public.vault_items;
create trigger vault_items_audit after insert or update on public.vault_items
  for each row execute function private.vault_item_audit_event();

-- Client-reported, metadata-only activity (reveal/copy/export etc.).
create or replace function private.record_vault_activity(
  p_tenant_id uuid, p_workspace_id uuid, p_item_id uuid, p_action text
) returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_recent integer;
begin
  if v_actor is null then raise exception 'active identity required' using errcode = '28000'; end if;
  if p_action not in ('item.revealed','item.copied','item.autofilled','item.history_viewed',
    'vault.unlocked','vault.locked','vault.exported','vault.imported','policy.blocked') then
    raise exception 'unsupported activity' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.workspace_memberships wm
    where wm.tenant_id = p_tenant_id and wm.workspace_id = p_workspace_id
      and wm.identity_id = v_actor and wm.status = 'active'
  ) then
    raise exception 'workspace membership required' using errcode = '42501';
  end if;
  if p_item_id is not null and not exists (
    select 1 from public.vault_items vi
    where vi.id = p_item_id and vi.tenant_id = p_tenant_id and vi.workspace_id = p_workspace_id
  ) then
    raise exception 'unknown vault item' using errcode = '22023';
  end if;
  select count(*) into v_recent from public.audit_events
    where actor_identity_id = v_actor and occurred_at > now() - interval '1 hour'
      and target_type = 'client_activity';
  if v_recent >= 1200 then
    raise exception 'activity rate limit exceeded' using errcode = '54000';
  end if;
  perform private.append_audit_event(p_tenant_id, v_actor, p_action, 'client_activity',
    p_item_id, jsonb_build_object('workspace_id', p_workspace_id));
end
$$;
revoke all on function private.record_vault_activity(uuid,uuid,uuid,text) from public, anon;
grant execute on function private.record_vault_activity(uuid,uuid,uuid,text) to authenticated;

-- Readable audit for organisation admins/auditors with filters.
create or replace function private.can_read_organization_audit(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin','auditor'])
    or private.can_manage_organization(target_tenant,array['organization_admin','security_admin','auditor'])
$$;
revoke all on function private.can_read_organization_audit(uuid) from public, anon;
grant execute on function private.can_read_organization_audit(uuid) to authenticated;

create or replace function private.search_organization_audit(
  p_tenant_id uuid,
  p_before_sequence bigint default null,
  p_limit integer default 100,
  p_action_prefix text default null,
  p_actor_identity_id uuid default null,
  p_since timestamptz default null,
  p_until timestamptz default null
) returns table (
  sequence bigint, occurred_at timestamptz, actor_identity_id uuid, actor_name text,
  action text, target_type text, target_id uuid, metadata jsonb, hash_version smallint,
  event_hash text
) language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_read_organization_audit(p_tenant_id) then
    raise exception 'organization audit access denied' using errcode = '42501';
  end if;
  return query
  select e.sequence, e.occurred_at, e.actor_identity_id,
    coalesce(p.display_name, u.email::text, 'System'),
    e.action, e.target_type, e.target_id, e.metadata, e.hash_version,
    encode(e.event_hash,'hex')
  from public.audit_events e
  left join public.organization_profiles p on p.tenant_id = e.tenant_id and p.identity_id = e.actor_identity_id
  left join public.identities i on i.id = e.actor_identity_id
  left join auth.users u on u.id = i.auth_user_id
  where e.tenant_id = p_tenant_id
    and (p_before_sequence is null or e.sequence < p_before_sequence)
    and (p_action_prefix is null or e.action like p_action_prefix || '%')
    and (p_actor_identity_id is null or e.actor_identity_id = p_actor_identity_id)
    and (p_since is null or e.occurred_at >= p_since)
    and (p_until is null or e.occurred_at < p_until)
  order by e.sequence desc
  limit least(greatest(coalesce(p_limit,100),1),500);
end
$$;
revoke all on function private.search_organization_audit(uuid,bigint,integer,text,uuid,timestamptz,timestamptz) from public, anon;
grant execute on function private.search_organization_audit(uuid,bigint,integer,text,uuid,timestamptz,timestamptz) to authenticated;

-- Chain verification: linkage for every event, full recomputation for v2 events.
create or replace function private.verify_organization_audit_chain(p_tenant_id uuid)
returns table (
  checked_events bigint, v2_events bigint, first_invalid_sequence bigint,
  first_invalid_reason text, head_sequence bigint, head_hash text, verified_at timestamptz
) language plpgsql stable security definer set search_path = ''
as $$
declare
  v_row record;
  v_previous bytea := null;
  v_checked bigint := 0;
  v_v2 bigint := 0;
  v_bad bigint := null;
  v_reason text := null;
  v_head bigint := null;
  v_head_hash bytea := null;
begin
  if not private.can_read_organization_audit(p_tenant_id) then
    raise exception 'organization audit access denied' using errcode = '42501';
  end if;
  for v_row in
    select * from public.audit_events where tenant_id = p_tenant_id order by sequence
  loop
    v_checked := v_checked + 1;
    if v_row.previous_hash is distinct from v_previous and v_bad is null then
      v_bad := v_row.sequence; v_reason := 'chain link mismatch';
    end if;
    if v_row.hash_version = 2 then
      v_v2 := v_v2 + 1;
      if v_bad is null and v_row.event_hash <> private.audit_event_digest_v2(
        v_row.tenant_id, v_row.actor_identity_id, v_row.action, v_row.target_type,
        v_row.target_id, v_row.metadata, v_row.previous_hash, v_row.occurred_at) then
        v_bad := v_row.sequence; v_reason := 'event hash mismatch';
      end if;
    end if;
    v_previous := v_row.event_hash;
    v_head := v_row.sequence;
    v_head_hash := v_row.event_hash;
  end loop;
  return query select v_checked, v_v2, v_bad, v_reason, v_head, encode(v_head_hash,'hex'), now();
end
$$;
revoke all on function private.verify_organization_audit_chain(uuid) from public, anon;
grant execute on function private.verify_organization_audit_chain(uuid) to authenticated;

comment on function private.record_vault_activity(uuid,uuid,uuid,text) is
  'Appends a metadata-only client activity event (no vault content) to the tenant audit chain.';
comment on function private.verify_organization_audit_chain(uuid) is
  'Recomputes the tenant audit hash chain and reports the first invalid event, if any.';

-- Browser-callable SECURITY INVOKER wrappers (implementations live in private).
create or replace function public.record_vault_activity(
  p_tenant_id uuid, p_workspace_id uuid, p_item_id uuid, p_action text
) returns void language sql volatile security invoker set search_path = ''
as $$ select private.record_vault_activity(p_tenant_id, p_workspace_id, p_item_id, p_action) $$;

create or replace function public.search_organization_audit(
  p_tenant_id uuid, p_before_sequence bigint default null, p_limit integer default 100,
  p_action_prefix text default null, p_actor_identity_id uuid default null,
  p_since timestamptz default null, p_until timestamptz default null
) returns table (
  sequence bigint, occurred_at timestamptz, actor_identity_id uuid, actor_name text,
  action text, target_type text, target_id uuid, metadata jsonb, hash_version smallint, event_hash text
) language sql stable security invoker set search_path = ''
as $$ select * from private.search_organization_audit(p_tenant_id, p_before_sequence, p_limit,
  p_action_prefix, p_actor_identity_id, p_since, p_until) $$;

create or replace function public.verify_organization_audit_chain(p_tenant_id uuid)
returns table (
  checked_events bigint, v2_events bigint, first_invalid_sequence bigint,
  first_invalid_reason text, head_sequence bigint, head_hash text, verified_at timestamptz
) language sql stable security invoker set search_path = ''
as $$ select * from private.verify_organization_audit_chain(p_tenant_id) $$;

revoke all on function public.record_vault_activity(uuid,uuid,uuid,text) from public, anon;
revoke all on function public.search_organization_audit(uuid,bigint,integer,text,uuid,timestamptz,timestamptz) from public, anon;
revoke all on function public.verify_organization_audit_chain(uuid) from public, anon;
grant execute on function public.record_vault_activity(uuid,uuid,uuid,text) to authenticated;
grant execute on function public.search_organization_audit(uuid,bigint,integer,text,uuid,timestamptz,timestamptz) to authenticated;
grant execute on function public.verify_organization_audit_chain(uuid) to authenticated;
