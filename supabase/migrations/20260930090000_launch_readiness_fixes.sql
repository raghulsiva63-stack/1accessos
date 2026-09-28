-- Launch-readiness fixes found in the September 2026 plan and journey audit.
-- 1. Device limits come from the plan of every tenant the person belongs to.
-- 2. Re-invited workspace members and re-invited organization members are reactivated.
-- 3. Members see only their own SCIM-provisioned account offer.
-- 4. Business-only admin features are gated on the server, and a downgrade
--    stops SCIM, audit streaming and still lets admins remove old policies.

-- 1 ---------------------------------------------------------------------------
-- NULL means unlimited. Paid plans with no device cap (every paid plan today)
-- lift the cap for everyone in that tenant; otherwise the Free cap of 2 applies.
create or replace function private.device_limit_for(target_identity uuid)
returns integer language sql stable security definer set search_path = ''
as $$
  with paid as (
    select e.max_devices
    from public.tenant_memberships m
    join public.tenant_entitlements e on e.tenant_id = m.tenant_id
    where m.identity_id = target_identity and m.status = 'active'
      and e.plan_code <> 'free'
      and (e.valid_until is null or e.valid_until > now())
      and (e.source = 'manual' or (e.source = 'stripe' and e.subscription_status in ('trialing','active','past_due')))
  )
  select case
    when exists (select 1 from public.account_entitlements a where a.identity_id = target_identity and a.plan_code = 'personal') then null
    when exists (select 1 from paid where max_devices is null) then null
    else greatest(2, coalesce((select max(max_devices) from paid), 2))
  end
$$;
revoke all on function private.device_limit_for(uuid) from public, anon, authenticated;

create or replace function private.can_register_device(target_identity uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select target_identity = private.current_identity_id()
    and (select count(*) from public.devices d
         where d.identity_id = target_identity and d.status <> 'revoked')
        < coalesce(private.device_limit_for(target_identity), 2147483647)
$$;

-- 2a --------------------------------------------------------------------------
-- Runs right after accept_workspace_invite marks the invite accepted. A person
-- who was removed earlier still has a revoked membership row; bring it back.
create or replace function private.reactivate_invited_workspace_member(p_invite_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_invite public.workspace_invites%rowtype;
begin
  select * into v_invite from public.workspace_invites i
    where i.id = p_invite_id and i.status = 'accepted' and i.accepted_by = v_actor
      and i.accepted_at > now() - interval '1 minute';
  if not found then return; end if;
  update public.tenant_memberships set status = 'active', updated_at = now()
    where tenant_id = v_invite.tenant_id and identity_id = v_actor and status = 'revoked';
  update public.workspace_memberships set status = 'active', role = v_invite.role, expires_at = null, updated_at = now()
    where tenant_id = v_invite.tenant_id and workspace_id = v_invite.workspace_id
      and identity_id = v_actor and status <> 'active';
end
$$;
revoke all on function private.reactivate_invited_workspace_member(uuid) from public, anon;
grant execute on function private.reactivate_invited_workspace_member(uuid) to authenticated;

create or replace function public.accept_workspace_invite(
  p_invite_id uuid,
  p_token_hash bytea,
  p_root_key_nonce bytea,
  p_root_wrapped_workspace_key bytea
) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_invite public.workspace_invites%rowtype;
  v_invalidated_hash bytea;
begin
  if v_identity is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_token_hash) <> 32 or octet_length(p_root_key_nonce) <> 12
    or octet_length(p_root_wrapped_workspace_key) < 48 then
    raise exception 'invalid invitation envelope' using errcode = '22023';
  end if;

  perform set_config('request.passkey_x_invite_proof', encode(p_token_hash, 'hex'), true);
  perform set_config('request.passkey_x_invite_accepting', p_invite_id::text, true);
  select * into v_invite from public.workspace_invites
    where id = p_invite_id and status = 'pending' and expires_at > now()
      and recipient_email_hash = private.current_verified_email_hash()
      and token_hash = p_token_hash
    for update;
  if not found then raise exception 'invitation is invalid or expired' using errcode = '28000'; end if;

  v_invalidated_hash := extensions.digest(p_token_hash || uuid_send(p_invite_id), 'sha256');
  update public.workspace_invites set status = 'accepted', accepted_by = v_identity,
    accepted_at = now(), updated_at = now(), token_hash = v_invalidated_hash
    where id = p_invite_id;

  insert into public.tenant_memberships(tenant_id, identity_id, role, status)
    values (v_invite.tenant_id, v_identity, 'member', 'active') on conflict do nothing;
  insert into public.workspace_memberships(tenant_id, workspace_id, identity_id, role, status)
    values (v_invite.tenant_id, v_invite.workspace_id, v_identity, v_invite.role, 'active')
    on conflict do nothing;
  perform private.reactivate_invited_workspace_member(p_invite_id);
  insert into public.key_envelopes(tenant_id, workspace_id, key_kind, key_version,
    recipient_identity_id, algorithm, nonce, wrapped_key)
    select v_invite.tenant_id, v_invite.workspace_id, 'workspace', w.current_key_version,
      v_identity, 'AES-256-GCM', p_root_key_nonce, p_root_wrapped_workspace_key
    from public.workspaces w where w.id = v_invite.workspace_id and w.tenant_id = v_invite.tenant_id;

  return jsonb_build_object('tenant_id', v_invite.tenant_id, 'workspace_id', v_invite.workspace_id, 'role', v_invite.role);
end
$$;

-- 2b --------------------------------------------------------------------------
-- A former member keeps their organization profile row; accepting a new
-- invitation must reactivate it instead of failing on the primary key.
create or replace function private.provision_accepted_organization_invitation()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_identity uuid := private.current_identity_id();
begin
  if old.status <> 'pending' or new.status <> 'accepted' then return new; end if;
  if v_identity is null
    or new.accepted_by <> v_identity
    or old.recipient_email_hash <> private.current_verified_email_hash()
    or old.token_hash <> decode(
      coalesce(current_setting('request.passkey_x_org_invite_proof',true),''),'hex'
    ) then
    raise exception 'organization invitation proof is invalid' using errcode = '28000';
  end if;

  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
  values (new.tenant_id,v_identity,'member','active')
  on conflict (tenant_id,identity_id) do update set status = 'active', updated_at = now()
    where public.tenant_memberships.status = 'revoked';

  insert into public.organization_profiles(
    tenant_id,identity_id,department_id,display_name,job_title,lifecycle_status,joined_on
  ) values (
    new.tenant_id,v_identity,new.department_id,
    new.display_name,new.job_title,'active',current_date
  )
  on conflict (tenant_id,identity_id) do update set
    department_id = excluded.department_id, display_name = excluded.display_name,
    job_title = excluded.job_title, lifecycle_status = 'active',
    joined_on = excluded.joined_on, updated_at = now();

  if new.team_id is not null then
    insert into public.organization_team_memberships(
      tenant_id,team_id,identity_id,role,status,assigned_by
    ) values (
      new.tenant_id,new.team_id,v_identity,new.team_role,'active',new.created_by
    )
    on conflict (team_id,identity_id) do update set role = excluded.role, status = 'active',
      assigned_by = excluded.assigned_by;
  end if;

  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,to_department_id,to_team_id,
    actor_identity_id,reason_code
  ) values (
    new.tenant_id,v_identity,'joined',new.department_id,
    new.team_id,v_identity,'onboarding'
  );
  return new;
end
$$;

-- 3 ---------------------------------------------------------------------------
create or replace function private.my_pending_provisioning()
returns table (id uuid, tenant_id uuid, display_name text)
language sql stable security definer set search_path = ''
as $$
  select u.id, u.tenant_id, u.display_name
  from public.scim_provisioned_users u
  where u.active and u.identity_id is null
    and u.email_hash = private.current_verified_email_hash()
    and private.current_identity_id() is not null
  order by u.created_at
$$;
revoke all on function private.my_pending_provisioning() from public, anon;
grant execute on function private.my_pending_provisioning() to authenticated;
create or replace function public.my_pending_provisioning()
returns table (id uuid, tenant_id uuid, display_name text)
language sql stable security invoker set search_path = ''
as $$ select * from private.my_pending_provisioning() $$;
revoke all on function public.my_pending_provisioning() from public, anon;
grant execute on function public.my_pending_provisioning() to authenticated;

-- 4 ---------------------------------------------------------------------------
create or replace function private.require_business_plan(p_tenant_id uuid)
returns void language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business plan required' using errcode = '42501', hint = 'plan_required';
  end if;
end
$$;
revoke all on function private.require_business_plan(uuid) from public, anon;
grant execute on function private.require_business_plan(uuid) to authenticated;

create or replace function private.require_business_plan_for_workspace(p_workspace_id uuid)
returns void language plpgsql stable security definer set search_path = ''
as $$
begin
  perform private.require_business_plan((select w.tenant_id from public.workspaces w where w.id = p_workspace_id));
end
$$;
revoke all on function private.require_business_plan_for_workspace(uuid) from public, anon;
grant execute on function private.require_business_plan_for_workspace(uuid) to authenticated;

create or replace function public.organization_compliance_snapshot(p_tenant_id uuid)
returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
begin
  perform private.require_business_plan(p_tenant_id);
  return private.organization_compliance_snapshot(p_tenant_id);
end
$$;

create or replace function public.organization_access_review(p_tenant_id uuid)
returns table (
  workspace_id uuid, suite text, workspace_status text, workspace_created_at timestamptz,
  key_rotation_required boolean, identity_id uuid, display_name text, email text,
  role text, membership_status text, expires_at timestamptz, member_since timestamptz,
  last_activity_at timestamptz
) language plpgsql stable security invoker set search_path = ''
as $$
begin
  perform private.require_business_plan(p_tenant_id);
  return query select * from private.organization_access_review(p_tenant_id);
end
$$;

-- Personal emergency access stays on every plan; organization break-glass is Business.
create or replace function public.create_emergency_access(
  p_id uuid, p_workspace_id uuid, p_kind text, p_recipient_email_hash bytea, p_label text,
  p_wait_hours integer, p_access_hours integer, p_token_hash bytea,
  p_key_version integer, p_key_nonce bytea, p_wrapped_workspace_key bytea, p_key_aad_hash bytea
) returns void language plpgsql volatile security invoker set search_path = ''
as $$
begin
  if p_kind = 'break_glass' then
    perform private.require_business_plan_for_workspace(p_workspace_id);
  end if;
  perform private.create_emergency_access(p_id, p_workspace_id, p_kind, p_recipient_email_hash, p_label,
    p_wait_hours, p_access_hours, p_token_hash, p_key_version, p_key_nonce, p_wrapped_workspace_key, p_key_aad_hash);
end
$$;

create or replace function private.can_manage_audit_webhooks(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_business_entitlement(target_tenant)
    and (private.has_tenant_role(target_tenant, array['owner','admin'])
      or private.can_manage_organization(target_tenant, array['organization_admin','security_admin']))
$$;

create or replace function private.scim_tenant_for_token(p_token text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_tenant uuid;
begin
  update public.scim_tokens s set last_used_at = now()
    where s.token_hash = extensions.digest(p_token, 'sha256') and s.revoked_at is null
      and private.has_business_entitlement(s.tenant_id)
    returning s.tenant_id into v_tenant;
  return v_tenant;
end
$$;

-- After a downgrade, admins can still remove policies they set while on Business.
drop policy if exists organization_policies_delete on public.organization_policies;
create policy organization_policies_delete
on public.organization_policies for delete to authenticated
using (
  (select private.can_manage_organization_scope(
    tenant_id,array['organization_admin','security_admin'],
    case when scope_type = 'department' then scope_id else null end,
    case when scope_type = 'team' then scope_id else null end
  ))
);

create or replace function private.deliver_audit_webhooks()
returns integer
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_hook public.audit_webhooks%rowtype;
  v_response record;
  v_through bigint;
  v_events jsonb;
  v_sent integer := 0;
begin
  for v_hook in select * from public.audit_webhooks w where w.enabled or w.test_request_id is not null for update skip locked loop
    if v_hook.test_request_id is not null then
      select r.status_code into v_response from net._http_response r where r.id = v_hook.test_request_id;
      if found then
        update public.audit_webhooks set last_test_status = coalesce(v_response.status_code, 0), test_request_id = null where id = v_hook.id;
      elsif v_hook.last_test_at < now() - interval '2 minutes' then
        update public.audit_webhooks set last_test_status = 0, test_request_id = null where id = v_hook.id;
      end if;
    end if;
    continue when not v_hook.enabled;
    -- Streaming stops while the organization has no Business plan (downgrade).
    continue when not private.has_business_entitlement(v_hook.tenant_id);

    if v_hook.pending_request_id is not null then
      select r.status_code, r.error_msg, r.timed_out into v_response from net._http_response r where r.id = v_hook.pending_request_id;
      if not found and v_hook.pending_since > now() - interval '3 minutes' then
        continue;
      end if;
      if found and v_response.status_code between 200 and 299 then
        update public.audit_webhooks set delivered_through = pending_through, pending_request_id = null, pending_through = null,
          pending_since = null, last_success_at = now(), last_status = v_response.status_code, last_error = null, failure_count = 0
          where id = v_hook.id;
        v_hook.delivered_through := v_hook.pending_through;
      else
        update public.audit_webhooks set pending_request_id = null, pending_through = null, pending_since = null,
          failure_count = failure_count + 1, enabled = failure_count + 1 < 100,
          last_status = case when found then v_response.status_code else null end,
          last_error = left(case when not found then 'no response' when v_response.timed_out then 'timed out'
            else coalesce(v_response.error_msg, 'HTTP ' || v_response.status_code) end, 300)
          where id = v_hook.id;
        continue;
      end if;
    end if;

    -- Exponential backoff after failures (1, 2, 4 … up to 60 minutes).
    continue when v_hook.failure_count > 0 and v_hook.last_attempt_at is not null
      and v_hook.last_attempt_at > now() - least(interval '60 minutes', interval '1 minute' * power(2, least(v_hook.failure_count, 6)));

    select max(e.sequence) into v_through from (
      select e.sequence from public.audit_events e
      where e.tenant_id = v_hook.tenant_id and e.sequence > v_hook.delivered_through
      order by e.sequence limit 200) e;
    continue when v_through is null;

    select coalesce(jsonb_agg(jsonb_build_object(
      'sequence', e.sequence, 'occurred_at', e.occurred_at, 'action', e.action, 'target_type', e.target_type,
      'target_id', e.target_id, 'actor_identity_id', e.actor_identity_id, 'metadata', e.metadata,
      'hash_version', e.hash_version, 'event_hash', encode(e.event_hash, 'hex')) order by e.sequence), '[]'::jsonb)
    into v_events
    from public.audit_events e
    where e.tenant_id = v_hook.tenant_id and e.sequence > v_hook.delivered_through and e.sequence <= v_through
      and (cardinality(v_hook.event_prefixes) = 0 or exists (select 1 from unnest(v_hook.event_prefixes) prefix where left(e.action, char_length(prefix)) = prefix));

    if jsonb_array_length(v_events) = 0 then
      update public.audit_webhooks set delivered_through = v_through where id = v_hook.id;
      continue;
    end if;

    update public.audit_webhooks set
      pending_request_id = private.post_audit_webhook(v_hook, jsonb_build_object(
        'source', 'passkey-x', 'type', 'audit_events', 'webhook_id', v_hook.id, 'tenant_id', v_hook.tenant_id,
        'sent_at', now(), 'first_sequence', v_hook.delivered_through + 1, 'last_sequence', v_through, 'events', v_events)),
      pending_through = v_through, pending_since = now(), last_attempt_at = now()
      where id = v_hook.id;
    v_sent := v_sent + 1;
  end loop;
  delete from private.audit_webhook_outbox o where o.created_at < now() - interval '1 hour';
  return v_sent;
end
$$;
