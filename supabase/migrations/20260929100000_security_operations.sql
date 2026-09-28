-- Passkey-X security operations:
--   * Emergency access (personal emergency contacts and organisation break-glass)
--   * Risky-event security alerts generated from the audit log
--   * Compliance snapshots (on demand and monthly)
--
-- Emergency access is zero-knowledge. The grantor wraps the workspace key with a
-- random grant secret T (sent to the grantee as a one-time link). The grantee stores
-- T re-wrapped under their own account root key. The server keeps the T-wrapped
-- workspace key behind an approval gate (grantor approval or an elapsed waiting
-- period) and only then releases it; the grantee then joins the workspace as a
-- time-limited viewer. Vlightsoft never holds T or the workspace key.

-- ---------------------------------------------------------------------------
-- Emergency access
-- ---------------------------------------------------------------------------
create table if not exists public.emergency_access_grants (
  id uuid primary key,
  tenant_id uuid not null,
  workspace_id uuid not null,
  kind text not null check (kind in ('personal','break_glass')),
  grantor_identity_id uuid not null references public.identities(id) on delete cascade,
  recipient_email_hash bytea not null check (octet_length(recipient_email_hash) = 32),
  grantee_identity_id uuid references public.identities(id) on delete cascade,
  label text check (label is null or char_length(label) <= 80),
  wait_hours integer not null check (wait_hours between 0 and 720),
  access_hours integer not null default 168 check (access_hours between 1 and 720),
  status text not null default 'invited'
    check (status in ('invited','active','requested','approved','revoked','used')),
  token_hash bytea not null check (octet_length(token_hash) = 32),
  invite_expires_at timestamptz not null default (now() + interval '14 days'),
  key_version integer not null check (key_version > 0),
  key_nonce bytea check (key_nonce is null or octet_length(key_nonce) = 12),
  wrapped_workspace_key bytea,
  key_aad_hash bytea not null check (octet_length(key_aad_hash) = 32),
  grantee_secret_nonce bytea,
  grantee_wrapped_secret bytea,
  requested_at timestamptz,
  approved_at timestamptz,
  decided_by uuid references public.identities(id) on delete set null,
  used_at timestamptz,
  created_tenant_membership boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  check (grantor_identity_id is distinct from grantee_identity_id)
);
create index if not exists emergency_access_grantor_idx on public.emergency_access_grants (grantor_identity_id);
create index if not exists emergency_access_grantee_idx on public.emergency_access_grants (grantee_identity_id);
create index if not exists emergency_access_tenant_idx on public.emergency_access_grants (tenant_id, status);

alter table public.emergency_access_grants enable row level security;
revoke all on public.emergency_access_grants from anon, authenticated;
-- Key material, the invite verifier and the grantee's wrapped secret are never selectable.
grant select (id, tenant_id, workspace_id, kind, grantor_identity_id, grantee_identity_id, label, wait_hours,
  access_hours, status, invite_expires_at, key_version, requested_at, approved_at, decided_by, used_at,
  created_at, updated_at) on public.emergency_access_grants to authenticated;

drop policy if exists emergency_access_read on public.emergency_access_grants;
create policy emergency_access_read on public.emergency_access_grants for select to authenticated
using (
  grantor_identity_id = (select private.current_identity_id())
  or grantee_identity_id = (select private.current_identity_id())
  or (status = 'invited' and recipient_email_hash = (select private.current_verified_email_hash()))
  or (kind = 'break_glass' and (select private.can_admin_workspace_access(tenant_id)))
);

drop policy if exists emergency_access_require_mfa on public.emergency_access_grants;
create policy emergency_access_require_mfa on public.emergency_access_grants as restrictive for all to authenticated
  using ((select private.session_mfa_satisfied())) with check ((select private.session_mfa_satisfied()));

-- Sharing policy (internal-only / disabled) applies to emergency contacts too.
drop trigger if exists emergency_access_sharing_policy on public.emergency_access_grants;
create trigger emergency_access_sharing_policy before insert on public.emergency_access_grants
  for each row execute function private.enforce_sharing_policy();

-- Grants whose waiting period has elapsed count as approved.
create or replace function private.emergency_access_released(g public.emergency_access_grants)
returns boolean language sql stable set search_path = ''
as $$
  select g.status = 'approved'
    or (g.status = 'requested' and g.requested_at is not null
        and g.requested_at + make_interval(hours => g.wait_hours) <= now())
$$;
revoke all on function private.emergency_access_released(public.emergency_access_grants) from public, anon, authenticated;

create or replace function private.create_emergency_access(
  p_id uuid, p_workspace_id uuid, p_kind text, p_recipient_email_hash bytea, p_label text,
  p_wait_hours integer, p_access_hours integer, p_token_hash bytea,
  p_key_version integer, p_key_nonce bytea, p_wrapped_workspace_key bytea, p_key_aad_hash bytea
) returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_workspace public.workspaces%rowtype;
  v_suite text;
begin
  if v_actor is null then raise exception 'active identity required' using errcode = '28000'; end if;
  select * into v_workspace from public.workspaces w where w.id = p_workspace_id;
  if not found or not private.can_manage_workspace(v_workspace.tenant_id, p_workspace_id) then
    raise exception 'emergency access denied' using errcode = '42501';
  end if;
  if p_kind not in ('personal','break_glass') then raise exception 'invalid kind' using errcode = '22023'; end if;
  if p_kind = 'break_glass' and not private.can_admin_workspace_access(v_workspace.tenant_id) then
    raise exception 'only organization administrators can create break-glass access' using errcode = '42501';
  end if;
  if p_kind = 'personal' and p_wait_hours < 24 then
    raise exception 'emergency contacts need a waiting period of at least 24 hours' using errcode = '22023';
  end if;
  if p_key_version is distinct from (select w.current_key_version from public.workspaces w where w.id = p_workspace_id) then
    raise exception 'workspace key changed; reload and try again' using errcode = '40001';
  end if;
  if octet_length(p_token_hash) <> 32 or octet_length(p_key_nonce) <> 12 or octet_length(p_wrapped_workspace_key) < 48
     or octet_length(p_key_aad_hash) <> 32 or octet_length(p_recipient_email_hash) <> 32 then
    raise exception 'invalid emergency access envelope' using errcode = '22023';
  end if;
  if (select count(*) from public.emergency_access_grants g
      where g.workspace_id = p_workspace_id and g.status not in ('revoked','used')) >= 10 then
    raise exception 'a workspace can have at most 10 active emergency grants' using errcode = 'P0001';
  end if;
  insert into public.emergency_access_grants (id, tenant_id, workspace_id, kind, grantor_identity_id,
    recipient_email_hash, label, wait_hours, access_hours, token_hash, key_version, key_nonce,
    wrapped_workspace_key, key_aad_hash)
  values (p_id, v_workspace.tenant_id, p_workspace_id, p_kind, v_actor, p_recipient_email_hash,
    nullif(btrim(coalesce(p_label, '')), ''), p_wait_hours, coalesce(p_access_hours, 168), p_token_hash,
    p_key_version, p_key_nonce, p_wrapped_workspace_key, p_key_aad_hash);
  perform private.append_audit_event(v_workspace.tenant_id, v_actor, 'emergency_access.created',
    'emergency_access_grants', p_id, jsonb_build_object('kind', p_kind, 'workspace_id', p_workspace_id,
      'wait_hours', p_wait_hours, 'access_hours', coalesce(p_access_hours, 168)));
end
$$;

create or replace function private.accept_emergency_access(
  p_id uuid, p_token_hash bytea, p_secret_nonce bytea, p_wrapped_secret bytea
) returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
begin
  if v_actor is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_secret_nonce) <> 12 or octet_length(p_wrapped_secret) < 48 then
    raise exception 'invalid envelope' using errcode = '22023';
  end if;
  select * into v_grant from public.emergency_access_grants g
    where g.id = p_id and g.status = 'invited' and g.invite_expires_at > now()
      and g.recipient_email_hash = private.current_verified_email_hash()
      and g.token_hash = p_token_hash
    for update;
  if not found then raise exception 'this emergency access invitation is invalid or expired' using errcode = '28000'; end if;
  if v_grant.grantor_identity_id = v_actor then raise exception 'you cannot be your own emergency contact' using errcode = '22023'; end if;
  update public.emergency_access_grants set status = 'active', grantee_identity_id = v_actor,
    grantee_secret_nonce = p_secret_nonce, grantee_wrapped_secret = p_wrapped_secret,
    token_hash = extensions.digest(p_token_hash || uuid_send(p_id), 'sha256'), updated_at = now()
    where id = p_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor, 'emergency_access.accepted',
    'emergency_access_grants', p_id, jsonb_build_object('kind', v_grant.kind));
end
$$;

create or replace function private.request_emergency_access(p_id uuid)
returns timestamptz language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
begin
  select * into v_grant from public.emergency_access_grants g
    where g.id = p_id and g.grantee_identity_id = v_actor and g.status = 'active' for update;
  if not found then raise exception 'emergency access is not available' using errcode = '42501'; end if;
  update public.emergency_access_grants set status = 'requested', requested_at = now(), approved_at = null,
    decided_by = null, updated_at = now() where id = p_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor, 'emergency_access.requested',
    'emergency_access_grants', p_id, jsonb_build_object('kind', v_grant.kind, 'wait_hours', v_grant.wait_hours));
  return now() + make_interval(hours => v_grant.wait_hours);
end
$$;

-- Grantor (or, for break-glass, an organisation administrator) approves or denies a request.
create or replace function private.decide_emergency_access(p_id uuid, p_approve boolean)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
begin
  select * into v_grant from public.emergency_access_grants g where g.id = p_id and g.status = 'requested' for update;
  if not found or not (v_grant.grantor_identity_id = v_actor
    or (v_grant.kind = 'break_glass' and private.can_admin_workspace_access(v_grant.tenant_id)
        and v_actor is distinct from v_grant.grantee_identity_id)) then
    raise exception 'no pending request to decide' using errcode = '42501';
  end if;
  update public.emergency_access_grants set
    status = case when p_approve then 'approved' else 'active' end,
    approved_at = case when p_approve then now() else null end,
    requested_at = case when p_approve then requested_at else null end,
    decided_by = v_actor, updated_at = now()
    where id = p_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor,
    case when p_approve then 'emergency_access.approved' else 'emergency_access.denied' end,
    'emergency_access_grants', p_id, jsonb_build_object('kind', v_grant.kind));
end
$$;

create or replace function private.revoke_emergency_access(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
begin
  select * into v_grant from public.emergency_access_grants g where g.id = p_id for update;
  if not found or not (v_grant.grantor_identity_id = v_actor or v_grant.grantee_identity_id = v_actor
    or (v_grant.kind = 'break_glass' and private.can_admin_workspace_access(v_grant.tenant_id))) then
    raise exception 'emergency access not found' using errcode = '42501';
  end if;
  update public.emergency_access_grants set status = 'revoked', key_nonce = null, wrapped_workspace_key = null,
    grantee_secret_nonce = null, grantee_wrapped_secret = null, updated_at = now() where id = p_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor, 'emergency_access.revoked',
    'emergency_access_grants', p_id, jsonb_build_object('kind', v_grant.kind));
end
$$;

-- Releases the envelopes to the grantee once approved or once the wait has elapsed.
create or replace function private.claim_emergency_access(p_id uuid)
returns table (key_version integer, key_nonce bytea, wrapped_workspace_key bytea, key_aad_hash bytea,
  grantee_secret_nonce bytea, grantee_wrapped_secret bytea, tenant_id uuid, workspace_id uuid)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
begin
  if not private.session_mfa_satisfied() then raise exception 'two-step verification required' using errcode = '28000'; end if;
  select * into v_grant from public.emergency_access_grants g
    where g.id = p_id and g.grantee_identity_id = v_actor for update;
  if not found or not private.emergency_access_released(v_grant) then
    raise exception 'emergency access has not been released yet' using errcode = '42501';
  end if;
  if v_grant.key_version is distinct from (select w.current_key_version from public.workspaces w where w.id = v_grant.workspace_id) then
    raise exception 'the vault key changed after this grant was made; ask for a new grant' using errcode = '40001';
  end if;
  return query select v_grant.key_version, v_grant.key_nonce, v_grant.wrapped_workspace_key, v_grant.key_aad_hash,
    v_grant.grantee_secret_nonce, v_grant.grantee_wrapped_secret, v_grant.tenant_id, v_grant.workspace_id;
end
$$;

-- Grantee proves possession of the workspace key by storing it wrapped under their root key,
-- and joins the workspace as a time-limited viewer.
create or replace function private.activate_emergency_access(p_id uuid, p_root_key_nonce bytea, p_root_wrapped_workspace_key bytea)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_grant public.emergency_access_grants%rowtype;
  v_expires timestamptz;
  v_created_tenant boolean := false;
begin
  if not private.session_mfa_satisfied() then raise exception 'two-step verification required' using errcode = '28000'; end if;
  if octet_length(p_root_key_nonce) <> 12 or octet_length(p_root_wrapped_workspace_key) < 48 then
    raise exception 'invalid envelope' using errcode = '22023';
  end if;
  select * into v_grant from public.emergency_access_grants g
    where g.id = p_id and g.grantee_identity_id = v_actor for update;
  if not found or not private.emergency_access_released(v_grant) then
    raise exception 'emergency access has not been released yet' using errcode = '42501';
  end if;
  v_expires := now() + make_interval(hours => v_grant.access_hours);
  -- Temporary emergency viewers do not consume a paid seat.
  perform set_config('request.passkey_x_emergency_access', v_grant.tenant_id::text, true);
  if not exists (select 1 from public.tenant_memberships tm
      where tm.tenant_id = v_grant.tenant_id and tm.identity_id = v_actor and tm.status = 'active') then
    v_created_tenant := true;
    insert into public.tenant_memberships (tenant_id, identity_id, role, status)
      values (v_grant.tenant_id, v_actor, 'member', 'active')
      on conflict (tenant_id, identity_id) do update set status = 'active', role = 'member', updated_at = now();
  end if;
  insert into public.workspace_memberships (tenant_id, workspace_id, identity_id, role, status, expires_at)
    values (v_grant.tenant_id, v_grant.workspace_id, v_actor, 'viewer', 'active', v_expires)
    on conflict (workspace_id, identity_id) do update set role = 'viewer', status = 'active',
      expires_at = excluded.expires_at, updated_at = now()
      where public.workspace_memberships.status <> 'active';
  if not exists (select 1 from public.key_envelopes k where k.workspace_id = v_grant.workspace_id
      and k.recipient_identity_id = v_actor and k.key_kind = 'workspace' and k.revoked_at is null
      and k.key_version = v_grant.key_version) then
    insert into public.key_envelopes (tenant_id, workspace_id, key_kind, key_version, recipient_identity_id,
      algorithm, nonce, wrapped_key)
    values (v_grant.tenant_id, v_grant.workspace_id, 'workspace', v_grant.key_version, v_actor,
      'AES-256-GCM', p_root_key_nonce, p_root_wrapped_workspace_key);
  end if;
  perform set_config('request.passkey_x_emergency_access', '', true);
  update public.emergency_access_grants set status = 'used', used_at = now(), key_nonce = null,
    wrapped_workspace_key = null, created_tenant_membership = v_created_tenant, updated_at = now() where id = p_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor, 'emergency_access.activated',
    'emergency_access_grants', p_id, jsonb_build_object('kind', v_grant.kind, 'workspace_id', v_grant.workspace_id,
      'expires_at', v_expires));
  return jsonb_build_object('tenant_id', v_grant.tenant_id, 'workspace_id', v_grant.workspace_id, 'expires_at', v_expires);
end
$$;

-- Seat limit exemption for emergency viewers (the bypass is transaction-local and
-- set only inside activate_emergency_access).
create or replace function private.enforce_tenant_member_limit()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_limit integer;
  v_active integer;
begin
  if new.status <> 'active' then return new; end if;
  if current_setting('request.passkey_x_emergency_access', true) = new.tenant_id::text then return new; end if;
  select max_members into v_limit
  from public.tenant_entitlements
  where tenant_id = new.tenant_id;
  if v_limit is null then v_limit := 1; end if;
  select count(*) into v_active
  from public.tenant_memberships tm
  where tm.tenant_id = new.tenant_id
    and tm.status = 'active'
    and tm.identity_id <> new.identity_id
    and not exists (
      select 1 from public.emergency_access_grants g
      where g.tenant_id = tm.tenant_id and g.grantee_identity_id = tm.identity_id
        and g.status = 'used' and g.created_tenant_membership
    );
  if v_active >= v_limit then
    raise exception 'tenant member limit reached' using errcode = '23514';
  end if;
  return new;
end
$$;

-- After an emergency viewer's access ends, remove the organisation membership that
-- activation created (workspace access itself is expired by px-expire-workspace-memberships).
create or replace function private.expire_emergency_access()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_count integer;
begin
  with ended as (
    select g.id, g.tenant_id, g.grantee_identity_id from public.emergency_access_grants g
    where g.status = 'used' and g.created_tenant_membership
      and g.used_at + make_interval(hours => g.access_hours) < now()
      and not exists (select 1 from public.workspace_memberships wm
        where wm.tenant_id = g.tenant_id and wm.identity_id = g.grantee_identity_id and wm.status = 'active'
          and (wm.expires_at is null or wm.expires_at > now()))
  ), revoked as (
    update public.tenant_memberships tm set status = 'revoked', updated_at = now()
    from ended where tm.tenant_id = ended.tenant_id and tm.identity_id = ended.grantee_identity_id and tm.status = 'active'
    returning tm.tenant_id
  )
  update public.emergency_access_grants g set created_tenant_membership = false, updated_at = now()
  from ended where g.id = ended.id;
  get diagnostics v_count = row_count;
  return v_count;
end
$$;
revoke all on function private.expire_emergency_access() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Security alerts (organisations)
-- ---------------------------------------------------------------------------
create table if not exists public.security_alerts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  severity text not null check (severity in ('critical','high','medium','low')),
  kind text not null check (char_length(kind) between 3 and 60),
  title text not null check (char_length(title) <= 160),
  detail jsonb not null default '{}',
  actor_identity_id uuid references public.identities(id) on delete set null,
  source_sequence bigint,
  dedupe_key text not null,
  status text not null default 'open' check (status in ('open','acknowledged','resolved')),
  acknowledged_by uuid references public.identities(id) on delete set null,
  acknowledged_at timestamptz,
  note text check (note is null or char_length(note) <= 500),
  created_at timestamptz not null default now(),
  unique (tenant_id, dedupe_key)
);
create index if not exists security_alerts_tenant_idx on public.security_alerts (tenant_id, status, created_at desc);

alter table public.security_alerts enable row level security;
revoke all on public.security_alerts from anon, authenticated;
grant select on public.security_alerts to authenticated;
drop policy if exists security_alerts_read on public.security_alerts;
create policy security_alerts_read on public.security_alerts for select to authenticated
  using ((select private.can_read_organization_audit(tenant_id)));

create table if not exists private.security_alert_cursors (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  last_sequence bigint not null default 0
);
revoke all on private.security_alert_cursors from public, anon, authenticated;

create or replace function private.raise_security_alert(
  p_tenant uuid, p_severity text, p_kind text, p_title text, p_detail jsonb,
  p_actor uuid, p_sequence bigint, p_dedupe text
) returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_id uuid;
begin
  insert into public.security_alerts (tenant_id, severity, kind, title, detail, actor_identity_id, source_sequence, dedupe_key)
  values (p_tenant, p_severity, p_kind, p_title, coalesce(p_detail, '{}'::jsonb), p_actor, p_sequence, p_dedupe)
  on conflict (tenant_id, dedupe_key) do nothing
  returning id into v_id;
  if v_id is not null then
    perform private.append_audit_event(p_tenant, null, 'security_alert.raised', 'security_alerts', v_id,
      jsonb_build_object('severity', p_severity, 'kind', p_kind, 'title', p_title));
  end if;
end
$$;
revoke all on function private.raise_security_alert(uuid,text,text,text,jsonb,uuid,bigint,text) from public, anon, authenticated;

-- Scans new audit events per organisation and raises alerts. Runs every 5 minutes.
create or replace function private.detect_security_alerts()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_tenant record;
  v_event record;
  v_burst record;
  v_from bigint;
  v_to bigint;
  v_count integer := 0;
begin
  for v_tenant in select t.id from public.tenants t where t.kind = 'organization' loop
    select c.last_sequence into v_from from private.security_alert_cursors c where c.tenant_id = v_tenant.id;
    if v_from is null then
      -- Start from "now" for organisations seen for the first time.
      insert into private.security_alert_cursors (tenant_id, last_sequence)
      values (v_tenant.id, coalesce((select max(e.sequence) from public.audit_events e where e.tenant_id = v_tenant.id), 0));
      continue;
    end if;
    select max(e.sequence) into v_to from public.audit_events e where e.tenant_id = v_tenant.id and e.sequence > v_from;
    continue when v_to is null;

    for v_event in
      select e.sequence, e.action, e.actor_identity_id, e.target_id, e.metadata
      from public.audit_events e
      where e.tenant_id = v_tenant.id and e.sequence > v_from and e.sequence <= v_to
        and e.action not like 'security\_alert.%'
      order by e.sequence
    loop
      if v_event.action in ('emergency_access.requested','emergency_access.activated') then
        perform private.raise_security_alert(v_tenant.id, 'critical', v_event.action,
          case when v_event.action = 'emergency_access.requested' then 'Emergency access was requested'
               else 'Emergency access was used to open a vault' end,
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      elsif v_event.action = 'vault.exported' then
        perform private.raise_security_alert(v_tenant.id, 'high', 'vault.exported', 'A member exported vault data',
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      elsif v_event.action = 'organization_admin_assignments.insert'
         or (v_event.action = 'tenant_memberships.role_changed' and v_event.metadata ->> 'to' in ('owner','admin')) then
        perform private.raise_security_alert(v_tenant.id, 'high', 'admin.granted', 'Administrator privileges were granted',
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      elsif v_event.action like 'organization\_policies.%' then
        perform private.raise_security_alert(v_tenant.id, 'medium', 'policy.changed', 'A security policy was changed',
          v_event.metadata, v_event.actor_identity_id, v_event.sequence,
          'policy:' || coalesce(v_event.actor_identity_id::text, '-') || ':' || to_char(now(), 'YYYYMMDDHH24'));
        v_count := v_count + 1;
      elsif v_event.action in ('audit_webhook.deleted','audit_webhook.disabled') then
        perform private.raise_security_alert(v_tenant.id, 'high', 'audit_streaming.stopped', 'Audit streaming to a SIEM was stopped',
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      elsif v_event.action in ('scim_token.created') then
        perform private.raise_security_alert(v_tenant.id, 'medium', 'scim.token_created', 'A SCIM provisioning token was created',
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      elsif v_event.action in ('org_recovery.approved','org_recovery.key_set','sso.optional','scim.user_deactivated') then
        perform private.raise_security_alert(v_tenant.id,
          case when v_event.action in ('org_recovery.approved','org_recovery.key_set') then 'high' else 'medium' end,
          v_event.action,
          case v_event.action
            when 'org_recovery.approved' then 'An administrator approved an organization vault recovery'
            when 'org_recovery.key_set' then 'The organization recovery key was set or replaced'
            when 'sso.optional' then 'Single sign-on is no longer required'
            else 'A member was deprovisioned by your identity provider' end,
          v_event.metadata, v_event.actor_identity_id, v_event.sequence, 'event:' || v_event.sequence);
        v_count := v_count + 1;
      end if;
    end loop;

    -- Bursts in the last 15 minutes (deduplicated per actor per hour).
    for v_burst in
      select e.actor_identity_id, count(*) filter (where e.action in ('item.revealed','item.copied')) as secret_access,
        count(*) filter (where e.action = 'policy.blocked') as blocked
      from public.audit_events e
      where e.tenant_id = v_tenant.id and e.occurred_at > now() - interval '15 minutes' and e.actor_identity_id is not null
      group by e.actor_identity_id
    loop
      if v_burst.secret_access >= 40 then
        perform private.raise_security_alert(v_tenant.id, 'high', 'secrets.burst', 'Unusually many secrets revealed or copied',
          jsonb_build_object('count_15m', v_burst.secret_access), v_burst.actor_identity_id, null,
          'burst:secrets:' || v_burst.actor_identity_id || ':' || to_char(now(), 'YYYYMMDDHH24'));
        v_count := v_count + 1;
      end if;
      if v_burst.blocked >= 5 then
        perform private.raise_security_alert(v_tenant.id, 'medium', 'policy.blocked_repeatedly', 'A member was repeatedly blocked by policy',
          jsonb_build_object('count_15m', v_burst.blocked), v_burst.actor_identity_id, null,
          'burst:blocked:' || v_burst.actor_identity_id || ':' || to_char(now(), 'YYYYMMDDHH24'));
        v_count := v_count + 1;
      end if;
    end loop;

    update private.security_alert_cursors set last_sequence = v_to where tenant_id = v_tenant.id;
  end loop;

  -- Mass deletion: 25+ items moved to trash by one member within 15 minutes.
  for v_burst in
    select vi.tenant_id, count(*) as deleted
    from public.vault_items vi
    join public.tenants t on t.id = vi.tenant_id and t.kind = 'organization'
    where vi.deleted_at > now() - interval '15 minutes'
    group by vi.tenant_id
    having count(*) >= 25
  loop
    perform private.raise_security_alert(v_burst.tenant_id, 'high', 'items.mass_deleted', 'Many vault items were moved to trash',
      jsonb_build_object('count_15m', v_burst.deleted), null, null,
      'burst:deleted:' || v_burst.tenant_id || ':' || to_char(now(), 'YYYYMMDDHH24'));
    v_count := v_count + 1;
  end loop;
  return v_count;
end
$$;
revoke all on function private.detect_security_alerts() from public, anon, authenticated;

create or replace function private.update_security_alert(p_id uuid, p_status text, p_note text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_alert public.security_alerts%rowtype;
begin
  select * into v_alert from public.security_alerts a where a.id = p_id for update;
  if not found or not private.can_admin_workspace_access(v_alert.tenant_id) then
    raise exception 'alert not found' using errcode = '42501';
  end if;
  if p_status not in ('open','acknowledged','resolved') then raise exception 'invalid status' using errcode = '22023'; end if;
  update public.security_alerts set status = p_status,
    acknowledged_by = case when p_status = 'open' then null else private.current_identity_id() end,
    acknowledged_at = case when p_status = 'open' then null else now() end,
    note = coalesce(nullif(btrim(coalesce(p_note, '')), ''), note)
    where id = p_id;
  perform private.append_audit_event(v_alert.tenant_id, private.current_identity_id(), 'security_alert.' || p_status,
    'security_alerts', p_id, jsonb_build_object('kind', v_alert.kind));
end
$$;

-- ---------------------------------------------------------------------------
-- Compliance snapshots
-- ---------------------------------------------------------------------------
create table if not exists public.compliance_snapshots (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  period text not null check (period ~ '^[0-9]{4}-[0-9]{2}$'),
  snapshot jsonb not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, period)
);
alter table public.compliance_snapshots enable row level security;
revoke all on public.compliance_snapshots from anon, authenticated;
grant select on public.compliance_snapshots to authenticated;
drop policy if exists compliance_snapshots_read on public.compliance_snapshots;
create policy compliance_snapshots_read on public.compliance_snapshots for select to authenticated
  using ((select private.can_read_organization_audit(tenant_id)));

-- Aggregate, metadata-only posture of an organisation. No secrets, titles or URLs.
create or replace function private.compute_compliance_snapshot(p_tenant_id uuid)
returns jsonb language sql stable security definer set search_path = ''
as $$
  with members as (
    select tm.identity_id, tm.role, tm.status, i.auth_user_id
    from public.tenant_memberships tm join public.identities i on i.id = tm.identity_id
    where tm.tenant_id = p_tenant_id
  ), active as (select * from members where status = 'active'),
  mfa as (
    select count(distinct a.identity_id) as n from active a
    join auth.mfa_factors f on f.user_id = a.auth_user_id and f.status = 'verified'
  ), health as (
    select count(*) as reporters, round(avg(h.score))::integer as avg_score, sum(h.weak_count) as weak,
      sum(h.reused_count) as reused, sum(h.old_count) as old, sum(coalesce(h.breached_count, 0)) as breached,
      sum(h.passkey_count) as passkeys, sum(h.login_count) as logins
    from public.security_health_reports h join active a on a.identity_id = h.identity_id
    where h.tenant_id = p_tenant_id
  ), policies as (
    select coalesce(jsonb_agg(jsonb_build_object('type', p.policy_type, 'scope', p.scope_type,
      'configuration', p.configuration) order by p.policy_type), '[]'::jsonb) as list
    from public.organization_policies p where p.tenant_id = p_tenant_id and p.enforced
  ), activity as (
    select count(*) filter (where e.action like 'item.%') as secret_access,
      count(*) filter (where e.action = 'vault.exported') as exports,
      count(*) filter (where e.action like 'organization\_policies.%') as policy_changes,
      count(*) filter (where e.action like 'emergency\_access.%') as emergency_events,
      count(*) as total
    from public.audit_events e where e.tenant_id = p_tenant_id and e.occurred_at > now() - interval '30 days'
  ), alerts as (
    select count(*) filter (where a.status = 'open') as open,
      count(*) filter (where a.status = 'open' and a.severity in ('critical','high')) as open_high,
      count(*) filter (where a.created_at > now() - interval '30 days') as last_30d
    from public.security_alerts a where a.tenant_id = p_tenant_id
  ), temp_access as (
    select count(*) as n from public.workspace_memberships wm
    where wm.tenant_id = p_tenant_id and wm.status = 'active' and wm.expires_at is not null
  ), streaming as (
    select count(*) filter (where w.enabled) as enabled, max(w.last_success_at) as last_success
    from public.audit_webhooks w where w.tenant_id = p_tenant_id
  ), emergency as (
    select count(*) filter (where g.status not in ('revoked','used')) as active_grants,
      count(*) filter (where g.kind = 'break_glass' and g.status not in ('revoked','used')) as break_glass
    from public.emergency_access_grants g where g.tenant_id = p_tenant_id
  )
  select jsonb_build_object(
    'generated_at', now(),
    'members', jsonb_build_object('active', (select count(*) from active),
      'suspended', (select count(*) from members where status in ('suspended','revoked')),
      'owners_admins', (select count(*) from active where role in ('owner','admin')),
      'with_mfa', (select n from mfa)),
    'vault_health', (select to_jsonb(health) from health),
    'policies', (select list from policies),
    'activity_30d', (select to_jsonb(activity) from activity),
    'alerts', (select to_jsonb(alerts) from alerts),
    'temporary_access_members', (select n from temp_access),
    'audit_streaming', (select to_jsonb(streaming) from streaming),
    'emergency_access', (select to_jsonb(emergency) from emergency)
  )
$$;
revoke all on function private.compute_compliance_snapshot(uuid) from public, anon, authenticated;

create or replace function private.organization_compliance_snapshot(p_tenant_id uuid)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
begin
  if not (private.can_read_organization_audit(p_tenant_id)
    or private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin','auditor'])) then
    raise exception 'compliance report access denied' using errcode = '42501';
  end if;
  return private.compute_compliance_snapshot(p_tenant_id);
end
$$;

create or replace function private.store_monthly_compliance_snapshots()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_count integer;
begin
  insert into public.compliance_snapshots (tenant_id, period, snapshot)
  select t.id, to_char(now(), 'YYYY-MM'), private.compute_compliance_snapshot(t.id)
  from public.tenants t where t.kind = 'organization'
  on conflict (tenant_id, period) do update set snapshot = excluded.snapshot, created_at = now();
  get diagnostics v_count = row_count;
  return v_count;
end
$$;
revoke all on function private.store_monthly_compliance_snapshots() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Browser-callable wrappers (project convention) and grants
-- ---------------------------------------------------------------------------
create or replace function public.create_emergency_access(
  p_id uuid, p_workspace_id uuid, p_kind text, p_recipient_email_hash bytea, p_label text,
  p_wait_hours integer, p_access_hours integer, p_token_hash bytea,
  p_key_version integer, p_key_nonce bytea, p_wrapped_workspace_key bytea, p_key_aad_hash bytea
) returns void language sql volatile security invoker set search_path = ''
as $$ select private.create_emergency_access(p_id, p_workspace_id, p_kind, p_recipient_email_hash, p_label,
  p_wait_hours, p_access_hours, p_token_hash, p_key_version, p_key_nonce, p_wrapped_workspace_key, p_key_aad_hash) $$;
create or replace function public.accept_emergency_access(p_id uuid, p_token_hash bytea, p_secret_nonce bytea, p_wrapped_secret bytea)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.accept_emergency_access(p_id, p_token_hash, p_secret_nonce, p_wrapped_secret) $$;
create or replace function public.request_emergency_access(p_id uuid)
returns timestamptz language sql volatile security invoker set search_path = ''
as $$ select private.request_emergency_access(p_id) $$;
create or replace function public.decide_emergency_access(p_id uuid, p_approve boolean)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.decide_emergency_access(p_id, p_approve) $$;
create or replace function public.revoke_emergency_access(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.revoke_emergency_access(p_id) $$;
create or replace function public.claim_emergency_access(p_id uuid)
returns table (key_version integer, key_nonce bytea, wrapped_workspace_key bytea, key_aad_hash bytea,
  grantee_secret_nonce bytea, grantee_wrapped_secret bytea, tenant_id uuid, workspace_id uuid)
language sql volatile security invoker set search_path = ''
as $$ select * from private.claim_emergency_access(p_id) $$;
create or replace function public.activate_emergency_access(p_id uuid, p_root_key_nonce bytea, p_root_wrapped_workspace_key bytea)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.activate_emergency_access(p_id, p_root_key_nonce, p_root_wrapped_workspace_key) $$;
create or replace function public.update_security_alert(p_id uuid, p_status text, p_note text default null)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.update_security_alert(p_id, p_status, p_note) $$;
create or replace function public.organization_compliance_snapshot(p_tenant_id uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select private.organization_compliance_snapshot(p_tenant_id) $$;

do $$
declare v_sig text;
begin
  foreach v_sig in array array[
    'create_emergency_access(uuid,uuid,text,bytea,text,integer,integer,bytea,integer,bytea,bytea,bytea)',
    'accept_emergency_access(uuid,bytea,bytea,bytea)',
    'request_emergency_access(uuid)',
    'decide_emergency_access(uuid,boolean)',
    'revoke_emergency_access(uuid)',
    'claim_emergency_access(uuid)',
    'activate_emergency_access(uuid,bytea,bytea)',
    'update_security_alert(uuid,text,text)',
    'organization_compliance_snapshot(uuid)'
  ] loop
    execute format('revoke all on function private.%s from public, anon', v_sig);
    execute format('grant execute on function private.%s to authenticated', v_sig);
    execute format('revoke all on function public.%s from public, anon', v_sig);
    execute format('grant execute on function public.%s to authenticated', v_sig);
  end loop;
end
$$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('px-detect-security-alerts', '*/5 * * * *', $cron$select private.detect_security_alerts()$cron$);
    perform cron.schedule('px-expire-emergency-access', '*/15 * * * *', $cron$select private.expire_emergency_access()$cron$);
    perform cron.schedule('px-monthly-compliance-snapshots', '15 2 1 * *', $cron$select private.store_monthly_compliance_snapshots()$cron$);
  end if;
end
$$;

comment on table public.emergency_access_grants is
  'Zero-knowledge emergency access. Key material is released only after approval or the waiting period; never selectable directly.';
comment on table public.security_alerts is 'Risky-event alerts derived from the organisation audit log (metadata only).';
comment on table public.compliance_snapshots is 'Monthly aggregate compliance posture per organisation (metadata only).';
