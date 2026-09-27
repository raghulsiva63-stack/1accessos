-- Passkey-X enterprise web v3 — enforceable organisation policies, zero-knowledge
-- security health reporting and the admin security overview.

-- ---------------------------------------------------------------------------
-- Policy catalogue
-- ---------------------------------------------------------------------------
alter table public.organization_policies drop constraint if exists organization_policies_policy_type_check;
alter table public.organization_policies add constraint organization_policies_policy_type_check
  check (policy_type in (
    'passkey_required','device_approval_required','minimum_vault_password',
    'sharing_mode','session_timeout_minutes','export_policy',
    'mfa_required','clipboard_clear_seconds','breach_monitoring','organization_recovery'
  ));

create or replace function private.valid_policy_configuration(p_type text, p_config jsonb)
returns boolean language plpgsql immutable set search_path = ''
as $$
begin
  if jsonb_typeof(p_config) <> 'object' then return false; end if;
  case p_type
    when 'passkey_required','device_approval_required','mfa_required' then
      return jsonb_typeof(p_config -> 'required') = 'boolean';
    when 'organization_recovery' then
      return jsonb_typeof(p_config -> 'enabled') = 'boolean';
    when 'minimum_vault_password' then
      return jsonb_typeof(p_config -> 'min_length') = 'number'
        and (p_config ->> 'min_length')::numeric between 12 and 128
        and (p_config -> 'min_strength' is null or (
          jsonb_typeof(p_config -> 'min_strength') = 'number'
          and (p_config ->> 'min_strength')::numeric between 0 and 4));
    when 'session_timeout_minutes' then
      return jsonb_typeof(p_config -> 'minutes') = 'number'
        and (p_config ->> 'minutes')::numeric between 1 and 480;
    when 'clipboard_clear_seconds' then
      return jsonb_typeof(p_config -> 'seconds') = 'number'
        and (p_config ->> 'seconds')::numeric between 5 and 300;
    when 'sharing_mode' then
      return p_config ->> 'mode' in ('open','internal_only','disabled');
    when 'export_policy' then
      return p_config ->> 'mode' in ('allowed','admins_only','blocked');
    when 'breach_monitoring' then
      return p_config ->> 'mode' in ('off','optional','required');
    else
      return false;
  end case;
end
$$;
revoke all on function private.valid_policy_configuration(text,jsonb) from public, anon;
grant execute on function private.valid_policy_configuration(text,jsonb) to authenticated;

create or replace function private.validate_organization_policy()
returns trigger language plpgsql set search_path = ''
as $$
begin
  if not private.valid_policy_configuration(new.policy_type, new.configuration) then
    raise exception 'invalid configuration for policy %', new.policy_type using errcode = '22023';
  end if;
  return new;
end
$$;
revoke all on function private.validate_organization_policy() from public, anon, authenticated;

drop trigger if exists organization_policies_validate on public.organization_policies;
create trigger organization_policies_validate before insert or update on public.organization_policies
  for each row execute function private.validate_organization_policy();

-- Tenant-level effective value of one policy for the current caller.
create or replace function private.tenant_policy_configuration(p_tenant uuid, p_type text)
returns jsonb language sql stable security definer set search_path = ''
as $$
  select p.configuration from public.organization_policies p
  where p.tenant_id = p_tenant and p.policy_type = p_type and p.enforced
    and p.scope_type = 'tenant'
  order by p.priority desc, p.version desc
  limit 1
$$;
revoke all on function private.tenant_policy_configuration(uuid,text) from public, anon, authenticated;

-- Self-service effective policies (merged across tenant/department/team scope).
create or replace function private.my_organization_policies(p_tenant_id uuid)
returns table (policy_type text, configuration jsonb, source_scope_type text, version integer)
language plpgsql stable security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not exists (
    select 1 from public.tenant_memberships tm
    where tm.tenant_id = p_tenant_id and tm.identity_id = v_actor and tm.status = 'active'
  ) then
    raise exception 'tenant membership required' using errcode = '42501';
  end if;
  return query
  with recursive profile_scope as (
    select profile.department_id from public.organization_profiles profile
    where profile.tenant_id = p_tenant_id and profile.identity_id = v_actor
  ), department_ancestors(id,parent_department_id,depth) as (
    select d.id,d.parent_department_id,1 from public.organization_departments d
    join profile_scope s on s.department_id = d.id where d.tenant_id = p_tenant_id
    union all
    select parent.id,parent.parent_department_id,child.depth + 1 from public.organization_departments parent
    join department_ancestors child on child.parent_department_id = parent.id
    where parent.tenant_id = p_tenant_id and child.depth < 32
  ), teams as (
    select m.team_id from public.organization_team_memberships m
    where m.tenant_id = p_tenant_id and m.identity_id = v_actor and m.status = 'active'
  ), candidates as (
    select p.policy_type, p.configuration, p.scope_type, p.version,
      case p.scope_type when 'team' then 3 when 'department' then 2 else 1 end as specificity,
      p.priority
    from public.organization_policies p
    where p.tenant_id = p_tenant_id and p.enforced and (
      p.scope_type = 'tenant'
      or (p.scope_type = 'department' and p.scope_id in (select id from department_ancestors))
      or (p.scope_type = 'team' and p.scope_id in (select team_id from teams))
    )
  )
  select distinct on (c.policy_type) c.policy_type, c.configuration, c.scope_type, c.version
  from candidates c
  order by c.policy_type, c.specificity desc, c.priority desc, c.version desc;
end
$$;
revoke all on function private.my_organization_policies(uuid) from public, anon;
grant execute on function private.my_organization_policies(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Server-side sharing enforcement
-- ---------------------------------------------------------------------------
create or replace function private.enforce_sharing_policy()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_mode text := coalesce(private.tenant_policy_configuration(new.tenant_id,'sharing_mode') ->> 'mode','open');
begin
  if v_mode = 'open' then return new; end if;
  if v_mode = 'disabled' and not private.has_tenant_role(new.tenant_id,array['owner','admin']) then
    raise exception 'sharing is disabled by organization policy' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.tenant_memberships tm
    join public.identities i on i.id = tm.identity_id
    join auth.users u on u.id = i.auth_user_id
    where tm.tenant_id = new.tenant_id and tm.status = 'active'
      and extensions.digest(convert_to(lower(trim(u.email)),'UTF8'),'sha256') = new.recipient_email_hash
  ) then
    raise exception 'organization policy only allows sharing with organization members' using errcode = '42501';
  end if;
  return new;
end
$$;
revoke all on function private.enforce_sharing_policy() from public, anon, authenticated;

drop trigger if exists access_capsules_sharing_policy on public.access_capsules;
create trigger access_capsules_sharing_policy before insert on public.access_capsules
  for each row execute function private.enforce_sharing_policy();
drop trigger if exists workspace_invites_sharing_policy on public.workspace_invites;
create trigger workspace_invites_sharing_policy before insert on public.workspace_invites
  for each row execute function private.enforce_sharing_policy();

-- ---------------------------------------------------------------------------
-- Zero-knowledge security health (aggregate counts only, computed on device)
-- ---------------------------------------------------------------------------
create table if not exists public.security_health_reports (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  score smallint not null check (score between 0 and 100),
  item_count integer not null default 0 check (item_count between 0 and 1000000),
  login_count integer not null default 0 check (login_count between 0 and 1000000),
  weak_count integer not null default 0 check (weak_count between 0 and 1000000),
  reused_count integer not null default 0 check (reused_count between 0 and 1000000),
  old_count integer not null default 0 check (old_count between 0 and 1000000),
  breached_count integer check (breached_count is null or breached_count between 0 and 1000000),
  missing_totp_count integer not null default 0 check (missing_totp_count between 0 and 1000000),
  passkey_count integer not null default 0 check (passkey_count between 0 and 1000000),
  breach_check_at timestamptz,
  client_kind text not null default 'web' check (client_kind in ('web','desktop','mobile','android','extension')),
  reported_at timestamptz not null default now(),
  primary key (tenant_id, identity_id)
);
create index if not exists security_health_reports_identity_idx on public.security_health_reports(identity_id);

alter table public.security_health_reports enable row level security;
revoke all on public.security_health_reports from anon, authenticated;
grant select on public.security_health_reports to authenticated;

drop policy if exists security_health_reports_read on public.security_health_reports;
create policy security_health_reports_read on public.security_health_reports for select to authenticated
using (
  identity_id = (select private.current_identity_id())
  or (select private.can_read_organization_audit(tenant_id))
  or (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin','auditor']))
);

create or replace function private.report_security_health(
  p_tenant_id uuid, p_score integer, p_item_count integer, p_login_count integer,
  p_weak_count integer, p_reused_count integer, p_old_count integer,
  p_breached_count integer, p_missing_totp_count integer, p_passkey_count integer,
  p_client_kind text default 'web'
) returns void language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not exists (
    select 1 from public.tenant_memberships tm
    where tm.tenant_id = p_tenant_id and tm.identity_id = v_actor and tm.status = 'active'
  ) then
    raise exception 'tenant membership required' using errcode = '42501';
  end if;
  insert into public.security_health_reports as r (tenant_id,identity_id,score,item_count,login_count,
    weak_count,reused_count,old_count,breached_count,missing_totp_count,passkey_count,
    breach_check_at,client_kind,reported_at)
  values (p_tenant_id,v_actor,p_score,p_item_count,p_login_count,p_weak_count,p_reused_count,
    p_old_count,p_breached_count,p_missing_totp_count,p_passkey_count,
    case when p_breached_count is null then null else now() end,
    coalesce(p_client_kind,'web'),now())
  on conflict (tenant_id,identity_id) do update set
    score = excluded.score, item_count = excluded.item_count, login_count = excluded.login_count,
    weak_count = excluded.weak_count, reused_count = excluded.reused_count,
    old_count = excluded.old_count,
    breached_count = coalesce(excluded.breached_count, r.breached_count),
    breach_check_at = coalesce(excluded.breach_check_at, r.breach_check_at),
    missing_totp_count = excluded.missing_totp_count, passkey_count = excluded.passkey_count,
    client_kind = excluded.client_kind, reported_at = now();
end
$$;
revoke all on function private.report_security_health(uuid,integer,integer,integer,integer,integer,integer,integer,integer,integer,text) from public, anon;
grant execute on function private.report_security_health(uuid,integer,integer,integer,integer,integer,integer,integer,integer,integer,text) to authenticated;

-- ---------------------------------------------------------------------------
-- Admin overview: one row per organisation member
-- ---------------------------------------------------------------------------
create or replace function private.organization_member_overview(p_tenant_id uuid)
returns table (
  identity_id uuid, email text, display_name text, job_title text, department_id uuid,
  tenant_role text, membership_status text, lifecycle_status text, admin_roles text[],
  mfa_factors integer, last_sign_in_at timestamptz, joined_at timestamptz,
  health_score smallint, weak_count integer, reused_count integer, old_count integer,
  breached_count integer, login_count integer, passkey_count integer, health_reported_at timestamptz,
  trusted_devices integer
) language plpgsql stable security definer set search_path = ''
as $$
begin
  if not (private.can_read_organization_audit(p_tenant_id)
    or private.can_manage_organization(p_tenant_id,array['organization_admin','security_admin','helpdesk_admin','auditor'])) then
    raise exception 'organization overview access denied' using errcode = '42501';
  end if;
  return query
  select tm.identity_id, u.email::text, coalesce(p.display_name, split_part(u.email::text,'@',1)),
    p.job_title, p.department_id, tm.role, tm.status, coalesce(p.lifecycle_status, tm.status),
    coalesce((select array_agg(distinct a.role order by a.role) from public.organization_admin_assignments a
      where a.tenant_id = tm.tenant_id and a.identity_id = tm.identity_id and a.status = 'active'), '{}'::text[]),
    (select count(*)::integer from auth.mfa_factors f where f.user_id = u.id and f.status = 'verified'),
    u.last_sign_in_at, tm.created_at,
    h.score, h.weak_count, h.reused_count, h.old_count, h.breached_count, h.login_count,
    h.passkey_count, h.reported_at,
    (select count(*)::integer from public.devices d where d.identity_id = tm.identity_id and d.status = 'trusted')
  from public.tenant_memberships tm
  join public.identities i on i.id = tm.identity_id
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles p on p.tenant_id = tm.tenant_id and p.identity_id = tm.identity_id
  left join public.security_health_reports h on h.tenant_id = tm.tenant_id and h.identity_id = tm.identity_id
  where tm.tenant_id = p_tenant_id
  order by coalesce(p.display_name, u.email::text);
end
$$;
revoke all on function private.organization_member_overview(uuid) from public, anon;
grant execute on function private.organization_member_overview(uuid) to authenticated;

-- Change a member's tenant role (owner/admin only; owners cannot be demoted by admins
-- and the last owner can never be removed).
create or replace function private.set_organization_member_role(
  p_tenant_id uuid, p_identity_id uuid, p_role text
) returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_current text;
begin
  if p_role not in ('owner','admin','member','auditor') then
    raise exception 'unsupported role' using errcode = '22023';
  end if;
  if not private.has_tenant_role(p_tenant_id,array['owner','admin']) then
    raise exception 'organization role change denied' using errcode = '42501';
  end if;
  select role into v_current from public.tenant_memberships
    where tenant_id = p_tenant_id and identity_id = p_identity_id for update;
  if v_current is null then raise exception 'member not found' using errcode = 'P0002'; end if;
  if (v_current = 'owner' or p_role = 'owner') and not private.has_tenant_role(p_tenant_id,array['owner']) then
    raise exception 'only owners can grant or remove the owner role' using errcode = '42501';
  end if;
  if v_current = 'owner' and p_role <> 'owner' and (
    select count(*) from public.tenant_memberships
    where tenant_id = p_tenant_id and role = 'owner' and status = 'active'
  ) <= 1 then
    raise exception 'an organization needs at least one owner' using errcode = '23514';
  end if;
  update public.tenant_memberships set role = p_role, updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
  perform private.append_audit_event(p_tenant_id, v_actor, 'tenant_memberships.role_changed',
    'tenant_memberships', p_identity_id, jsonb_build_object('from', v_current, 'to', p_role));
end
$$;
revoke all on function private.set_organization_member_role(uuid,uuid,text) from public, anon;
grant execute on function private.set_organization_member_role(uuid,uuid,text) to authenticated;

comment on table public.security_health_reports is
  'Aggregate, device-computed vault health counts. Never contains secrets, titles, URLs or usernames.';

-- ---------------------------------------------------------------------------
-- Vault password change while unlocked. The client proves it could unwrap the
-- account root locally; the server only accepts a replacement for the exact
-- wrap it currently stores (optimistic concurrency) and a strong KDF profile.
-- The recovery wrap is untouched, so a mistaken change is always recoverable.
-- ---------------------------------------------------------------------------
create or replace function private.rotate_master_with_session(
  p_expected_master_nonce bytea,
  p_salt bytea,
  p_kdf_parameters jsonb,
  p_master_nonce bytea,
  p_master_wrapped_root bytea
) returns void language plpgsql security definer set search_path = ''
as $$
declare v_identity uuid := private.current_identity_id();
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  if coalesce((auth.jwt() ->> 'iat')::bigint, 0) < extract(epoch from now())::bigint - 43200 then
    raise exception 'sign in again before changing the vault password' using errcode = '28000';
  end if;
  if octet_length(p_salt) <> 16 or octet_length(p_master_nonce) <> 12
     or octet_length(p_master_wrapped_root) < 48 or octet_length(p_expected_master_nonce) <> 12 then
    raise exception 'invalid cryptographic parameter length' using errcode = '22023';
  end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID'
     or (p_kdf_parameters ->> 'memoryKib')::integer not between 65536 and 1048576
     or (p_kdf_parameters ->> 'iterations')::integer not between 3 and 12
     or (p_kdf_parameters ->> 'parallelism')::integer not between 1 and 4
     or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then
    raise exception 'invalid KDF profile' using errcode = '22023';
  end if;
  update public.account_crypto_profiles
    set salt = p_salt, kdf_parameters = p_kdf_parameters, master_nonce = p_master_nonce,
        master_wrapped_root = p_master_wrapped_root, updated_at = now()
    where identity_id = v_identity and master_nonce = p_expected_master_nonce;
  if not found then
    raise exception 'vault password changed on another device; unlock again' using errcode = '40001';
  end if;
  perform private.append_audit_event(tm.tenant_id, v_identity, 'vault.password_changed', 'identities', v_identity, '{}'::jsonb)
    from public.tenant_memberships tm
    join public.tenants t on t.id = tm.tenant_id and t.kind = 'organization'
    where tm.identity_id = v_identity and tm.status = 'active';
end
$$;
revoke all on function private.rotate_master_with_session(bytea,bytea,jsonb,bytea,bytea) from public, anon;
grant execute on function private.rotate_master_with_session(bytea,bytea,jsonb,bytea,bytea) to authenticated;

-- Browser-callable SECURITY INVOKER wrappers (implementations live in private).
create or replace function public.my_organization_policies(p_tenant_id uuid)
returns table (policy_type text, configuration jsonb, source_scope_type text, version integer)
language sql stable security invoker set search_path = ''
as $$ select * from private.my_organization_policies(p_tenant_id) $$;

create or replace function public.report_security_health(
  p_tenant_id uuid, p_score integer, p_item_count integer, p_login_count integer,
  p_weak_count integer, p_reused_count integer, p_old_count integer,
  p_breached_count integer, p_missing_totp_count integer, p_passkey_count integer,
  p_client_kind text default 'web'
) returns void language sql volatile security invoker set search_path = ''
as $$ select private.report_security_health(p_tenant_id, p_score, p_item_count, p_login_count,
  p_weak_count, p_reused_count, p_old_count, p_breached_count, p_missing_totp_count,
  p_passkey_count, p_client_kind) $$;

create or replace function public.organization_member_overview(p_tenant_id uuid)
returns table (
  identity_id uuid, email text, display_name text, job_title text, department_id uuid,
  tenant_role text, membership_status text, lifecycle_status text, admin_roles text[],
  mfa_factors integer, last_sign_in_at timestamptz, joined_at timestamptz,
  health_score smallint, weak_count integer, reused_count integer, old_count integer,
  breached_count integer, login_count integer, passkey_count integer, health_reported_at timestamptz,
  trusted_devices integer
) language sql stable security invoker set search_path = ''
as $$ select * from private.organization_member_overview(p_tenant_id) $$;

create or replace function public.set_organization_member_role(p_tenant_id uuid, p_identity_id uuid, p_role text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_organization_member_role(p_tenant_id, p_identity_id, p_role) $$;

create or replace function public.rotate_master_with_session(
  p_expected_master_nonce bytea, p_salt bytea, p_kdf_parameters jsonb,
  p_master_nonce bytea, p_master_wrapped_root bytea
) returns void language sql volatile security invoker set search_path = ''
as $$ select private.rotate_master_with_session(p_expected_master_nonce, p_salt, p_kdf_parameters,
  p_master_nonce, p_master_wrapped_root) $$;

revoke all on function public.my_organization_policies(uuid) from public, anon;
revoke all on function public.report_security_health(uuid,integer,integer,integer,integer,integer,integer,integer,integer,integer,text) from public, anon;
revoke all on function public.organization_member_overview(uuid) from public, anon;
revoke all on function public.set_organization_member_role(uuid,uuid,text) from public, anon;
revoke all on function public.rotate_master_with_session(bytea,bytea,jsonb,bytea,bytea) from public, anon;
grant execute on function public.my_organization_policies(uuid) to authenticated;
grant execute on function public.report_security_health(uuid,integer,integer,integer,integer,integer,integer,integer,integer,integer,text) to authenticated;
grant execute on function public.organization_member_overview(uuid) to authenticated;
grant execute on function public.set_organization_member_role(uuid,uuid,text) to authenticated;
grant execute on function public.rotate_master_with_session(bytea,bytea,jsonb,bytea,bytea) to authenticated;
