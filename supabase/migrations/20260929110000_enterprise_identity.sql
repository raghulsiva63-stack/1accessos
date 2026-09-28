-- Passkey-X enterprise identity:
--   * SCIM 2.0 provisioning (tokens, pre-provisioned users, deprovisioning)
--   * SAML SSO connection management with DNS domain verification
--   * Opt-in organisation recovery (zero-knowledge escrow to an offline org key)

-- ---------------------------------------------------------------------------
-- SCIM provisioning
-- ---------------------------------------------------------------------------
create table if not exists public.scim_tokens (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 80),
  token_hash bytea not null unique check (octet_length(token_hash) = 32),
  token_hint text not null,
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index if not exists scim_tokens_tenant_idx on public.scim_tokens (tenant_id);
alter table public.scim_tokens enable row level security;
revoke all on public.scim_tokens from anon, authenticated;
grant select (id, tenant_id, name, token_hint, created_by, created_at, last_used_at, revoked_at) on public.scim_tokens to authenticated;
drop policy if exists scim_tokens_read on public.scim_tokens;
create policy scim_tokens_read on public.scim_tokens for select to authenticated
  using ((select private.can_manage_audit_webhooks(tenant_id)));

create table if not exists public.scim_provisioned_users (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  external_id text check (external_id is null or char_length(external_id) <= 255),
  user_name text not null check (char_length(user_name) between 3 and 320),
  email_hash bytea not null check (octet_length(email_hash) = 32),
  display_name text not null check (char_length(btrim(display_name)) between 1 and 120),
  job_title text check (job_title is null or char_length(job_title) <= 120),
  active boolean not null default true,
  identity_id uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, email_hash),
  unique (tenant_id, external_id)
);
create index if not exists scim_users_email_idx on public.scim_provisioned_users (email_hash) where identity_id is null;
alter table public.scim_provisioned_users enable row level security;
revoke all on public.scim_provisioned_users from anon, authenticated;
grant select (id, tenant_id, external_id, user_name, display_name, job_title, active, identity_id, created_at, updated_at)
  on public.scim_provisioned_users to authenticated;
drop policy if exists scim_users_read on public.scim_provisioned_users;
create policy scim_users_read on public.scim_provisioned_users for select to authenticated
using (
  (select private.can_read_organization_audit(tenant_id))
  or (select private.can_manage_organization(tenant_id, array['organization_admin','helpdesk_admin']))
  or email_hash = (select private.current_verified_email_hash())
);

create or replace function private.create_scim_token(p_tenant_id uuid, p_name text)
returns table (id uuid, token text)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_token text := 'pxscim_' || encode(extensions.gen_random_bytes(32), 'hex');
  v_id uuid;
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then
    raise exception 'provisioning management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = p_tenant_id) is distinct from 'organization' then
    raise exception 'provisioning requires an organization' using errcode = '22023';
  end if;
  if not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement required' using errcode = '23514';
  end if;
  if (select count(*) from public.scim_tokens s where s.tenant_id = p_tenant_id and s.revoked_at is null) >= 3 then
    raise exception 'an organization can have at most 3 active provisioning tokens' using errcode = 'P0001';
  end if;
  insert into public.scim_tokens (tenant_id, name, token_hash, token_hint, created_by)
  values (p_tenant_id, btrim(p_name), extensions.digest(v_token, 'sha256'), right(v_token, 4), private.current_identity_id())
  returning scim_tokens.id into v_id;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'scim_token.created', 'scim_tokens', v_id,
    jsonb_build_object('name', btrim(p_name)));
  return query select v_id, v_token;
end
$$;

create or replace function private.revoke_scim_token(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.scim_tokens%rowtype;
begin
  select * into v_row from public.scim_tokens s where s.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_row.tenant_id) then
    raise exception 'token not found' using errcode = '42501';
  end if;
  update public.scim_tokens set revoked_at = coalesce(revoked_at, now()) where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, private.current_identity_id(), 'scim_token.revoked', 'scim_tokens', p_id, '{}'::jsonb);
end
$$;

-- Service role: resolves a bearer token to its organisation.
create or replace function private.scim_tenant_for_token(p_token text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_tenant uuid;
begin
  update public.scim_tokens s set last_used_at = now()
    where s.token_hash = extensions.digest(p_token, 'sha256') and s.revoked_at is null
    returning s.tenant_id into v_tenant;
  return v_tenant;
end
$$;

-- Deactivates a provisioned member: suspends the organisation membership, removes
-- workspace access and key envelopes, and flags affected workspaces for key rotation.
create or replace function private.scim_offboard_identity(p_tenant_id uuid, p_identity_id uuid, p_reason text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_role text;
begin
  select tm.role into v_role from public.tenant_memberships tm where tm.tenant_id = p_tenant_id and tm.identity_id = p_identity_id;
  if v_role is null then return; end if;
  if v_role = 'owner' then
    raise exception 'organization owners cannot be deprovisioned through SCIM' using errcode = '42501';
  end if;
  update public.workspaces w set key_rotation_required = true, updated_at = now()
    where w.tenant_id = p_tenant_id and exists (select 1 from public.workspace_memberships wm
      where wm.workspace_id = w.id and wm.identity_id = p_identity_id and wm.status = 'active');
  update public.workspace_memberships set status = 'revoked', updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id and status = 'active';
  update public.key_envelopes set revoked_at = now()
    where tenant_id = p_tenant_id and recipient_identity_id = p_identity_id and revoked_at is null;
  update public.tenant_memberships set status = 'suspended', updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id and status = 'active';
  update public.organization_profiles set lifecycle_status = 'suspended', updated_at = now()
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
  perform private.append_audit_event(p_tenant_id, null, 'scim.user_deactivated', 'identities', p_identity_id,
    jsonb_build_object('reason', p_reason));
end
$$;

create or replace function private.scim_upsert_user(
  p_tenant_id uuid, p_id uuid, p_external_id text, p_user_name text, p_display_name text, p_job_title text, p_active boolean
) returns public.scim_provisioned_users
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_row public.scim_provisioned_users%rowtype;
  v_email text := lower(btrim(p_user_name));
  v_was_active boolean;
begin
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'userName must be an email address' using errcode = '22023';
  end if;
  if p_id is not null then
    select * into v_row from public.scim_provisioned_users u where u.id = p_id and u.tenant_id = p_tenant_id for update;
    if not found then raise exception 'user not found' using errcode = 'P0002'; end if;
    v_was_active := v_row.active;
    update public.scim_provisioned_users set external_id = coalesce(p_external_id, external_id), user_name = v_email,
      email_hash = extensions.digest(convert_to(v_email, 'UTF8'), 'sha256'),
      display_name = coalesce(nullif(btrim(coalesce(p_display_name, '')), ''), display_name),
      job_title = coalesce(p_job_title, job_title), active = coalesce(p_active, active), updated_at = now()
      where id = p_id returning * into v_row;
  else
    insert into public.scim_provisioned_users (tenant_id, external_id, user_name, email_hash, display_name, job_title, active)
    values (p_tenant_id, p_external_id, v_email, extensions.digest(convert_to(v_email, 'UTF8'), 'sha256'),
      coalesce(nullif(btrim(coalesce(p_display_name, '')), ''), split_part(v_email, '@', 1)), p_job_title, coalesce(p_active, true))
    returning * into v_row;
    v_was_active := v_row.active;
    perform private.append_audit_event(p_tenant_id, null, 'scim.user_provisioned', 'scim_provisioned_users', v_row.id,
      jsonb_build_object('external_id', p_external_id));
  end if;
  if v_row.identity_id is not null then
    update public.organization_profiles set display_name = v_row.display_name, job_title = v_row.job_title, updated_at = now()
      where tenant_id = p_tenant_id and identity_id = v_row.identity_id;
    if v_was_active and not v_row.active then
      perform private.scim_offboard_identity(p_tenant_id, v_row.identity_id, 'deactivated');
    elsif not v_was_active and v_row.active then
      -- Membership returns; vault access must be re-shared by people who hold the keys.
      update public.tenant_memberships set status = 'active', updated_at = now()
        where tenant_id = p_tenant_id and identity_id = v_row.identity_id and status = 'suspended';
      update public.organization_profiles set lifecycle_status = 'active', updated_at = now()
        where tenant_id = p_tenant_id and identity_id = v_row.identity_id;
      perform private.append_audit_event(p_tenant_id, null, 'scim.user_reactivated', 'identities', v_row.identity_id, '{}'::jsonb);
    end if;
  end if;
  return v_row;
end
$$;

create or replace function private.scim_delete_user(p_tenant_id uuid, p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.scim_provisioned_users%rowtype;
begin
  select * into v_row from public.scim_provisioned_users u where u.id = p_id and u.tenant_id = p_tenant_id for update;
  if not found then return false; end if;
  if v_row.identity_id is not null then
    perform private.scim_offboard_identity(p_tenant_id, v_row.identity_id, 'deleted');
    update public.organization_profiles set lifecycle_status = 'deprovisioned', updated_at = now()
      where tenant_id = p_tenant_id and identity_id = v_row.identity_id;
  end if;
  delete from public.scim_provisioned_users where id = p_id;
  perform private.append_audit_event(p_tenant_id, null, 'scim.user_deleted', 'scim_provisioned_users', p_id, '{}'::jsonb);
  return true;
end
$$;

create or replace function private.scim_list_users(p_tenant_id uuid, p_user_name text, p_external_id text, p_offset integer, p_limit integer)
returns table (total bigint, users jsonb)
language sql stable security definer set search_path = ''
as $$
  with matched as (
    select u.* from public.scim_provisioned_users u
    where u.tenant_id = p_tenant_id
      and (p_user_name is null or u.user_name = lower(btrim(p_user_name)))
      and (p_external_id is null or u.external_id = p_external_id)
  )
  select (select count(*) from matched),
    coalesce((select jsonb_agg(to_jsonb(page) order by page.created_at) from (
      select m.id, m.external_id, m.user_name, m.display_name, m.job_title, m.active, m.identity_id, m.created_at, m.updated_at
      from matched m order by m.created_at offset greatest(p_offset, 0) limit least(greatest(p_limit, 0), 200)) page), '[]'::jsonb)
$$;

-- Member side: organisations that have provisioned the signed-in email.
create or replace function private.claim_provisioned_membership(p_id uuid)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_row public.scim_provisioned_users%rowtype;
begin
  select * into v_row from public.scim_provisioned_users u
    where u.id = p_id and u.active and u.identity_id is null
      and u.email_hash = private.current_verified_email_hash()
    for update;
  if not found or v_actor is null then raise exception 'no pending organization account' using errcode = '42501'; end if;
  insert into public.tenant_memberships (tenant_id, identity_id, role, status)
    values (v_row.tenant_id, v_actor, 'member', 'active')
    on conflict (tenant_id, identity_id) do update set status = 'active', updated_at = now();
  insert into public.organization_profiles (tenant_id, identity_id, display_name, job_title, lifecycle_status)
    values (v_row.tenant_id, v_actor, v_row.display_name, v_row.job_title, 'active')
    on conflict (tenant_id, identity_id) do update set display_name = excluded.display_name,
      job_title = excluded.job_title, lifecycle_status = 'active', updated_at = now();
  update public.scim_provisioned_users set identity_id = v_actor, updated_at = now() where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, v_actor, 'scim.user_joined', 'identities', v_actor, '{}'::jsonb);
  return v_row.tenant_id;
end
$$;

-- ---------------------------------------------------------------------------
-- SAML SSO connections
-- ---------------------------------------------------------------------------
create table if not exists public.sso_connections (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  domain text not null unique check (domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'),
  verification_token text not null,
  domain_verified_at timestamptz,
  metadata_url text check (metadata_url is null or (metadata_url ~ '^https://' and char_length(metadata_url) <= 500)),
  status text not null default 'draft' check (status in ('draft','requested','active','disabled')),
  enforce_sso boolean not null default false,
  provider_id text,
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.sso_connections enable row level security;
revoke all on public.sso_connections from anon, authenticated;
grant select (tenant_id, domain, verification_token, domain_verified_at, metadata_url, status, enforce_sso, created_at, updated_at)
  on public.sso_connections to authenticated;
drop policy if exists sso_connections_read on public.sso_connections;
create policy sso_connections_read on public.sso_connections for select to authenticated
  using ((select private.can_read_organization_audit(tenant_id)) or (select private.can_manage_audit_webhooks(tenant_id)));

create or replace function private.save_sso_connection(p_tenant_id uuid, p_domain text, p_metadata_url text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_domain text := lower(btrim(p_domain));
  v_existing public.sso_connections%rowtype;
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then
    raise exception 'sso management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = p_tenant_id) is distinct from 'organization' then
    raise exception 'single sign-on requires an organization' using errcode = '22023';
  end if;
  if not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement required' using errcode = '23514';
  end if;
  if v_domain in ('gmail.com','googlemail.com','outlook.com','hotmail.com','yahoo.com','icloud.com','proton.me','protonmail.com','live.com','aol.com') then
    raise exception 'use your organization''s own email domain' using errcode = '22023';
  end if;
  select * into v_existing from public.sso_connections c where c.tenant_id = p_tenant_id for update;
  if not found then
    insert into public.sso_connections (tenant_id, domain, verification_token, metadata_url, created_by)
    values (p_tenant_id, v_domain, 'passkey-x-verification=' || encode(extensions.gen_random_bytes(16), 'hex'),
      nullif(btrim(coalesce(p_metadata_url, '')), ''), private.current_identity_id());
  else
    update public.sso_connections set
      domain = v_domain,
      metadata_url = nullif(btrim(coalesce(p_metadata_url, '')), ''),
      domain_verified_at = case when v_existing.domain = v_domain then domain_verified_at else null end,
      verification_token = case when v_existing.domain = v_domain then verification_token
        else 'passkey-x-verification=' || encode(extensions.gen_random_bytes(16), 'hex') end,
      status = case when v_existing.domain = v_domain and v_existing.status = 'active' then 'active' else 'draft' end,
      updated_at = now()
      where tenant_id = p_tenant_id;
  end if;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'sso.configured', 'sso_connections', null,
    jsonb_build_object('domain', v_domain));
end
$$;

-- Called by the identity-admin edge function after it finds the TXT record.
create or replace function private.mark_sso_domain_verified(p_tenant_id uuid, p_domain text)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
begin
  update public.sso_connections set domain_verified_at = now(), updated_at = now()
    where tenant_id = p_tenant_id and domain = lower(p_domain);
  if found then
    perform private.append_audit_event(p_tenant_id, null, 'sso.domain_verified', 'sso_connections', null, jsonb_build_object('domain', lower(p_domain)));
  end if;
  return found;
end
$$;

create or replace function private.request_sso_activation(p_tenant_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.sso_connections%rowtype;
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then raise exception 'sso management denied' using errcode = '42501'; end if;
  select * into v_row from public.sso_connections c where c.tenant_id = p_tenant_id for update;
  if not found or v_row.domain_verified_at is null then raise exception 'verify your domain first' using errcode = '22023'; end if;
  if v_row.metadata_url is null then raise exception 'add your identity provider metadata URL first' using errcode = '22023'; end if;
  update public.sso_connections set status = case when status = 'active' then 'active' else 'requested' end, updated_at = now()
    where tenant_id = p_tenant_id;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'sso.activation_requested', 'sso_connections', null,
    jsonb_build_object('domain', v_row.domain));
end
$$;

create or replace function private.set_sso_enforcement(p_tenant_id uuid, p_enforce boolean)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then raise exception 'sso management denied' using errcode = '42501'; end if;
  update public.sso_connections set enforce_sso = p_enforce, updated_at = now()
    where tenant_id = p_tenant_id and (status = 'active' or not p_enforce);
  if not found then raise exception 'single sign-on must be active before it can be required' using errcode = '22023'; end if;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(),
    case when p_enforce then 'sso.enforced' else 'sso.optional' end, 'sso_connections', null, '{}'::jsonb);
end
$$;

-- Login screen lookup: is single sign-on available / required for this email domain?
create or replace function public.sso_status_for_email(p_email text)
returns table (sso_available boolean, sso_required boolean)
language sql stable security definer set search_path = ''
as $$
  select coalesce(bool_or(c.status = 'active'), false), coalesce(bool_or(c.status = 'active' and c.enforce_sso), false)
  from public.sso_connections c
  where c.domain = lower(split_part(btrim(coalesce(p_email, '')), '@', 2)) and c.domain_verified_at is not null
$$;
revoke all on function public.sso_status_for_email(text) from public;
grant execute on function public.sso_status_for_email(text) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- Organisation recovery (opt-in per organisation)
-- ---------------------------------------------------------------------------
create table if not exists public.organization_recovery_keys (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  key_id uuid not null,
  public_key bytea not null check (octet_length(public_key) = 65),
  fingerprint text not null,
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now()
);
alter table public.organization_recovery_keys enable row level security;
revoke all on public.organization_recovery_keys from anon, authenticated;
grant select on public.organization_recovery_keys to authenticated;
drop policy if exists organization_recovery_keys_read on public.organization_recovery_keys;
create policy organization_recovery_keys_read on public.organization_recovery_keys for select to authenticated
using (exists (select 1 from public.tenant_memberships tm
  where tm.tenant_id = organization_recovery_keys.tenant_id and tm.identity_id = (select private.current_identity_id()) and tm.status = 'active'));

create table if not exists public.organization_recovery_enrollments (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  key_id uuid not null,
  ephemeral_public_key bytea not null check (octet_length(ephemeral_public_key) = 65),
  nonce bytea not null check (octet_length(nonce) = 12),
  ciphertext bytea not null check (octet_length(ciphertext) >= 48),
  created_at timestamptz not null default now(),
  primary key (tenant_id, identity_id)
);
alter table public.organization_recovery_enrollments enable row level security;
revoke all on public.organization_recovery_enrollments from anon, authenticated;
grant select (tenant_id, identity_id, key_id, created_at) on public.organization_recovery_enrollments to authenticated;
drop policy if exists organization_recovery_enrollments_read on public.organization_recovery_enrollments;
create policy organization_recovery_enrollments_read on public.organization_recovery_enrollments for select to authenticated
using (identity_id = (select private.current_identity_id()) or (select private.can_read_organization_audit(tenant_id)));

create table if not exists public.organization_recovery_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','approved','completed','denied','expired')),
  decided_by uuid references public.identities(id) on delete set null,
  decided_at timestamptz,
  release_nonce bytea,
  release_ciphertext bytea,
  release_code_hash bytea,
  expires_at timestamptz not null default (now() + interval '7 days'),
  created_at timestamptz not null default now()
);
create unique index if not exists organization_recovery_one_open
  on public.organization_recovery_requests (tenant_id, identity_id) where status in ('pending','approved');
alter table public.organization_recovery_requests enable row level security;
revoke all on public.organization_recovery_requests from anon, authenticated;
grant select (id, tenant_id, identity_id, status, decided_at, release_nonce, release_ciphertext, expires_at, created_at)
  on public.organization_recovery_requests to authenticated;
drop policy if exists organization_recovery_requests_read on public.organization_recovery_requests;
-- Members see their own request (the release is encrypted under a code only they receive);
-- admins see the queue. Organisation recovery stays readable without two-step so a
-- member locked out of their vault can still finish recovery after signing in.
create policy organization_recovery_requests_read on public.organization_recovery_requests for select to authenticated
using (identity_id = (select private.current_identity_id())
  or (select private.can_manage_organization(tenant_id, array['organization_admin','security_admin','helpdesk_admin'])));

create or replace function private.recovery_enabled(p_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce((select (p.configuration ->> 'enabled')::boolean from public.organization_policies p
    where p.tenant_id = p_tenant and p.policy_type = 'organization_recovery' and p.enforced and p.scope_type = 'tenant'
    order by p.priority desc, p.version desc limit 1), false)
$$;

create or replace function private.set_organization_recovery_key(p_tenant_id uuid, p_key_id uuid, p_public_key bytea, p_fingerprint text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if not private.has_tenant_role(p_tenant_id, array['owner','admin']) then
    raise exception 'only owners and admins can manage the recovery key' using errcode = '42501';
  end if;
  if octet_length(p_public_key) <> 65 or get_byte(p_public_key, 0) <> 4 then
    raise exception 'invalid recovery public key' using errcode = '22023';
  end if;
  insert into public.organization_recovery_keys (tenant_id, key_id, public_key, fingerprint, created_by)
  values (p_tenant_id, p_key_id, p_public_key, left(p_fingerprint, 64), private.current_identity_id())
  on conflict (tenant_id) do update set key_id = excluded.key_id, public_key = excluded.public_key,
    fingerprint = excluded.fingerprint, created_by = excluded.created_by, created_at = now();
  -- Enrollments made to an older key can no longer be opened; members re-enroll on next unlock.
  delete from public.organization_recovery_enrollments e where e.tenant_id = p_tenant_id and e.key_id <> p_key_id;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'org_recovery.key_set', 'organization_recovery_keys', p_key_id,
    jsonb_build_object('fingerprint', left(p_fingerprint, 64)));
end
$$;

create or replace function private.enroll_organization_recovery(p_tenant_id uuid, p_key_id uuid, p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not exists (select 1 from public.tenant_memberships tm
      where tm.tenant_id = p_tenant_id and tm.identity_id = v_actor and tm.status = 'active') then
    raise exception 'organization membership required' using errcode = '42501';
  end if;
  if not private.recovery_enabled(p_tenant_id) then
    raise exception 'organization recovery is not enabled' using errcode = '22023';
  end if;
  if p_key_id is distinct from (select k.key_id from public.organization_recovery_keys k where k.tenant_id = p_tenant_id) then
    raise exception 'the organization recovery key changed; reload and try again' using errcode = '40001';
  end if;
  insert into public.organization_recovery_enrollments (tenant_id, identity_id, key_id, ephemeral_public_key, nonce, ciphertext)
  values (p_tenant_id, v_actor, p_key_id, p_ephemeral_public_key, p_nonce, p_ciphertext)
  on conflict (tenant_id, identity_id) do update set key_id = excluded.key_id,
    ephemeral_public_key = excluded.ephemeral_public_key, nonce = excluded.nonce, ciphertext = excluded.ciphertext, created_at = now();
  perform private.append_audit_event(p_tenant_id, v_actor, 'org_recovery.enrolled', 'identities', v_actor, '{}'::jsonb);
end
$$;

create or replace function private.request_organization_recovery(p_tenant_id uuid)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_id uuid;
begin
  if v_actor is null or not exists (select 1 from public.organization_recovery_enrollments e
      where e.tenant_id = p_tenant_id and e.identity_id = v_actor) then
    raise exception 'you are not enrolled in organization recovery' using errcode = '42501';
  end if;
  update public.organization_recovery_requests set status = 'expired'
    where tenant_id = p_tenant_id and identity_id = v_actor and status in ('pending','approved') and expires_at <= now();
  select r.id into v_id from public.organization_recovery_requests r
    where r.tenant_id = p_tenant_id and r.identity_id = v_actor and r.status in ('pending','approved');
  if v_id is not null then return v_id; end if;
  insert into public.organization_recovery_requests (tenant_id, identity_id) values (p_tenant_id, v_actor) returning id into v_id;
  perform private.append_audit_event(p_tenant_id, v_actor, 'org_recovery.requested', 'organization_recovery_requests', v_id, '{}'::jsonb);
  return v_id;
end
$$;

-- Admin queue including the member's escrow envelope (decrypted only in the admin's browser with the offline kit).
create or replace function private.organization_recovery_queue(p_tenant_id uuid)
returns table (request_id uuid, identity_id uuid, display_name text, email text, created_at timestamptz,
  key_id uuid, ephemeral_public_key bytea, nonce bytea, ciphertext bytea)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin','helpdesk_admin']) then
    raise exception 'recovery queue access denied' using errcode = '42501';
  end if;
  return query
  select r.id, r.identity_id, coalesce(p.display_name, split_part(u.email::text, '@', 1)), u.email::text, r.created_at,
    e.key_id, e.ephemeral_public_key, e.nonce, e.ciphertext
  from public.organization_recovery_requests r
  join public.organization_recovery_enrollments e on e.tenant_id = r.tenant_id and e.identity_id = r.identity_id
  join public.identities i on i.id = r.identity_id
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles p on p.tenant_id = r.tenant_id and p.identity_id = r.identity_id
  where r.tenant_id = p_tenant_id and r.status = 'pending' and r.expires_at > now()
  order by r.created_at;
end
$$;

create or replace function private.decide_organization_recovery(p_request_id uuid, p_approve boolean,
  p_release_nonce bytea, p_release_ciphertext bytea, p_release_code_hash bytea)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_row public.organization_recovery_requests%rowtype;
begin
  select * into v_row from public.organization_recovery_requests r where r.id = p_request_id and r.status = 'pending' for update;
  if not found or not private.can_manage_organization(v_row.tenant_id, array['organization_admin','security_admin','helpdesk_admin'])
     or v_actor = v_row.identity_id then
    raise exception 'recovery request not available' using errcode = '42501';
  end if;
  if not private.session_mfa_satisfied() then raise exception 'two-step verification required' using errcode = '28000'; end if;
  if p_approve and (octet_length(p_release_nonce) <> 12 or octet_length(p_release_ciphertext) < 48 or octet_length(p_release_code_hash) <> 32) then
    raise exception 'invalid recovery release' using errcode = '22023';
  end if;
  update public.organization_recovery_requests set status = case when p_approve then 'approved' else 'denied' end,
    decided_by = v_actor, decided_at = now(),
    release_nonce = case when p_approve then p_release_nonce end,
    release_ciphertext = case when p_approve then p_release_ciphertext end,
    release_code_hash = case when p_approve then p_release_code_hash end,
    expires_at = case when p_approve then now() + interval '24 hours' else expires_at end
    where id = p_request_id;
  perform private.append_audit_event(v_row.tenant_id, v_actor,
    case when p_approve then 'org_recovery.approved' else 'org_recovery.denied' end,
    'organization_recovery_requests', p_request_id, jsonb_build_object('member', v_row.identity_id));
end
$$;

-- Member finishes recovery with the one-time code: replaces the vault password wrap.
create or replace function private.complete_organization_recovery(p_request_id uuid, p_code_hash bytea,
  p_salt bytea, p_kdf_parameters jsonb, p_master_nonce bytea, p_master_wrapped_root bytea)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_row public.organization_recovery_requests%rowtype;
begin
  select * into v_row from public.organization_recovery_requests r
    where r.id = p_request_id and r.identity_id = v_actor and r.status = 'approved' and r.expires_at > now() for update;
  if not found or v_row.release_code_hash is distinct from p_code_hash then
    raise exception 'recovery code rejected' using errcode = '28000';
  end if;
  if octet_length(p_salt) <> 16 or octet_length(p_master_nonce) <> 12 or octet_length(p_master_wrapped_root) < 48 then
    raise exception 'invalid cryptographic parameter length' using errcode = '22023';
  end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID'
     or (p_kdf_parameters ->> 'memoryKib')::integer not between 65536 and 1048576
     or (p_kdf_parameters ->> 'iterations')::integer not between 3 and 12
     or (p_kdf_parameters ->> 'parallelism')::integer not between 1 and 4
     or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then
    raise exception 'invalid KDF profile' using errcode = '22023';
  end if;
  update public.account_crypto_profiles set salt = p_salt, kdf_parameters = p_kdf_parameters,
    master_nonce = p_master_nonce, master_wrapped_root = p_master_wrapped_root, updated_at = now()
    where identity_id = v_actor;
  if not found then raise exception 'vault profile not found' using errcode = 'P0002'; end if;
  update public.organization_recovery_requests set status = 'completed', release_nonce = null, release_ciphertext = null,
    release_code_hash = null where id = p_request_id;
  perform private.append_audit_event(v_row.tenant_id, v_actor, 'org_recovery.completed', 'organization_recovery_requests', p_request_id, '{}'::jsonb);
end
$$;

-- ---------------------------------------------------------------------------
-- Wrappers and grants
-- ---------------------------------------------------------------------------
create or replace function public.create_scim_token(p_tenant_id uuid, p_name text)
returns table (id uuid, token text) language sql volatile security invoker set search_path = ''
as $$ select * from private.create_scim_token(p_tenant_id, p_name) $$;
create or replace function public.revoke_scim_token(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.revoke_scim_token(p_id) $$;
create or replace function public.claim_provisioned_membership(p_id uuid)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.claim_provisioned_membership(p_id) $$;
create or replace function public.save_sso_connection(p_tenant_id uuid, p_domain text, p_metadata_url text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.save_sso_connection(p_tenant_id, p_domain, p_metadata_url) $$;
create or replace function public.request_sso_activation(p_tenant_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.request_sso_activation(p_tenant_id) $$;
create or replace function public.set_sso_enforcement(p_tenant_id uuid, p_enforce boolean)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_sso_enforcement(p_tenant_id, p_enforce) $$;
create or replace function public.set_organization_recovery_key(p_tenant_id uuid, p_key_id uuid, p_public_key bytea, p_fingerprint text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_organization_recovery_key(p_tenant_id, p_key_id, p_public_key, p_fingerprint) $$;
create or replace function public.enroll_organization_recovery(p_tenant_id uuid, p_key_id uuid, p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.enroll_organization_recovery(p_tenant_id, p_key_id, p_ephemeral_public_key, p_nonce, p_ciphertext) $$;
create or replace function public.request_organization_recovery(p_tenant_id uuid)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.request_organization_recovery(p_tenant_id) $$;
create or replace function public.organization_recovery_queue(p_tenant_id uuid)
returns table (request_id uuid, identity_id uuid, display_name text, email text, created_at timestamptz,
  key_id uuid, ephemeral_public_key bytea, nonce bytea, ciphertext bytea)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_recovery_queue(p_tenant_id) $$;
create or replace function public.decide_organization_recovery(p_request_id uuid, p_approve boolean,
  p_release_nonce bytea default null, p_release_ciphertext bytea default null, p_release_code_hash bytea default null)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.decide_organization_recovery(p_request_id, p_approve, p_release_nonce, p_release_ciphertext, p_release_code_hash) $$;
create or replace function public.complete_organization_recovery(p_request_id uuid, p_code_hash bytea,
  p_salt bytea, p_kdf_parameters jsonb, p_master_nonce bytea, p_master_wrapped_root bytea)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.complete_organization_recovery(p_request_id, p_code_hash, p_salt, p_kdf_parameters, p_master_nonce, p_master_wrapped_root) $$;

-- Service-role wrappers used by the scim and identity-admin edge functions.
create or replace function public.scim_tenant_for_token(p_token text) returns uuid
language sql volatile security invoker set search_path = '' as $$ select private.scim_tenant_for_token(p_token) $$;
create or replace function public.scim_upsert_user(p_tenant_id uuid, p_id uuid, p_external_id text, p_user_name text,
  p_display_name text, p_job_title text, p_active boolean) returns public.scim_provisioned_users
language sql volatile security invoker set search_path = ''
as $$ select * from private.scim_upsert_user(p_tenant_id, p_id, p_external_id, p_user_name, p_display_name, p_job_title, p_active) $$;
create or replace function public.scim_delete_user(p_tenant_id uuid, p_id uuid) returns boolean
language sql volatile security invoker set search_path = '' as $$ select private.scim_delete_user(p_tenant_id, p_id) $$;
create or replace function public.scim_list_users(p_tenant_id uuid, p_user_name text, p_external_id text, p_offset integer, p_limit integer)
returns table (total bigint, users jsonb) language sql stable security invoker set search_path = ''
as $$ select * from private.scim_list_users(p_tenant_id, p_user_name, p_external_id, p_offset, p_limit) $$;
create or replace function public.mark_sso_domain_verified(p_tenant_id uuid, p_domain text) returns boolean
language sql volatile security invoker set search_path = '' as $$ select private.mark_sso_domain_verified(p_tenant_id, p_domain) $$;

do $$
declare v_sig text;
begin
  foreach v_sig in array array[
    'create_scim_token(uuid,text)', 'revoke_scim_token(uuid)', 'claim_provisioned_membership(uuid)',
    'save_sso_connection(uuid,text,text)', 'request_sso_activation(uuid)', 'set_sso_enforcement(uuid,boolean)',
    'set_organization_recovery_key(uuid,uuid,bytea,text)', 'enroll_organization_recovery(uuid,uuid,bytea,bytea,bytea)',
    'request_organization_recovery(uuid)', 'organization_recovery_queue(uuid)',
    'decide_organization_recovery(uuid,boolean,bytea,bytea,bytea)',
    'complete_organization_recovery(uuid,bytea,bytea,jsonb,bytea,bytea)'
  ] loop
    execute format('revoke all on function private.%s from public, anon', v_sig);
    execute format('grant execute on function private.%s to authenticated', v_sig);
    execute format('revoke all on function public.%s from public, anon', v_sig);
    execute format('grant execute on function public.%s to authenticated', v_sig);
  end loop;
  foreach v_sig in array array[
    'scim_tenant_for_token(text)', 'scim_upsert_user(uuid,uuid,text,text,text,text,boolean)', 'scim_delete_user(uuid,uuid)',
    'scim_list_users(uuid,text,text,integer,integer)', 'mark_sso_domain_verified(uuid,text)'
  ] loop
    execute format('revoke all on function private.%s from public, anon, authenticated', v_sig);
    execute format('grant execute on function private.%s to service_role', v_sig);
    execute format('revoke all on function public.%s from public, anon, authenticated', v_sig);
    execute format('grant execute on function public.%s to service_role', v_sig);
  end loop;
end
$$;
revoke all on function private.scim_offboard_identity(uuid,uuid,text) from public, anon, authenticated;
revoke all on function private.recovery_enabled(uuid) from public, anon, authenticated;
grant usage on schema private to service_role;

