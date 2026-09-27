-- Passkey-X enterprise web v3 — access controls and Secure Send.
--
-- 1. Temporary (just-in-time) workspace membership with automatic expiry.
-- 2. Organization access review and admin revocation of workspace access.
-- 3. Secure Send: end-to-end encrypted, expiring, view-limited links. The key
--    lives only in the URL fragment; the server stores ciphertext and burns it
--    after the last permitted view.

-- ---------------------------------------------------------------------------
-- 1. Temporary workspace membership
-- ---------------------------------------------------------------------------
alter table public.workspace_memberships add column if not exists expires_at timestamptz;
create index if not exists workspace_memberships_expiry_idx
  on public.workspace_memberships(expires_at) where expires_at is not null and status = 'active';

create or replace function private.has_workspace_role(target_tenant uuid, target_workspace uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1 from public.workspace_memberships wm
    join public.identities i on i.id = wm.identity_id
    where wm.tenant_id = target_tenant and wm.workspace_id = target_workspace
      and i.auth_user_id = auth.uid() and i.status = 'active'
      and wm.status = 'active' and wm.role = any(allowed_roles)
      and (wm.expires_at is null or wm.expires_at > now())
  )
$$;

create or replace function private.can_admin_workspace_access(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant, array['owner','admin'])
    or private.can_manage_organization(target_tenant, array['organization_admin','security_admin'])
$$;
revoke all on function private.can_admin_workspace_access(uuid) from public, anon;
grant execute on function private.can_admin_workspace_access(uuid) to authenticated;

create or replace function private.set_workspace_member_expiry(
  p_workspace_id uuid, p_identity_id uuid, p_expires_at timestamptz
) returns void language plpgsql security definer set search_path = ''
as $$
declare v_member public.workspace_memberships%rowtype;
begin
  select * into v_member from public.workspace_memberships
    where workspace_id = p_workspace_id and identity_id = p_identity_id and status = 'active' for update;
  if not found then raise exception 'member not found' using errcode = 'P0002'; end if;
  if v_member.role = 'owner' then raise exception 'workspace owners cannot be time-limited' using errcode = '42501'; end if;
  if not (private.can_manage_workspace(v_member.tenant_id, v_member.workspace_id)
          or private.can_admin_workspace_access(v_member.tenant_id)) then
    raise exception 'workspace access change denied' using errcode = '42501';
  end if;
  if p_expires_at is not null and (p_expires_at <= now() or p_expires_at > now() + interval '366 days') then
    raise exception 'expiry must be in the next 12 months' using errcode = '22023';
  end if;
  update public.workspace_memberships set expires_at = p_expires_at, updated_at = now()
    where workspace_id = p_workspace_id and identity_id = p_identity_id;
  perform private.append_audit_event(v_member.tenant_id, private.current_identity_id(),
    'workspace_memberships.expiry_set', 'workspace_memberships', p_identity_id,
    jsonb_build_object('workspace_id', p_workspace_id, 'expires_at', p_expires_at));
end
$$;
revoke all on function private.set_workspace_member_expiry(uuid,uuid,timestamptz) from public, anon;
grant execute on function private.set_workspace_member_expiry(uuid,uuid,timestamptz) to authenticated;

-- Finalises expired memberships: revoke membership + key envelopes and flag rotation.
create or replace function private.expire_workspace_memberships()
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_row record; v_count integer := 0;
begin
  for v_row in
    select tenant_id, workspace_id, identity_id from public.workspace_memberships
    where status = 'active' and expires_at is not null and expires_at <= now()
    for update skip locked
  loop
    update public.workspace_memberships set status = 'revoked', updated_at = now()
      where workspace_id = v_row.workspace_id and identity_id = v_row.identity_id;
    update public.key_envelopes set revoked_at = now()
      where workspace_id = v_row.workspace_id and recipient_identity_id = v_row.identity_id and revoked_at is null;
    update public.workspaces set key_rotation_required = true, updated_at = now()
      where id = v_row.workspace_id and tenant_id = v_row.tenant_id;
    perform private.append_audit_event(v_row.tenant_id, null, 'workspace_memberships.expired',
      'workspace_memberships', v_row.identity_id, jsonb_build_object('workspace_id', v_row.workspace_id));
    v_count := v_count + 1;
  end loop;
  return v_count;
end
$$;
revoke all on function private.expire_workspace_memberships() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. Access review
-- ---------------------------------------------------------------------------
create or replace function private.organization_access_review(p_tenant_id uuid)
returns table (
  workspace_id uuid, suite text, workspace_status text, workspace_created_at timestamptz,
  key_rotation_required boolean, identity_id uuid, display_name text, email text,
  role text, membership_status text, expires_at timestamptz, member_since timestamptz,
  last_activity_at timestamptz
) language plpgsql stable security definer set search_path = ''
as $$
begin
  if not (private.can_admin_workspace_access(p_tenant_id) or private.can_read_organization_audit(p_tenant_id)) then
    raise exception 'access review denied' using errcode = '42501';
  end if;
  return query
  select w.id, w.suite, w.status, w.created_at, w.key_rotation_required,
    wm.identity_id, coalesce(p.display_name, split_part(u.email::text,'@',1)), u.email::text,
    wm.role, wm.status, wm.expires_at, wm.created_at,
    (select max(e.occurred_at) from public.audit_events e
      where e.tenant_id = w.tenant_id and e.actor_identity_id = wm.identity_id
        and e.metadata ->> 'workspace_id' = w.id::text)
  from public.workspaces w
  join public.workspace_memberships wm on wm.workspace_id = w.id and wm.tenant_id = w.tenant_id
  join public.identities i on i.id = wm.identity_id
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles p on p.tenant_id = w.tenant_id and p.identity_id = wm.identity_id
  where w.tenant_id = p_tenant_id and wm.status in ('active','suspended')
  order by w.created_at, wm.role, coalesce(p.display_name, u.email::text);
end
$$;
revoke all on function private.organization_access_review(uuid) from public, anon;
grant execute on function private.organization_access_review(uuid) to authenticated;

create or replace function private.admin_revoke_workspace_member(
  p_tenant_id uuid, p_workspace_id uuid, p_identity_id uuid
) returns void language plpgsql security definer set search_path = ''
as $$
declare v_member public.workspace_memberships%rowtype;
begin
  if not private.can_admin_workspace_access(p_tenant_id) then
    raise exception 'workspace access change denied' using errcode = '42501';
  end if;
  select * into v_member from public.workspace_memberships
    where tenant_id = p_tenant_id and workspace_id = p_workspace_id and identity_id = p_identity_id
      and status = 'active' for update;
  if not found then raise exception 'member not found' using errcode = 'P0002'; end if;
  if v_member.role = 'owner' and (
    select count(*) from public.workspace_memberships
    where workspace_id = p_workspace_id and role = 'owner' and status = 'active'
  ) <= 1 then
    raise exception 'a workspace needs at least one owner' using errcode = '23514';
  end if;
  update public.workspace_memberships set status = 'revoked', updated_at = now()
    where workspace_id = p_workspace_id and identity_id = p_identity_id;
  update public.key_envelopes set revoked_at = now()
    where workspace_id = p_workspace_id and recipient_identity_id = p_identity_id and revoked_at is null;
  update public.workspaces set key_rotation_required = true, updated_at = now()
    where id = p_workspace_id and tenant_id = p_tenant_id;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(),
    'workspace_memberships.admin_revoked', 'workspace_memberships', p_identity_id,
    jsonb_build_object('workspace_id', p_workspace_id, 'role', v_member.role));
end
$$;
revoke all on function private.admin_revoke_workspace_member(uuid,uuid,uuid) from public, anon;
grant execute on function private.admin_revoke_workspace_member(uuid,uuid,uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 3. Secure Send
-- ---------------------------------------------------------------------------
create table if not exists public.secure_sends (
  id uuid primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  created_by uuid not null references public.identities(id) on delete cascade,
  kind text not null check (kind in ('text','file')),
  nonce bytea not null check (octet_length(nonce) = 12),
  ciphertext bytea check (ciphertext is null or octet_length(ciphertext) between 16 and 7340032),
  byte_size integer not null check (byte_size between 16 and 7340032),
  requires_passphrase boolean not null default false,
  passphrase_salt bytea check (passphrase_salt is null or octet_length(passphrase_salt) = 16),
  max_views integer not null check (max_views between 1 and 100),
  view_count integer not null default 0 check (view_count >= 0),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  show_sender boolean not null default false,
  access_check bytea not null check (octet_length(access_check) = 32),
  failed_attempts integer not null default 0 check (failed_attempts >= 0),
  created_at timestamptz not null default now(),
  last_viewed_at timestamptz,
  check (requires_passphrase = (passphrase_salt is not null)),
  check (expires_at <= created_at + interval '31 days')
);
create index if not exists secure_sends_creator_idx on public.secure_sends(created_by, created_at desc);
create index if not exists secure_sends_tenant_idx on public.secure_sends(tenant_id, created_at desc);
create index if not exists secure_sends_expiry_idx on public.secure_sends(expires_at) where ciphertext is not null;

alter table public.secure_sends enable row level security;
revoke all on public.secure_sends from anon, authenticated;
grant select (id,tenant_id,created_by,kind,byte_size,requires_passphrase,max_views,view_count,
  expires_at,revoked_at,show_sender,created_at,last_viewed_at) on public.secure_sends to authenticated;

drop policy if exists secure_sends_read on public.secure_sends;
create policy secure_sends_read on public.secure_sends for select to authenticated
using (
  created_by = (select private.current_identity_id())
  or (select private.can_admin_workspace_access(tenant_id))
  or (select private.can_read_organization_audit(tenant_id))
);

create or replace function private.create_secure_send(
  p_id uuid, p_tenant_id uuid, p_kind text, p_nonce bytea, p_ciphertext bytea,
  p_passphrase_salt bytea, p_max_views integer, p_expires_at timestamptz, p_show_sender boolean,
  p_access_check bytea
) returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_mode text;
  v_recent integer;
begin
  if v_actor is null or not exists (
    select 1 from public.tenant_memberships tm
    where tm.tenant_id = p_tenant_id and tm.identity_id = v_actor and tm.status = 'active'
  ) then
    raise exception 'tenant membership required' using errcode = '42501';
  end if;
  v_mode := coalesce(private.tenant_policy_configuration(p_tenant_id,'sharing_mode') ->> 'mode','open');
  if v_mode <> 'open' and not private.has_tenant_role(p_tenant_id, array['owner','admin']) then
    raise exception 'secure send is restricted by organization policy' using errcode = '42501';
  end if;
  if p_expires_at <= now() or p_expires_at > now() + interval '30 days' then
    raise exception 'expiry must be within 30 days' using errcode = '22023';
  end if;
  select count(*) into v_recent from public.secure_sends
    where created_by = v_actor and created_at > now() - interval '1 day';
  if v_recent >= 100 then raise exception 'daily secure send limit reached' using errcode = '54000'; end if;
  insert into public.secure_sends(id,tenant_id,created_by,kind,nonce,ciphertext,byte_size,
    requires_passphrase,passphrase_salt,max_views,expires_at,show_sender,access_check)
  values (p_id,p_tenant_id,v_actor,p_kind,p_nonce,p_ciphertext,octet_length(p_ciphertext),
    p_passphrase_salt is not null,p_passphrase_salt,p_max_views,p_expires_at,coalesce(p_show_sender,false),
    extensions.digest(p_access_check,'sha256'));
  perform private.append_audit_event(p_tenant_id, v_actor, 'secure_send.created', 'secure_sends', p_id,
    jsonb_build_object('kind', p_kind, 'max_views', p_max_views, 'expires_at', p_expires_at,
      'passphrase', p_passphrase_salt is not null));
end
$$;
revoke all on function private.create_secure_send(uuid,uuid,text,bytea,bytea,bytea,integer,timestamptz,boolean,bytea) from public, anon;
grant execute on function private.create_secure_send(uuid,uuid,text,bytea,bytea,bytea,integer,timestamptz,boolean,bytea) to authenticated;

-- Metadata only; never consumes a view (safe for link previews).
create or replace function private.peek_secure_send(p_id uuid)
returns table (kind text, byte_size integer, requires_passphrase boolean, passphrase_salt bytea,
  views_left integer, expires_at timestamptz, available boolean, sender text)
language sql stable security definer set search_path = ''
as $$
  select s.kind, s.byte_size, s.requires_passphrase, s.passphrase_salt, greatest(s.max_views - s.view_count, 0),
    s.expires_at,
    s.revoked_at is null and s.expires_at > now() and s.view_count < s.max_views and s.ciphertext is not null
      and s.failed_attempts < 10,
    case when s.show_sender then u.email::text else null end
  from public.secure_sends s
  left join public.identities i on i.id = s.created_by
  left join auth.users u on u.id = i.auth_user_id
  where s.id = p_id
$$;
revoke all on function private.peek_secure_send(uuid) from public;
grant execute on function private.peek_secure_send(uuid) to anon, authenticated;

-- Consumes one view and returns the ciphertext. The last view burns it.
create or replace function private.open_secure_send(p_id uuid, p_proof bytea)
returns table (kind text, nonce bytea, ciphertext bytea, views_left integer)
language plpgsql volatile security definer set search_path = ''
as $$
#variable_conflict use_column
declare v_send public.secure_sends%rowtype;
begin
  select * into v_send from public.secure_sends s where s.id = p_id for update;
  if not found or v_send.revoked_at is not null or v_send.expires_at <= now()
     or v_send.view_count >= v_send.max_views or v_send.ciphertext is null
     or v_send.failed_attempts >= 10 then
    raise exception 'this link has expired or was already used' using errcode = 'P0002';
  end if;
  -- Only holders of the full link key (and passphrase, if any) can consume a view.
  if p_proof is null or octet_length(p_proof) <> 32
     or extensions.digest(p_proof,'sha256') <> v_send.access_check then
    update public.secure_sends set failed_attempts = failed_attempts + 1 where id = p_id;
    return;
  end if;
  update public.secure_sends set view_count = view_count + 1, last_viewed_at = now(),
    ciphertext = case when view_count + 1 >= max_views then null else ciphertext end
    where id = p_id;
  perform private.append_audit_event(v_send.tenant_id, private.current_identity_id(), 'secure_send.opened',
    'secure_sends', p_id, jsonb_build_object('view', v_send.view_count + 1, 'max_views', v_send.max_views));
  return query select v_send.kind, v_send.nonce, v_send.ciphertext,
    v_send.max_views - v_send.view_count - 1;
end
$$;
revoke all on function private.open_secure_send(uuid,bytea) from public;
grant execute on function private.open_secure_send(uuid,bytea) to anon, authenticated;

create or replace function private.revoke_secure_send(p_id uuid)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_send public.secure_sends%rowtype;
begin
  select * into v_send from public.secure_sends where id = p_id for update;
  if not found or not (v_send.created_by = private.current_identity_id()
     or private.can_admin_workspace_access(v_send.tenant_id)) then
    raise exception 'secure send not found' using errcode = 'P0002';
  end if;
  update public.secure_sends set revoked_at = coalesce(revoked_at, now()), ciphertext = null where id = p_id;
  perform private.append_audit_event(v_send.tenant_id, private.current_identity_id(), 'secure_send.revoked',
    'secure_sends', p_id, '{}'::jsonb);
end
$$;
revoke all on function private.revoke_secure_send(uuid) from public, anon;
grant execute on function private.revoke_secure_send(uuid) to authenticated;

create or replace function private.purge_expired_secure_sends()
returns integer language sql volatile security definer set search_path = ''
as $$
  with purged as (
    update public.secure_sends set ciphertext = null
    where ciphertext is not null and (expires_at <= now() or revoked_at is not null or view_count >= max_views)
    returning 1
  ) select count(*)::integer from purged
$$;
revoke all on function private.purge_expired_secure_sends() from public, anon, authenticated;

-- Schedule housekeeping when pg_cron is available.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('px-expire-workspace-memberships', '*/5 * * * *', 'select private.expire_workspace_memberships()');
    perform cron.schedule('px-purge-secure-sends', '*/15 * * * *', 'select private.purge_expired_secure_sends()');
  end if;
end
$$;

comment on table public.secure_sends is
  'End-to-end encrypted one-time links. The decryption key exists only in the link fragment; ciphertext is burned after the final view or expiry.';

-- Browser-callable SECURITY INVOKER wrappers (implementations live in private).
grant usage on schema private to anon;

create or replace function public.set_workspace_member_expiry(p_workspace_id uuid, p_identity_id uuid, p_expires_at timestamptz)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_workspace_member_expiry(p_workspace_id, p_identity_id, p_expires_at) $$;

create or replace function public.organization_access_review(p_tenant_id uuid)
returns table (
  workspace_id uuid, suite text, workspace_status text, workspace_created_at timestamptz,
  key_rotation_required boolean, identity_id uuid, display_name text, email text,
  role text, membership_status text, expires_at timestamptz, member_since timestamptz,
  last_activity_at timestamptz
) language sql stable security invoker set search_path = ''
as $$ select * from private.organization_access_review(p_tenant_id) $$;

create or replace function public.admin_revoke_workspace_member(p_tenant_id uuid, p_workspace_id uuid, p_identity_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.admin_revoke_workspace_member(p_tenant_id, p_workspace_id, p_identity_id) $$;

create or replace function public.create_secure_send(
  p_id uuid, p_tenant_id uuid, p_kind text, p_nonce bytea, p_ciphertext bytea,
  p_passphrase_salt bytea, p_max_views integer, p_expires_at timestamptz, p_show_sender boolean,
  p_access_check bytea
) returns void language sql volatile security invoker set search_path = ''
as $$ select private.create_secure_send(p_id, p_tenant_id, p_kind, p_nonce, p_ciphertext,
  p_passphrase_salt, p_max_views, p_expires_at, p_show_sender, p_access_check) $$;

create or replace function public.revoke_secure_send(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.revoke_secure_send(p_id) $$;

create or replace function public.peek_secure_send(p_id uuid)
returns table (kind text, byte_size integer, requires_passphrase boolean, passphrase_salt bytea,
  views_left integer, expires_at timestamptz, available boolean, sender text)
language sql stable security invoker set search_path = ''
as $$ select * from private.peek_secure_send(p_id) $$;

create or replace function public.open_secure_send(p_id uuid, p_proof bytea)
returns table (kind text, nonce bytea, ciphertext bytea, views_left integer)
language sql volatile security invoker set search_path = ''
as $$ select * from private.open_secure_send(p_id, p_proof) $$;

revoke all on function public.set_workspace_member_expiry(uuid,uuid,timestamptz) from public, anon;
revoke all on function public.organization_access_review(uuid) from public, anon;
revoke all on function public.admin_revoke_workspace_member(uuid,uuid,uuid) from public, anon;
revoke all on function public.create_secure_send(uuid,uuid,text,bytea,bytea,bytea,integer,timestamptz,boolean,bytea) from public, anon;
revoke all on function public.revoke_secure_send(uuid) from public, anon;
revoke all on function public.peek_secure_send(uuid) from public;
revoke all on function public.open_secure_send(uuid,bytea) from public;
grant execute on function public.set_workspace_member_expiry(uuid,uuid,timestamptz) to authenticated;
grant execute on function public.organization_access_review(uuid) to authenticated;
grant execute on function public.admin_revoke_workspace_member(uuid,uuid,uuid) to authenticated;
grant execute on function public.create_secure_send(uuid,uuid,text,bytea,bytea,bytea,integer,timestamptz,boolean,bytea) to authenticated;
grant execute on function public.revoke_secure_send(uuid) to authenticated;
grant execute on function public.peek_secure_send(uuid) to anon, authenticated;
grant execute on function public.open_secure_send(uuid,bytea) to anon, authenticated;
