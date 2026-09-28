-- Passkey-X v6 security fixes (from the 28 Sep 2026 review).
--  1. Server-side two-step enforcement (aal2) on vault secrets for accounts with a verified factor.
--  2. Re-authentication checks use the sign-in time (amr), not the refreshable token iat.
--  3. Department/team scoped policies are enforced server-side, not only shown in the UI.
--  4. Time-limited managers cannot remove or extend their own expiry.
--  5. Expired temporary members cannot record activity.
--  6. Access requests must reference an item in the same workspace.
--  7. Webhook event filters match literal prefixes (LIKE treated "_" as a wildcard).
--  8. Private-schema functions are no longer executable by PUBLIC by default.
--  9. Head-revision view so clients fetch one revision per item (no 1000-row truncation).

-- ---------------------------------------------------------------------------
-- 1. Two-step (aal2) enforcement
-- ---------------------------------------------------------------------------
create or replace function private.session_mfa_satisfied()
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'
    or auth.uid() is null
    or not exists (
      select 1 from auth.mfa_factors f
      where f.user_id = auth.uid() and f.status = 'verified'
    )
$$;
revoke all on function private.session_mfa_satisfied() from public, anon;
grant execute on function private.session_mfa_satisfied() to authenticated;

do $$
declare v_table text;
begin
  foreach v_table in array array[
    'account_crypto_profiles', 'vault_items', 'vault_item_revisions', 'key_envelopes',
    'attachments', 'attachment_versions', 'access_capsules', 'workspace_invites'
  ] loop
    if to_regclass('public.' || v_table) is not null then
      execute format('drop policy if exists %I on public.%I', v_table || '_require_mfa', v_table);
      execute format(
        'create policy %I on public.%I as restrictive for all to authenticated using ((select private.session_mfa_satisfied())) with check ((select private.session_mfa_satisfied()))',
        v_table || '_require_mfa', v_table);
    end if;
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- 2. Recent sign-in check based on the authentication time
-- ---------------------------------------------------------------------------
create or replace function private.signed_in_within(p_seconds integer)
returns boolean language sql stable set search_path = ''
as $$
  select coalesce((
    select max((entry ->> 'timestamp')::bigint)
    from jsonb_array_elements(case when jsonb_typeof(auth.jwt() -> 'amr') = 'array' then auth.jwt() -> 'amr' else '[]'::jsonb end) entry
    where jsonb_typeof(entry -> 'timestamp') = 'number'
  ), 0) >= extract(epoch from now())::bigint - p_seconds
$$;
revoke all on function private.signed_in_within(integer) from public, anon;
grant execute on function private.signed_in_within(integer) to authenticated;

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
  if not private.session_mfa_satisfied() then
    raise exception 'two-step verification required' using errcode = '28000';
  end if;
  if not private.signed_in_within(43200) then
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

-- ---------------------------------------------------------------------------
-- 3. Effective (scoped) policy for the current caller
-- ---------------------------------------------------------------------------
create or replace function private.tenant_policy_configuration(p_tenant uuid, p_type text)
returns jsonb language sql stable security definer set search_path = ''
as $$
  with recursive actor as (
    select private.current_identity_id() as id
  ), profile_scope as (
    select profile.department_id from public.organization_profiles profile, actor
    where profile.tenant_id = p_tenant and profile.identity_id = actor.id
  ), department_ancestors(id, parent_department_id, depth) as (
    select d.id, d.parent_department_id, 1 from public.organization_departments d
    join profile_scope s on s.department_id = d.id where d.tenant_id = p_tenant
    union all
    select parent.id, parent.parent_department_id, child.depth + 1 from public.organization_departments parent
    join department_ancestors child on child.parent_department_id = parent.id
    where parent.tenant_id = p_tenant and child.depth < 32
  ), teams as (
    select m.team_id from public.organization_team_memberships m, actor
    where m.tenant_id = p_tenant and m.identity_id = actor.id and m.status = 'active'
  )
  select p.configuration from public.organization_policies p
  where p.tenant_id = p_tenant and p.policy_type = p_type and p.enforced and (
    p.scope_type = 'tenant'
    or (p.scope_type = 'department' and p.scope_id in (select id from department_ancestors))
    or (p.scope_type = 'team' and p.scope_id in (select team_id from teams))
  )
  order by case p.scope_type when 'team' then 3 when 'department' then 2 else 1 end desc,
    p.priority desc, p.version desc
  limit 1
$$;
revoke all on function private.tenant_policy_configuration(uuid,text) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. Temporary access cannot be self-extended
-- ---------------------------------------------------------------------------
create or replace function private.set_workspace_member_expiry(
  p_workspace_id uuid, p_identity_id uuid, p_expires_at timestamptz
) returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_member public.workspace_memberships%rowtype;
  v_actor uuid := private.current_identity_id();
  v_is_admin boolean;
begin
  select * into v_member from public.workspace_memberships
    where workspace_id = p_workspace_id and identity_id = p_identity_id and status = 'active' for update;
  if not found then raise exception 'member not found' using errcode = 'P0002'; end if;
  if v_member.role = 'owner' then raise exception 'workspace owners cannot be time-limited' using errcode = '42501'; end if;
  v_is_admin := private.can_admin_workspace_access(v_member.tenant_id);
  if not (private.can_manage_workspace(v_member.tenant_id, v_member.workspace_id) or v_is_admin) then
    raise exception 'workspace access change denied' using errcode = '42501';
  end if;
  if p_identity_id = v_actor and not v_is_admin then
    raise exception 'you cannot change your own access expiry' using errcode = '42501';
  end if;
  -- Clearing or extending an existing limit is an administrator decision.
  if v_member.expires_at is not null and not v_is_admin
     and (p_expires_at is null or p_expires_at > v_member.expires_at) then
    raise exception 'only an organization administrator can remove or extend a time limit' using errcode = '42501';
  end if;
  if p_expires_at is not null and (p_expires_at <= now() or p_expires_at > now() + interval '366 days') then
    raise exception 'expiry must be in the next 12 months' using errcode = '22023';
  end if;
  update public.workspace_memberships set expires_at = p_expires_at, updated_at = now()
    where workspace_id = p_workspace_id and identity_id = p_identity_id;
  perform private.append_audit_event(v_member.tenant_id, v_actor,
    'workspace_memberships.expiry_set', 'workspace_memberships', p_identity_id,
    jsonb_build_object('workspace_id', p_workspace_id, 'expires_at', p_expires_at));
end
$$;

-- ---------------------------------------------------------------------------
-- 5. Activity requires a current (non-expired) membership
-- ---------------------------------------------------------------------------
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
  if not private.has_workspace_role(p_tenant_id, p_workspace_id, array['owner','manager','editor','viewer']) then
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

-- ---------------------------------------------------------------------------
-- 6. Access requests stay inside their workspace
-- ---------------------------------------------------------------------------
drop policy if exists access_requests_create on public.access_requests;
create policy access_requests_create on public.access_requests for insert to authenticated
with check (
  requester_identity_id = (select private.current_identity_id())
  and status = 'pending' and expires_at > now()
  and (select private.has_workspace_role(tenant_id, workspace_id, array['manager','editor','viewer']))
  and (item_id is null or exists (
    select 1 from public.vault_items vi
    where vi.id = access_requests.item_id
      and vi.tenant_id = access_requests.tenant_id
      and vi.workspace_id = access_requests.workspace_id
  ))
);

-- ---------------------------------------------------------------------------
-- 8. Default privileges: private functions are not callable unless granted
-- ---------------------------------------------------------------------------
alter default privileges in schema private revoke execute on functions from public;
revoke all on function private.valid_webhook_url(text) from public, anon;
grant execute on function private.valid_webhook_url(text) to authenticated;

-- ---------------------------------------------------------------------------
-- 9. One row per live item with its head revision (RLS applies via security_invoker)
-- ---------------------------------------------------------------------------
create or replace view public.vault_item_heads with (security_invoker = true) as
  select i.id, i.tenant_id, i.workspace_id, i.content_type, i.schema_version, i.head_revision,
    i.deleted_at, i.updated_at, r.nonce, r.ciphertext, r.aad_hash, r.key_version
  from public.vault_items i
  join public.vault_item_revisions r on r.item_id = i.id and r.revision = i.head_revision;
revoke all on public.vault_item_heads from anon, public;
grant select on public.vault_item_heads to authenticated;

create index if not exists vault_items_workspace_updated_idx
  on public.vault_items (tenant_id, workspace_id, updated_at desc);

-- ---------------------------------------------------------------------------
-- 10. Tenant SMS verification: atomic rate limit and attempt counting
-- ---------------------------------------------------------------------------
create or replace function private.create_sms_verification_challenge(
  p_id uuid, p_tenant_id uuid, p_identity_id uuid, p_code_sha256 bytea, p_phone_sha256 bytea
) returns boolean language plpgsql volatile security definer set search_path = ''
as $$
begin
  -- Serialise per identity and per tenant so parallel requests cannot pass the limits.
  perform pg_advisory_xact_lock(hashtextextended('px-sms-identity:' || p_identity_id::text, 0));
  perform pg_advisory_xact_lock(hashtextextended('px-sms-tenant:' || p_tenant_id::text, 0));
  if (select count(*) from public.sms_verification_challenges c
      where c.identity_id = p_identity_id and c.created_at > now() - interval '1 hour') >= 5 then
    return false;
  end if;
  if (select count(*) from public.sms_verification_challenges c
      where c.tenant_id = p_tenant_id and c.created_at > now() - interval '1 hour') >= 60 then
    return false;
  end if;
  insert into public.sms_verification_challenges (id, tenant_id, identity_id, code_sha256, phone_sha256)
  values (p_id, p_tenant_id, p_identity_id, p_code_sha256, p_phone_sha256);
  return true;
end
$$;
revoke all on function private.create_sms_verification_challenge(uuid,uuid,uuid,bytea,bytea) from public, anon, authenticated;
grant execute on function private.create_sms_verification_challenge(uuid,uuid,uuid,bytea,bytea) to service_role;

-- Every guess consumes one attempt under a row lock, including the correct one.
create or replace function private.check_sms_verification_code(
  p_id uuid, p_tenant_id uuid, p_identity_id uuid, p_candidate_sha256 bytea
) returns table (outcome text, phone_sha256 bytea)
language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.sms_verification_challenges%rowtype;
begin
  update public.sms_verification_challenges c set attempts = c.attempts + 1
    where c.id = p_id and c.tenant_id = p_tenant_id and c.identity_id = p_identity_id
      and c.status = 'pending' and c.expires_at > now() and c.attempts < 5
    returning c.* into v_row;
  if not found then
    return query select 'expired'::text, null::bytea; return;
  end if;
  if v_row.code_sha256 = p_candidate_sha256 then
    update public.sms_verification_challenges set status = 'verified', verified_at = now() where id = p_id;
    return query select 'verified'::text, v_row.phone_sha256; return;
  end if;
  if v_row.attempts >= 5 then
    update public.sms_verification_challenges set status = 'failed' where id = p_id;
    return query select 'locked'::text, null::bytea; return;
  end if;
  return query select 'invalid'::text, null::bytea;
end
$$;
revoke all on function private.check_sms_verification_code(uuid,uuid,uuid,bytea) from public, anon, authenticated;
grant execute on function private.check_sms_verification_code(uuid,uuid,uuid,bytea) to service_role;

create or replace function public.create_sms_verification_challenge(
  p_id uuid, p_tenant_id uuid, p_identity_id uuid, p_code_sha256 bytea, p_phone_sha256 bytea
) returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.create_sms_verification_challenge(p_id, p_tenant_id, p_identity_id, p_code_sha256, p_phone_sha256) $$;
create or replace function public.check_sms_verification_code(
  p_id uuid, p_tenant_id uuid, p_identity_id uuid, p_candidate_sha256 bytea
) returns table (outcome text, phone_sha256 bytea) language sql volatile security invoker set search_path = ''
as $$ select * from private.check_sms_verification_code(p_id, p_tenant_id, p_identity_id, p_candidate_sha256) $$;
revoke all on function public.create_sms_verification_challenge(uuid,uuid,uuid,bytea,bytea) from public, anon, authenticated;
revoke all on function public.check_sms_verification_code(uuid,uuid,uuid,bytea) from public, anon, authenticated;
grant execute on function public.create_sms_verification_challenge(uuid,uuid,uuid,bytea,bytea) to service_role;
grant execute on function public.check_sms_verification_code(uuid,uuid,uuid,bytea) to service_role;

-- ---------------------------------------------------------------------------
-- 11. Password rotation policy
-- ---------------------------------------------------------------------------
alter table public.organization_policies drop constraint if exists organization_policies_policy_type_check;
alter table public.organization_policies add constraint organization_policies_policy_type_check
  check (policy_type in (
    'passkey_required','device_approval_required','minimum_vault_password',
    'sharing_mode','session_timeout_minutes','export_policy',
    'mfa_required','clipboard_clear_seconds','breach_monitoring','organization_recovery',
    'password_rotation'
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
    when 'password_rotation' then
      return jsonb_typeof(p_config -> 'days') = 'number'
        and (p_config ->> 'days')::numeric between 30 and 730;
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
