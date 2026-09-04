begin;

-- Move all authenticated public RPCs to SECURITY INVOKER. Narrow bootstrap
-- grants plus RLS provide the transaction boundary without bypassing caller RLS.
create or replace function private.owns_personal_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.tenants t
    where t.id = target_tenant
      and t.kind = 'personal'
      and t.created_by = private.current_identity_id()
  )
$$;

create or replace function private.owns_personal_workspace(target_tenant uuid, target_workspace uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.workspaces w
    where w.tenant_id = target_tenant
      and w.id = target_workspace
      and w.created_by = private.current_identity_id()
      and private.owns_personal_tenant(target_tenant)
  )
$$;

revoke all on function private.owns_personal_tenant(uuid) from public, anon;
revoke all on function private.owns_personal_workspace(uuid,uuid) from public, anon;
grant execute on function private.owns_personal_tenant(uuid) to authenticated;
grant execute on function private.owns_personal_workspace(uuid,uuid) to authenticated;

create or replace function private.can_register_device(target_identity uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select target_identity = private.current_identity_id()
    and (
      select count(*) from public.devices d
      where d.identity_id = target_identity and d.status <> 'revoked'
    ) < case
          when coalesce((select e.plan_code from public.account_entitlements e where e.identity_id = target_identity), 'free') = 'personal'
          then 2147483647
          else 2
        end
$$;

revoke all on function private.can_register_device(uuid) from public, anon;
grant execute on function private.can_register_device(uuid) to authenticated;

drop policy if exists devices_insert_self on public.devices;
create policy devices_insert_self on public.devices for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and status = 'trusted'
  and revoked_at is null
  and (select private.can_register_device(identity_id))
);

grant insert (id, auth_user_id, kind, status) on public.identities to authenticated;
grant insert (id, kind, created_by) on public.tenants to authenticated;
grant insert (tenant_id, identity_id, role, status) on public.tenant_memberships to authenticated;
grant insert (id, tenant_id, kind, created_by) on public.workspaces to authenticated;
grant insert (tenant_id, workspace_id, identity_id, role, status) on public.workspace_memberships to authenticated;
grant insert (identity_id, salt, kdf_parameters, master_nonce, master_wrapped_root,
  recovery_nonce, recovery_wrapped_root, recovery_verifier)
on public.account_crypto_profiles to authenticated;

create policy identities_bootstrap_self on public.identities for insert to authenticated
with check (
  auth_user_id = (select auth.uid())
  and kind = 'human'
  and status = 'active'
);

create policy tenants_bootstrap_personal on public.tenants for insert to authenticated
with check (
  kind = 'personal'
  and created_by = (select private.current_identity_id())
);

create policy tenant_memberships_bootstrap_owner on public.tenant_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and role = 'owner'
  and status = 'active'
  and (select private.owns_personal_tenant(tenant_id))
);

create policy workspaces_bootstrap_personal on public.workspaces for insert to authenticated
with check (
  kind = 'vault'
  and created_by = (select private.current_identity_id())
  and (select private.owns_personal_tenant(tenant_id))
);

create policy workspace_memberships_bootstrap_owner on public.workspace_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and role = 'owner'
  and status = 'active'
  and (select private.owns_personal_workspace(tenant_id, workspace_id))
);

create policy crypto_profile_bootstrap_self on public.account_crypto_profiles for insert to authenticated
with check (identity_id = (select private.current_identity_id()));

revoke all on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea)
from public, anon, authenticated;
drop function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea);

create function public.bootstrap_personal_vault(
  p_salt bytea,
  p_kdf_parameters jsonb,
  p_master_nonce bytea,
  p_master_wrapped_root bytea,
  p_recovery_nonce bytea,
  p_recovery_wrapped_root bytea,
  p_recovery_verifier bytea,
  p_workspace_nonce bytea,
  p_workspace_wrapped_key bytea,
  p_device_public_key bytea
) returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_auth_user uuid := auth.uid();
  v_identity uuid := gen_random_uuid();
  v_tenant uuid := gen_random_uuid();
  v_workspace uuid := gen_random_uuid();
  v_device uuid := gen_random_uuid();
begin
  if v_auth_user is null then raise exception 'authentication required' using errcode = '28000'; end if;
  if exists (select 1 from public.identities where auth_user_id = v_auth_user) then raise exception 'account already initialized' using errcode = '23505'; end if;
  if octet_length(p_salt) <> 16 or octet_length(p_master_nonce) <> 12 or octet_length(p_recovery_nonce) <> 12 or octet_length(p_recovery_verifier) <> 32 or octet_length(p_workspace_nonce) <> 12 then raise exception 'invalid cryptographic parameter length' using errcode = '22023'; end if;
  if octet_length(p_master_wrapped_root) < 48 or octet_length(p_recovery_wrapped_root) < 48 or octet_length(p_workspace_wrapped_key) < 48 or octet_length(p_device_public_key) < 33 then raise exception 'invalid encrypted key material' using errcode = '22023'; end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID' or (p_kdf_parameters ->> 'memoryKib')::integer < 8192 or (p_kdf_parameters ->> 'iterations')::integer < 1 or (p_kdf_parameters ->> 'parallelism')::integer < 1 or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then raise exception 'invalid KDF profile' using errcode = '22023'; end if;

  insert into public.identities(id, auth_user_id, kind) values (v_identity, v_auth_user, 'human');
  insert into public.tenants(id, kind, created_by) values (v_tenant, 'personal', v_identity);
  insert into public.tenant_memberships(tenant_id, identity_id, role) values (v_tenant, v_identity, 'owner');
  insert into public.workspaces(id, tenant_id, kind, created_by) values (v_workspace, v_tenant, 'vault', v_identity);
  insert into public.workspace_memberships(tenant_id, workspace_id, identity_id, role) values (v_tenant, v_workspace, v_identity, 'owner');
  insert into public.devices(id, identity_id, public_key, status, last_seen_at) values (v_device, v_identity, p_device_public_key, 'trusted', now());
  insert into public.account_crypto_profiles(identity_id, salt, kdf_parameters, master_nonce, master_wrapped_root, recovery_nonce, recovery_wrapped_root, recovery_verifier)
  values (v_identity, p_salt, p_kdf_parameters, p_master_nonce, p_master_wrapped_root, p_recovery_nonce, p_recovery_wrapped_root, p_recovery_verifier);
  insert into public.key_envelopes(tenant_id, workspace_id, key_kind, key_version, recipient_identity_id, algorithm, nonce, wrapped_key)
  values (v_tenant, v_workspace, 'workspace', 1, v_identity, 'AES-256-GCM', p_workspace_nonce, p_workspace_wrapped_key);

  return jsonb_build_object('identity_id', v_identity, 'tenant_id', v_tenant, 'workspace_id', v_workspace, 'device_id', v_device);
end
$$;

revoke all on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea) from public, anon;
grant execute on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea) to authenticated;

alter function public.set_recovery_verifier_once(bytea)
security invoker;

grant update (recovery_verifier, updated_at)
on public.account_crypto_profiles to authenticated;

create policy crypto_profile_legacy_recovery_init on public.account_crypto_profiles for update to authenticated
using (
  identity_id = (select private.current_identity_id())
  and recovery_verifier is null
)
with check (
  identity_id = (select private.current_identity_id())
  and recovery_verifier is not null
);

alter function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea)
security invoker;

grant update (salt, kdf_parameters, master_nonce, master_wrapped_root, updated_at)
on public.account_crypto_profiles to authenticated;

create policy crypto_profile_recovery_rotate on public.account_crypto_profiles for update to authenticated
using (
  identity_id = (select private.current_identity_id())
  and recovery_verifier = decode(coalesce(current_setting('request.passkey_x_recovery_proof', true), ''), 'hex')
)
with check (identity_id = (select private.current_identity_id()));

create or replace function public.rotate_master_with_recovery(
  p_recovery_verifier bytea,
  p_salt bytea,
  p_kdf_parameters jsonb,
  p_master_nonce bytea,
  p_master_wrapped_root bytea
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'authentication required' using errcode = '28000'; end if;
  if octet_length(p_recovery_verifier) <> 32 or octet_length(p_salt) <> 16 or octet_length(p_master_nonce) <> 12 or octet_length(p_master_wrapped_root) < 48 then raise exception 'invalid cryptographic parameter length' using errcode = '22023'; end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID' or (p_kdf_parameters ->> 'memoryKib')::integer < 8192 or (p_kdf_parameters ->> 'iterations')::integer < 1 or (p_kdf_parameters ->> 'parallelism')::integer < 1 or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then raise exception 'invalid KDF profile' using errcode = '22023'; end if;

  perform set_config('request.passkey_x_recovery_proof', encode(p_recovery_verifier, 'hex'), true);
  update public.account_crypto_profiles
  set salt = p_salt,
      kdf_parameters = p_kdf_parameters,
      master_nonce = p_master_nonce,
      master_wrapped_root = p_master_wrapped_root,
      updated_at = now()
  where identity_id = private.current_identity_id();

  if not found then raise exception 'recovery proof rejected' using errcode = '28000'; end if;
end
$$;

revoke all on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea) from public, anon;
grant execute on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea) to authenticated;

comment on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea)
is 'Atomic caller-RLS bootstrap for a single personal identity, tenant, workspace, entitlement, device and encrypted key hierarchy.';
comment on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea)
is 'SECURITY INVOKER recovery rotation; a transaction-local proof unlocks only the caller own RLS row.';
comment on function public.set_recovery_verifier_once(bytea)
is 'One-time SECURITY INVOKER upgrade path for profiles created before recovery proofs were introduced.';

commit;
