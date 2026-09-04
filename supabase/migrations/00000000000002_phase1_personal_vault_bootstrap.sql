begin;

create table public.account_crypto_profiles (
  identity_id uuid primary key references public.identities(id) on delete cascade,
  salt bytea not null check (octet_length(salt) = 16),
  kdf_parameters jsonb not null,
  master_nonce bytea not null check (octet_length(master_nonce) = 12),
  master_wrapped_root bytea not null check (octet_length(master_wrapped_root) >= 48),
  recovery_nonce bytea not null check (octet_length(recovery_nonce) = 12),
  recovery_wrapped_root bytea not null check (octet_length(recovery_wrapped_root) >= 48),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (kdf_parameters ->> 'algorithm' = 'ARGON2ID'),
  check ((kdf_parameters ->> 'memoryKib')::integer >= 8192),
  check ((kdf_parameters ->> 'iterations')::integer >= 1),
  check ((kdf_parameters ->> 'parallelism')::integer >= 1),
  check ((kdf_parameters ->> 'hashLength')::integer = 32)
);

alter table public.account_crypto_profiles enable row level security;
revoke all on public.account_crypto_profiles from anon, authenticated;
grant select on public.account_crypto_profiles to authenticated;

create policy crypto_profile_read_self on public.account_crypto_profiles
for select to authenticated
using (identity_id = (select private.current_identity_id()));

create or replace function public.bootstrap_personal_vault(
  p_salt bytea,
  p_kdf_parameters jsonb,
  p_master_nonce bytea,
  p_master_wrapped_root bytea,
  p_recovery_nonce bytea,
  p_recovery_wrapped_root bytea,
  p_workspace_nonce bytea,
  p_workspace_wrapped_key bytea,
  p_device_public_key bytea
) returns jsonb
language plpgsql
security definer
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
  if octet_length(p_salt) <> 16 or octet_length(p_master_nonce) <> 12 or octet_length(p_recovery_nonce) <> 12 or octet_length(p_workspace_nonce) <> 12 then raise exception 'invalid cryptographic parameter length' using errcode = '22023'; end if;
  if octet_length(p_master_wrapped_root) < 48 or octet_length(p_recovery_wrapped_root) < 48 or octet_length(p_workspace_wrapped_key) < 48 or octet_length(p_device_public_key) < 33 then raise exception 'invalid encrypted key material' using errcode = '22023'; end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID' or (p_kdf_parameters ->> 'memoryKib')::integer < 8192 or (p_kdf_parameters ->> 'iterations')::integer < 1 or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then raise exception 'invalid KDF profile' using errcode = '22023'; end if;

  insert into public.identities(id, auth_user_id, kind) values (v_identity, v_auth_user, 'human');
  insert into public.tenants(id, kind, created_by) values (v_tenant, 'personal', v_identity);
  insert into public.tenant_memberships(tenant_id, identity_id, role) values (v_tenant, v_identity, 'owner');
  insert into public.workspaces(id, tenant_id, kind, created_by) values (v_workspace, v_tenant, 'vault', v_identity);
  insert into public.workspace_memberships(tenant_id, workspace_id, identity_id, role) values (v_tenant, v_workspace, v_identity, 'owner');
  insert into public.devices(id, identity_id, public_key, status, last_seen_at) values (v_device, v_identity, p_device_public_key, 'trusted', now());
  insert into public.account_crypto_profiles(identity_id, salt, kdf_parameters, master_nonce, master_wrapped_root, recovery_nonce, recovery_wrapped_root)
  values (v_identity, p_salt, p_kdf_parameters, p_master_nonce, p_master_wrapped_root, p_recovery_nonce, p_recovery_wrapped_root);
  insert into public.key_envelopes(tenant_id, workspace_id, key_kind, key_version, recipient_identity_id, algorithm, nonce, wrapped_key)
  values (v_tenant, v_workspace, 'workspace', 1, v_identity, 'AES-256-GCM', p_workspace_nonce, p_workspace_wrapped_key);

  return jsonb_build_object('identity_id', v_identity, 'tenant_id', v_tenant, 'workspace_id', v_workspace, 'device_id', v_device);
end
$$;

revoke all on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea) from public, anon;
grant execute on function public.bootstrap_personal_vault(bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea) to authenticated;

commit;

