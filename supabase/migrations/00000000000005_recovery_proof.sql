begin;

alter table public.account_crypto_profiles
add column recovery_verifier bytea;

alter table public.account_crypto_profiles
add constraint account_crypto_profiles_recovery_verifier_length
check (recovery_verifier is null or octet_length(recovery_verifier) = 32);

revoke update on public.account_crypto_profiles from authenticated;
drop policy if exists crypto_profile_rotate_self on public.account_crypto_profiles;

create or replace function public.set_recovery_verifier_once(p_verifier bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or octet_length(p_verifier) <> 32 then
    raise exception 'invalid recovery verifier' using errcode = '22023';
  end if;

  update public.account_crypto_profiles p
  set recovery_verifier = p_verifier,
      updated_at = now()
  from public.identities i
  where p.identity_id = i.id
    and i.auth_user_id = auth.uid()
    and i.status = 'active'
    and p.recovery_verifier is null;

  if not found then
    raise exception 'recovery verifier is already configured' using errcode = '23505';
  end if;
end
$$;

create or replace function public.rotate_master_with_recovery(
  p_recovery_verifier bytea,
  p_salt bytea,
  p_kdf_parameters jsonb,
  p_master_nonce bytea,
  p_master_wrapped_root bytea
) returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  if octet_length(p_recovery_verifier) <> 32
    or octet_length(p_salt) <> 16
    or octet_length(p_master_nonce) <> 12
    or octet_length(p_master_wrapped_root) < 48 then
    raise exception 'invalid cryptographic parameter length' using errcode = '22023';
  end if;
  if p_kdf_parameters ->> 'algorithm' <> 'ARGON2ID'
    or (p_kdf_parameters ->> 'memoryKib')::integer < 8192
    or (p_kdf_parameters ->> 'iterations')::integer < 1
    or (p_kdf_parameters ->> 'parallelism')::integer < 1
    or (p_kdf_parameters ->> 'hashLength')::integer <> 32 then
    raise exception 'invalid KDF profile' using errcode = '22023';
  end if;

  update public.account_crypto_profiles p
  set salt = p_salt,
      kdf_parameters = p_kdf_parameters,
      master_nonce = p_master_nonce,
      master_wrapped_root = p_master_wrapped_root,
      updated_at = now()
  from public.identities i
  where p.identity_id = i.id
    and i.auth_user_id = auth.uid()
    and i.status = 'active'
    and p.recovery_verifier = p_recovery_verifier;

  if not found then
    raise exception 'recovery proof rejected' using errcode = '28000';
  end if;
end
$$;

revoke all on function public.set_recovery_verifier_once(bytea) from public, anon;
revoke all on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea) from public, anon;
grant execute on function public.set_recovery_verifier_once(bytea) to authenticated;
grant execute on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea) to authenticated;

comment on function public.set_recovery_verifier_once(bytea)
is 'Registers one client-derived recovery proof after initial vault bootstrap; the proof cannot be replaced.';
comment on function public.rotate_master_with_recovery(bytea,bytea,jsonb,bytea,bytea)
is 'Rotates only the password-derived root wrapper after client-side recovery-key decryption and proof.';

commit;
