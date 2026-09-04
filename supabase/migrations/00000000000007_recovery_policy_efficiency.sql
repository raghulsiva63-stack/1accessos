begin;

-- A single UPDATE policy avoids evaluating two permissive policies for every
-- row.  The transaction-local recovery proof is wrapped in SELECT so Postgres
-- computes it once per statement instead of once per candidate row.
drop policy if exists crypto_profile_legacy_recovery_init on public.account_crypto_profiles;
drop policy if exists crypto_profile_recovery_rotate on public.account_crypto_profiles;

create policy crypto_profile_recovery_update
on public.account_crypto_profiles
for update
to authenticated
using (
  identity_id = (select private.current_identity_id())
  and (
    recovery_verifier is null
    or recovery_verifier = decode(
      coalesce((select current_setting('request.passkey_x_recovery_proof', true)), ''),
      'hex'
    )
  )
)
with check (
  identity_id = (select private.current_identity_id())
  and recovery_verifier is not null
);

commit;
