begin;

-- Referrals: "give a month, get a month".
-- Each person has one invite code. A friend who signs up with it (within 14 days of creating
-- their account, and before paying for anything) gets a 30-day first trial; once the friend's
-- first real payment goes through, the inviter gets one month of their own plan as Stripe
-- account credit. Stripe side effects happen only in the service-role Edge Functions; browsers
-- can only read their own code and totals and claim a code for themselves.
create table public.referral_codes (
  identity_id uuid primary key references public.identities(id) on delete cascade,
  code text not null unique check (code ~ '^[A-HJ-NP-Z2-9]{8}$'),
  created_at timestamptz not null default now()
);

create table public.referrals (
  id uuid primary key default gen_random_uuid(),
  referrer_identity_id uuid not null references public.identities(id) on delete cascade,
  referred_identity_id uuid not null unique references public.identities(id) on delete cascade,
  status text not null default 'signed_up' check (status in ('signed_up','converted','rewarded')),
  created_at timestamptz not null default now(),
  converted_at timestamptz,
  rewarded_at timestamptz,
  reward_amount_minor integer check (reward_amount_minor is null or reward_amount_minor > 0),
  reward_currency text check (reward_currency is null or reward_currency in ('inr','usd')),
  stripe_balance_transaction_id text check (stripe_balance_transaction_id is null or stripe_balance_transaction_id ~ '^cbtxn_[A-Za-z0-9]+$'),
  check (referrer_identity_id <> referred_identity_id)
);
create index referrals_referrer_idx on public.referrals(referrer_identity_id, status);

alter table public.referral_codes enable row level security;
alter table public.referrals enable row level security;
revoke all on public.referral_codes, public.referrals from public, anon, authenticated;
grant select, insert, update, delete on public.referral_codes, public.referrals to service_role;
create policy referral_codes_deny_clients on public.referral_codes for all to anon, authenticated using (false) with check (false);
create policy referrals_deny_clients on public.referrals for all to anon, authenticated using (false) with check (false);

-- Your own invite code, created on first use. Codes avoid look-alike characters (0/O, 1/I).
create or replace function private.my_referral_code()
returns text language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_code text;
  v_alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  v_attempt integer := 0;
begin
  if v_actor is null then raise exception 'authentication required' using errcode = '42501'; end if;
  select code into v_code from public.referral_codes where identity_id = v_actor;
  if found then return v_code; end if;
  loop
    v_attempt := v_attempt + 1;
    select string_agg(substr(v_alphabet, 1 + (get_byte(extensions.gen_random_bytes(1), 0) % 32), 1), '')
      into v_code from generate_series(1, 8);
    begin
      insert into public.referral_codes(identity_id, code) values (v_actor, v_code);
      return v_code;
    exception when unique_violation then
      select code into v_code from public.referral_codes where identity_id = v_actor;
      if found then return v_code; end if;
      if v_attempt >= 5 then raise; end if;
    end;
  end loop;
end
$$;

-- Claim a friend's code for yourself. Returns a short status the app can explain.
create or replace function private.claim_referral(p_code text)
returns text language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_referrer uuid;
  v_created timestamptz;
begin
  if v_actor is null then raise exception 'authentication required' using errcode = '42501'; end if;
  if p_code is null or upper(btrim(p_code)) !~ '^[A-HJ-NP-Z2-9]{8}$' then return 'invalid_code'; end if;
  select identity_id into v_referrer from public.referral_codes where code = upper(btrim(p_code));
  if not found then return 'invalid_code'; end if;
  if v_referrer = v_actor then return 'self'; end if;
  if exists (select 1 from public.referrals where referred_identity_id = v_actor) then return 'already_referred'; end if;
  select created_at into v_created from public.identities where id = v_actor;
  if v_created < now() - interval '14 days' then return 'too_late'; end if;
  if exists (
    select 1 from public.billing_subscriptions subscription
    join public.tenant_memberships membership on membership.tenant_id = subscription.tenant_id
    where membership.identity_id = v_actor and membership.role = 'owner'
  ) then return 'already_paying'; end if;
  insert into public.referrals(referrer_identity_id, referred_identity_id) values (v_referrer, v_actor)
    on conflict (referred_identity_id) do nothing;
  return 'claimed';
end
$$;

-- Your code and how your invitations are doing. No names or emails of the people you invited.
create or replace function private.my_referral_summary()
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
begin
  if v_actor is null then raise exception 'authentication required' using errcode = '42501'; end if;
  return jsonb_build_object(
    'code', private.my_referral_code(),
    'joined', (select count(*) from public.referrals where referrer_identity_id = v_actor),
    'paid', (select count(*) from public.referrals where referrer_identity_id = v_actor and status in ('converted','rewarded')),
    'rewarded', (select count(*) from public.referrals where referrer_identity_id = v_actor and status = 'rewarded'),
    'credits', coalesce((
      select jsonb_object_agg(reward_currency, total) from (
        select reward_currency, sum(reward_amount_minor) as total from public.referrals
        where referrer_identity_id = v_actor and status = 'rewarded' group by reward_currency
      ) totals
    ), '{}'::jsonb),
    'referred', exists (select 1 from public.referrals where referred_identity_id = v_actor)
  );
end
$$;

revoke all on function private.my_referral_code(), private.claim_referral(text), private.my_referral_summary() from public, anon;
grant execute on function private.my_referral_code(), private.claim_referral(text), private.my_referral_summary() to authenticated;

create function public.claim_referral(p_code text) returns text
language sql volatile security invoker set search_path = ''
as $$ select private.claim_referral(p_code) $$;
create function public.my_referral_summary() returns jsonb
language sql volatile security invoker set search_path = ''
as $$ select private.my_referral_summary() $$;
revoke all on function public.claim_referral(text), public.my_referral_summary() from public, anon;
grant execute on function public.claim_referral(text), public.my_referral_summary() to authenticated;

commit;
