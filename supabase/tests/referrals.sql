-- Referral codes, claiming rules and client isolation.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('a9000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','ref-inviter@example.invalid',now(),'',now(),now()),
  ('a9000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','ref-friend@example.invalid',now(),'',now(),now()),
  ('a9000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','ref-late@example.invalid',now(),'',now(),now());

create temporary table ref (actor text primary key, value text) on commit drop;
grant all on ref to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000001',true);
select public.bootstrap_personal_vault(
  decode(repeat('51',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('52',12),'hex'), decode(repeat('53',48),'hex'), decode(repeat('54',12),'hex'), decode(repeat('55',48),'hex'),
  decode(repeat('56',32),'hex'), decode(repeat('57',12),'hex'), decode(repeat('58',48),'hex'), decode(repeat('59',65),'hex'));
insert into ref values ('code', (public.my_referral_summary() ->> 'code'));
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000002',true);
select public.bootstrap_personal_vault(
  decode(repeat('61',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('62',12),'hex'), decode(repeat('63',48),'hex'), decode(repeat('64',12),'hex'), decode(repeat('65',48),'hex'),
  decode(repeat('66',32),'hex'), decode(repeat('67',12),'hex'), decode(repeat('68',48),'hex'), decode(repeat('69',65),'hex'));
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000003',true);
select public.bootstrap_personal_vault(
  decode(repeat('71',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('72',12),'hex'), decode(repeat('73',48),'hex'), decode(repeat('74',12),'hex'), decode(repeat('75',48),'hex'),
  decode(repeat('76',32),'hex'), decode(repeat('77',12),'hex'), decode(repeat('78',48),'hex'), decode(repeat('79',65),'hex'));
reset role;

do $$ declare v_code text := (select value from ref where actor = 'code'); begin
  if v_code !~ '^[A-HJ-NP-Z2-9]{8}$' then raise exception 'bad referral code format: %', v_code; end if;
end $$;

-- 1. The code is stable for its owner.
set local role authenticated;
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000001',true);
do $$ begin
  if (public.my_referral_summary() ->> 'code') <> (select value from ref where actor = 'code') then raise exception 'referral code changed'; end if;
  -- 2. You cannot refer yourself.
  if public.claim_referral((select value from ref where actor = 'code')) <> 'self' then raise exception 'self referral allowed'; end if;
end $$;

-- 3. A new friend can claim once; junk codes are rejected.
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000002',true);
do $$ begin
  if public.claim_referral('not-a-code') <> 'invalid_code' then raise exception 'junk code accepted'; end if;
  if public.claim_referral('ZZZZZZZZ') <> 'invalid_code' then raise exception 'unknown code accepted'; end if;
  if public.claim_referral(lower((select value from ref where actor = 'code'))) <> 'claimed' then raise exception 'valid claim failed'; end if;
  if public.claim_referral((select value from ref where actor = 'code')) <> 'already_referred' then raise exception 'second claim allowed'; end if;
  if (public.my_referral_summary() ->> 'referred')::boolean is not true then raise exception 'friend not marked as referred'; end if;
end $$;

-- 4. Browsers cannot read or write the tables directly.
do $$ begin
  perform 1 from public.referrals;
  raise exception 'client read referrals table';
exception when insufficient_privilege then null;
end $$;
do $$ begin
  insert into public.referrals(referrer_identity_id, referred_identity_id)
    values ((select id from public.identities limit 1), (select id from public.identities limit 1));
  raise exception 'client wrote referrals table';
exception when insufficient_privilege then null;
end $$;

-- 5. Old accounts cannot claim.
reset role;
update public.identities set created_at = now() - interval '30 days'
  where auth_user_id = 'a9000000-0000-4000-8000-000000000003';
set local role authenticated;
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000003',true);
do $$ begin
  if public.claim_referral((select value from ref where actor = 'code')) <> 'too_late' then raise exception 'late claim allowed'; end if;
end $$;

-- 6. The inviter sees totals only.
select set_config('request.jwt.claim.sub','a9000000-0000-4000-8000-000000000001',true);
do $$ declare v jsonb := public.my_referral_summary(); begin
  if (v ->> 'joined')::int <> 1 or (v ->> 'paid')::int <> 0 then raise exception 'unexpected summary %', v; end if;
  if v::text ~* 'example\.invalid' then raise exception 'summary leaked an email'; end if;
end $$;
reset role;

rollback;
