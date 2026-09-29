-- AI Security Coach admission for every plan, and the monthly allowance refill.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('a8000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','coach-owner@example.invalid',now(),'',now(),now()),
  ('a8000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','coach-other@example.invalid',now(),'',now(),now());

create temporary table coach (actor text primary key, bootstrap jsonb) on commit drop;
grant all on coach to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000001',true);
insert into coach values ('owner', public.bootstrap_personal_vault(
  decode(repeat('31',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'), decode(repeat('34',12),'hex'), decode(repeat('35',48),'hex'),
  decode(repeat('36',32),'hex'), decode(repeat('37',12),'hex'), decode(repeat('38',48),'hex'), decode(repeat('39',65),'hex')));
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000002',true);
insert into coach values ('other', public.bootstrap_personal_vault(
  decode(repeat('41',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('42',12),'hex'), decode(repeat('43',48),'hex'), decode(repeat('44',12),'hex'), decode(repeat('45',48),'hex'),
  decode(repeat('46',32),'hex'), decode(repeat('47',12),'hex'), decode(repeat('48',48),'hex'), decode(repeat('49',65),'hex')));

-- 1. A Free member can use the coach on their own tenant; it costs one credit.
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000001',true);
select public.begin_ai_assistant_request(((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid,
  'vault_health', decode(repeat('ab',32),'hex'), array['vault_health_counts']);
reset role;
do $$ begin
  if (select ai_credits_remaining from public.tenant_entitlements
      where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid) <> 19 then
    raise exception 'coach request did not consume exactly one credit';
  end if;
end $$;

-- 1b. A request that fails at the provider refunds its credit.
set local role authenticated;
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000001',true);
select public.complete_ai_assistant_request(public.begin_ai_assistant_request(
  ((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid,
  'vault_health', decode(repeat('ac',32),'hex'), array['vault_health_counts']), 'failed', 0, 0, 'provider_unavailable');
reset role;
do $$ begin
  if (select ai_credits_remaining from public.tenant_entitlements
      where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid) <> 19 then
    raise exception 'failed coach request was not refunded';
  end if;
end $$;

-- 2. The coach cannot run on someone else's tenant, or with business context categories.
set local role authenticated;
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000001',true);
do $$ begin
  perform public.begin_ai_assistant_request(((select bootstrap ->> 'tenant_id' from coach where actor='other'))::uuid,
    'vault_health', decode(repeat('ab',32),'hex'), array['vault_health_counts']);
  raise exception 'coach ran on a foreign tenant';
exception when insufficient_privilege then null;
end $$;
do $$ begin
  perform public.begin_ai_assistant_request(((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid,
    'vault_health', decode(repeat('ab',32),'hex'), array['tenant_counts']);
  raise exception 'coach accepted non-vault context';
exception when invalid_parameter_value then null;
end $$;
-- 3. The Business advisor stays Business-only.
do $$ begin
  perform public.begin_ai_assistant_request(((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid,
    'security_posture', decode(repeat('ab',32),'hex'), array['tenant_counts']);
  raise exception 'business advisor ran on a free personal tenant';
exception when insufficient_privilege then null;
end $$;

-- 4. No credits left: refused.
reset role;
update public.tenant_entitlements set ai_credits_remaining = 0
  where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid;
set local role authenticated;
select set_config('request.jwt.claim.sub','a8000000-0000-4000-8000-000000000001',true);
do $$ begin
  perform public.begin_ai_assistant_request(((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid,
    'vault_health', decode(repeat('ab',32),'hex'), array['vault_health_counts']);
  raise exception 'coach ran without credits';
exception when program_limit_exceeded then null;
end $$;

-- 5. Browsers cannot trigger the refill.
do $$ begin
  perform private.refill_monthly_allowances();
  raise exception 'authenticated user refilled allowances';
exception when insufficient_privilege then null;
end $$;
reset role;

-- 6. The monthly refill restores Free to 20/50 and a paid plan to its allowance.
update public.tenant_entitlements set plan_code = 'personal', source = 'stripe', subscription_status = 'active',
  ai_credits_remaining = 3, automation_runs_remaining = 1
  where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='other'))::uuid;
select private.refill_monthly_allowances();
do $$ begin
  if (select ai_credits_remaining from public.tenant_entitlements
      where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='owner'))::uuid) <> 20 then
    raise exception 'free tenant was not refilled to 20 credits';
  end if;
  if (select (ai_credits_remaining, automation_runs_remaining) from public.tenant_entitlements
      where tenant_id = ((select bootstrap ->> 'tenant_id' from coach where actor='other'))::uuid) is distinct from (250, 500) then
    raise exception 'personal plan was not refilled to its allowance';
  end if;
  if not exists (select 1 from cron.job where jobname = 'px-refill-monthly-allowances') then
    raise exception 'monthly refill is not scheduled';
  end if;
end $$;

rollback;
