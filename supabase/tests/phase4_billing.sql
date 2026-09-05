begin;

insert into auth.users (
  id, instance_id, aud, role, email, email_confirmed_at,
  encrypted_password, created_at, updated_at
) values
  ('81000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','billing-owner@example.invalid',now(),'',now(),now()),
  ('82000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','billing-outsider@example.invalid',now(),'',now(),now());

insert into public.identities(id, auth_user_id, kind)
values
  ('81100000-0000-4000-8000-000000000001','81000000-0000-4000-8000-000000000001','human'),
  ('82100000-0000-4000-8000-000000000002','82000000-0000-4000-8000-000000000002','human');

insert into public.tenants(id, kind, created_by)
values
  ('81200000-0000-4000-8000-000000000001','family','81100000-0000-4000-8000-000000000001'),
  ('82200000-0000-4000-8000-000000000002','personal','82100000-0000-4000-8000-000000000002');

insert into public.tenant_memberships(tenant_id, identity_id, role, status)
values
  ('81200000-0000-4000-8000-000000000001','81100000-0000-4000-8000-000000000001','owner','active'),
  ('82200000-0000-4000-8000-000000000002','82100000-0000-4000-8000-000000000002','owner','active');

do $$ begin
  if (select count(*) from public.tenant_entitlements
      where tenant_id in ('81200000-0000-4000-8000-000000000001','82200000-0000-4000-8000-000000000002')) <> 2 then
    raise exception 'Phase 4 provisioning failure: free entitlement missing';
  end if;
end $$;

do $$ begin
  insert into public.tenant_memberships(tenant_id, identity_id, role, status)
  values ('81200000-0000-4000-8000-000000000001','82100000-0000-4000-8000-000000000002','member','active');
  raise exception 'Phase 4 entitlement failure: Free member limit was bypassed';
exception when check_violation then null;
end $$;

insert into public.workspaces(id, tenant_id, kind, created_by, status)
values ('81300000-0000-4000-8000-000000000001','81200000-0000-4000-8000-000000000001','shared','81100000-0000-4000-8000-000000000001','active');

do $$ begin
  insert into public.workspaces(id, tenant_id, kind, created_by, status)
  values ('81300000-0000-4000-8000-000000000002','81200000-0000-4000-8000-000000000001','shared','81100000-0000-4000-8000-000000000001','active');
  raise exception 'Phase 4 entitlement failure: Free workspace limit was bypassed';
exception when check_violation then null;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','81000000-0000-4000-8000-000000000001',true);

do $$ begin
  if (select count(*) from public.tenant_entitlements
      where tenant_id='81200000-0000-4000-8000-000000000001') <> 1
    or exists (select 1 from public.tenant_entitlements
      where tenant_id='82200000-0000-4000-8000-000000000002') then
    raise exception 'Phase 4 RLS failure: entitlement crossed tenant boundary';
  end if;
end $$;

do $$ begin
  perform 1 from public.billing_customers limit 1;
  raise exception 'Phase 4 grant failure: browser role queried billing customers';
exception when insufficient_privilege then null;
end $$;

set local role service_role;

do $$ begin
  if not public.apply_stripe_billing_event_checked(
    'evt_phase4activate001','customer.subscription.updated','2026-07-29.dahlia',
    decode(repeat('aa',32),'hex'),false,
    '81200000-0000-4000-8000-000000000001','cus_phase4customer001',
    'sub_phase4subscription001','prod_phase4family001','price_phase4familyinr001',
    'family','month','inr','active',1,
    now(),now()+interval '1 month',false,null
  ) then
    raise exception 'Phase 4 webhook failure: first event was not applied';
  end if;
end $$;

do $$ begin
  if public.apply_stripe_billing_event_checked(
    'evt_phase4activate001','customer.subscription.updated','2026-07-29.dahlia',
    decode(repeat('aa',32),'hex'),false,
    '81200000-0000-4000-8000-000000000001','cus_phase4customer001',
    'sub_phase4subscription001','prod_phase4family001','price_phase4familyinr001',
    'family','month','inr','active',1,
    now(),now()+interval '1 month',false,null
  ) then
    raise exception 'Phase 4 replay failure: duplicate event was applied';
  end if;
  if (select delivery_count from public.billing_events where stripe_event_id='evt_phase4activate001') <> 2 then
    raise exception 'Phase 4 replay failure: delivery count missing';
  end if;
  if (select plan_code from public.tenant_entitlements where tenant_id='81200000-0000-4000-8000-000000000001') <> 'family' then
    raise exception 'Phase 4 entitlement failure: paid plan not activated';
  end if;
end $$;

do $$ begin
  perform public.apply_stripe_billing_event_checked(
    'evt_phase4activate001','customer.subscription.updated','2026-07-29.dahlia',
    decode(repeat('cc',32),'hex'),false,
    '81200000-0000-4000-8000-000000000001','cus_phase4customer001',
    'sub_phase4subscription001','prod_phase4family001','price_phase4familyinr001',
    'family','month','inr','active',1,
    now(),now()+interval '1 month',false,null
  );
  raise exception 'Phase 4 integrity failure: changed duplicate payload was accepted';
exception when check_violation then null;
end $$;

do $$ begin
  perform public.apply_stripe_billing_event_checked(
    'evt_phase4wrongmode001','customer.subscription.updated','2026-07-29.dahlia',
    decode(repeat('dd',32),'hex'),true,
    '81200000-0000-4000-8000-000000000001','cus_phase4customer001',
    'sub_phase4subscription001','prod_phase4family001','price_phase4familyinr001',
    'family','month','inr','active',1,
    now(),now()+interval '1 month',false,null
  );
  raise exception 'Phase 4 integrity failure: live/test mode mixing was accepted';
exception when check_violation then null;
end $$;

select public.apply_stripe_billing_event_checked(
  'evt_phase4cancel001','customer.subscription.deleted','2026-07-29.dahlia',
  decode(repeat('bb',32),'hex'),false,
  '81200000-0000-4000-8000-000000000001','cus_phase4customer001',
  'sub_phase4subscription001','prod_phase4family001','price_phase4familyinr001',
  'family','month','inr','canceled',1,
  now()-interval '1 month',now(),false,now()
);

do $$ begin
  if (select plan_code from public.tenant_entitlements where tenant_id='81200000-0000-4000-8000-000000000001') <> 'free'
    or (select subscription_status from public.tenant_entitlements where tenant_id='81200000-0000-4000-8000-000000000001') <> 'canceled' then
    raise exception 'Phase 4 cancellation failure: free fallback missing';
  end if;
end $$;

rollback;
