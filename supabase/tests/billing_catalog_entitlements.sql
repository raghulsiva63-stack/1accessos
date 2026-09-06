begin;

insert into auth.users (
  id, instance_id, aud, role, email, email_confirmed_at,
  encrypted_password, created_at, updated_at
) values
  ('91000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','catalog-team@example.invalid',now(),'',now(),now()),
  ('92000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','catalog-pro@example.invalid',now(),'',now(),now());

insert into public.identities(id, auth_user_id, kind)
values
  ('91100000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001','human'),
  ('92100000-0000-4000-8000-000000000002','92000000-0000-4000-8000-000000000002','human');

insert into public.tenants(id, kind, created_by)
values
  ('91200000-0000-4000-8000-000000000001','organization','91100000-0000-4000-8000-000000000001'),
  ('92200000-0000-4000-8000-000000000002','personal','92100000-0000-4000-8000-000000000002');

insert into public.tenant_memberships(tenant_id, identity_id, role, status)
values
  ('91200000-0000-4000-8000-000000000001','91100000-0000-4000-8000-000000000001','owner','active'),
  ('92200000-0000-4000-8000-000000000002','92100000-0000-4000-8000-000000000002','owner','active');

set local role service_role;

select public.apply_stripe_billing_event_checked(
  'evt_catalogteam001','customer.subscription.updated','2026-07-29.dahlia',
  decode(repeat('11',32),'hex'),false,
  '91200000-0000-4000-8000-000000000001','cus_catalogteam001',
  'sub_catalogteam001','prod_catalogteam001','price_catalogteam001',
  'team','month','inr','active',3,
  now(),now()+interval '1 month',false,null
);

do $$
begin
  if not exists (
    select 1 from public.tenant_entitlements
    where tenant_id='91200000-0000-4000-8000-000000000001'
      and plan_code='team' and max_members=3
      and ai_credits_remaining=1800 and automation_runs_remaining=6000
  ) then
    raise exception 'Team seat quantity did not scale entitlements exactly';
  end if;
end
$$;

do $$
begin
  perform public.apply_stripe_billing_event_checked(
    'evt_catalogbadqty001','customer.subscription.updated','2026-07-29.dahlia',
    decode(repeat('22',32),'hex'),false,
    '92200000-0000-4000-8000-000000000002','cus_catalogpro001',
    'sub_catalogbadqty001','prod_catalogbusiness001','price_catalogbusiness001',
    'business','month','inr','active',4,
    now(),now()+interval '1 month',false,null
  );
  raise exception 'Business subscription below five seats was accepted';
exception when invalid_parameter_value then
  null;
end
$$;

select public.apply_stripe_billing_event_checked(
  'evt_catalogpro001','customer.subscription.updated','2026-07-29.dahlia',
  decode(repeat('33',32),'hex'),false,
  '92200000-0000-4000-8000-000000000002','cus_catalogpro001',
  'sub_catalogpro001','prod_catalogpro001','price_catalogpro001',
  'professional','year','usd','trialing',1,
  now(),now()+interval '14 days',false,null
);

do $$
begin
  if not exists (
    select 1 from public.tenant_entitlements
    where tenant_id='92200000-0000-4000-8000-000000000002'
      and plan_code='professional' and max_members=1
      and ai_credits_remaining=1000 and automation_runs_remaining=3000
  ) then
    raise exception 'Professional catalog entitlement was not applied';
  end if;
end
$$;

select public.apply_stripe_billing_event_checked(
  'evt_catalogcancel001','customer.subscription.deleted','2026-07-29.dahlia',
  decode(repeat('44',32),'hex'),false,
  '91200000-0000-4000-8000-000000000001','cus_catalogteam001',
  'sub_catalogteam001','prod_catalogteam001','price_catalogteam001',
  'team','month','inr','canceled',3,
  now()-interval '1 month',now(),false,now()
);

do $$
begin
  if not exists (
    select 1 from public.tenant_entitlements
    where tenant_id='91200000-0000-4000-8000-000000000001'
      and plan_code='free' and max_members=1 and max_workspaces=1
      and max_devices=2 and ai_credits_remaining=20
      and automation_runs_remaining=50
  ) then
    raise exception 'Cancellation did not restore exact Free entitlements';
  end if;
end
$$;

rollback;
