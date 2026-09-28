-- Launch readiness: plan-based device limits, Business-only admin features,
-- and the member-only SCIM provisioning offer.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('a7000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','lr-owner@example.invalid',now(),'',now(),now()),
  ('a7000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','lr-joiner@example.invalid',now(),'',now(),now());

create temporary table lr (actor text primary key, bootstrap jsonb) on commit drop;
grant all on lr to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
insert into lr values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000002',true);
insert into lr values ('joiner', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));

-- 1. Free: the bootstrap device plus one more; the third is refused.
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
insert into public.devices (id, identity_id, public_key, status)
values ('a7100000-0000-4000-8000-000000000002', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid,
  decode(repeat('61',65),'hex'), 'trusted');
do $$ begin
  insert into public.devices (id, identity_id, public_key, status)
  values ('a7100000-0000-4000-8000-000000000003', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid,
    decode(repeat('63',65),'hex'), 'trusted');
  raise exception 'Free account registered a third device';
exception when insufficient_privilege then null;
end $$;
reset role;

-- A paid plan on the person's tenant lifts the cap.
update public.tenant_entitlements set plan_code = 'personal', source = 'stripe', subscription_status = 'active',
  max_devices = null, valid_until = now() + interval '30 days'
  where tenant_id = ((select bootstrap ->> 'tenant_id' from lr where actor='owner'))::uuid;
set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
insert into public.devices (id, identity_id, public_key, status)
values ('a7100000-0000-4000-8000-000000000003', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid,
  decode(repeat('65',65),'hex'), 'trusted');
reset role;

-- A canceled subscription brings the Free cap back for new devices.
update public.tenant_entitlements set subscription_status = 'canceled'
  where tenant_id = ((select bootstrap ->> 'tenant_id' from lr where actor='owner'))::uuid;
set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
do $$ begin
  insert into public.devices (id, identity_id, public_key, status)
  values ('a7100000-0000-4000-8000-000000000004', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid,
    decode(repeat('67',65),'hex'), 'trusted');
  raise exception 'Canceled plan still allowed unlimited devices';
exception when insufficient_privilege then null;
end $$;
reset role;

-- 2. Business-only admin features on an organization without Business.
insert into public.tenants (id, kind, created_by) values
  ('a7200000-0000-4000-8000-000000000001', 'organization', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid);
insert into public.tenant_memberships (tenant_id, identity_id, role, status) values
  ('a7200000-0000-4000-8000-000000000001', ((select bootstrap ->> 'identity_id' from lr where actor='owner'))::uuid, 'owner', 'active');
insert into public.tenant_entitlements (tenant_id, plan_code, subscription_status, source, max_members, max_workspaces, max_devices)
values ('a7200000-0000-4000-8000-000000000001', 'team', 'active', 'stripe', 10, 10, null)
on conflict (tenant_id) do update set plan_code = 'team', subscription_status = 'active', source = 'stripe';

set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
do $$ begin
  perform public.organization_compliance_snapshot('a7200000-0000-4000-8000-000000000001');
  raise exception 'Team plan produced a compliance report';
exception when insufficient_privilege then
  if sqlerrm <> 'business plan required' then raise; end if;
end $$;
do $$ begin
  perform * from public.organization_access_review('a7200000-0000-4000-8000-000000000001');
  raise exception 'Team plan ran an access review';
exception when insufficient_privilege then
  if sqlerrm <> 'business plan required' then raise; end if;
end $$;
do $$ begin
  if private.can_manage_audit_webhooks('a7200000-0000-4000-8000-000000000001') then
    raise exception 'Team plan can manage audit streaming';
  end if;
end $$;
reset role;

update public.tenant_entitlements set plan_code = 'business', max_members = 50
  where tenant_id = 'a7200000-0000-4000-8000-000000000001';
set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
do $$ begin
  if not private.can_manage_audit_webhooks('a7200000-0000-4000-8000-000000000001') then
    raise exception 'Business owner cannot manage audit streaming';
  end if;
end $$;
reset role;

-- 3. The SCIM offer is visible only to the person it was made for.
insert into public.scim_provisioned_users (tenant_id, external_id, user_name, email_hash, display_name, active)
values ('a7200000-0000-4000-8000-000000000001', 'ext-1', 'lr-joiner@example.invalid',
  extensions.digest(convert_to('lr-joiner@example.invalid','UTF8'),'sha256'), 'Joiner', true);
set local role authenticated;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000001',true);
do $$ begin
  if exists (select 1 from public.my_pending_provisioning()) then
    raise exception 'Admin was offered another person''s provisioned account';
  end if;
end $$;
select set_config('request.jwt.claim.sub','a7000000-0000-4000-8000-000000000002',true);
do $$ begin
  if (select count(*) from public.my_pending_provisioning()) <> 1 then
    raise exception 'Provisioned person cannot see their own offer';
  end if;
end $$;
reset role;

rollback;
