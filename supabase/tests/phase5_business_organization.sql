begin;

insert into auth.users(
  id,instance_id,aud,role,email,email_confirmed_at,encrypted_password,created_at,updated_at
) values
  ('91000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','office-owner@example.invalid',now(),'',now(),now()),
  ('92000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','office-member@example.invalid',now(),'',now(),now()),
  ('93000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','office-outsider@example.invalid',now(),'',now(),now());

insert into public.identities(id,auth_user_id,kind) values
  ('91100000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001','human'),
  ('92100000-0000-4000-8000-000000000002','92000000-0000-4000-8000-000000000002','human'),
  ('93100000-0000-4000-8000-000000000003','93000000-0000-4000-8000-000000000003','human');

insert into public.tenants(id,kind,created_by) values
  ('91200000-0000-4000-8000-000000000001','organization','91100000-0000-4000-8000-000000000001'),
  ('93200000-0000-4000-8000-000000000003','organization','93100000-0000-4000-8000-000000000003');

insert into public.tenant_memberships(tenant_id,identity_id,role,status) values
  ('91200000-0000-4000-8000-000000000001','91100000-0000-4000-8000-000000000001','owner','active'),
  ('93200000-0000-4000-8000-000000000003','93100000-0000-4000-8000-000000000003','owner','active');

update public.tenant_entitlements set
  plan_code='business',subscription_status='active',source='manual',
  max_members=500,max_workspaces=500,max_devices=null,
  ai_credits_remaining=10000,automation_runs_remaining=50000
where tenant_id='91200000-0000-4000-8000-000000000001';

insert into public.tenant_memberships(tenant_id,identity_id,role,status)
values ('91200000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002','member','active');

insert into public.workspaces(id,tenant_id,kind,created_by,suite,status)
values ('91300000-0000-4000-8000-000000000001','91200000-0000-4000-8000-000000000001','shared','91100000-0000-4000-8000-000000000001','business','active');
insert into public.workspace_memberships(tenant_id,workspace_id,identity_id,role,status) values
  ('91200000-0000-4000-8000-000000000001','91300000-0000-4000-8000-000000000001','91100000-0000-4000-8000-000000000001','owner','active'),
  ('91200000-0000-4000-8000-000000000001','91300000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002','viewer','active');
insert into public.key_envelopes(
  tenant_id,workspace_id,key_kind,key_version,recipient_identity_id,algorithm,nonce,wrapped_key
) values (
  '91200000-0000-4000-8000-000000000001','91300000-0000-4000-8000-000000000001',
  'workspace',1,'92100000-0000-4000-8000-000000000002','AES-256-GCM',
  decode(repeat('11',12),'hex'),decode(repeat('22',48),'hex')
);

set local role authenticated;
select set_config('request.jwt.claim.sub','91000000-0000-4000-8000-000000000001',true);

insert into public.organization_departments(id,tenant_id,display_name,slug,created_by)
values ('91400000-0000-4000-8000-000000000001','91200000-0000-4000-8000-000000000001','Engineering','engineering','91100000-0000-4000-8000-000000000001');
insert into public.organization_teams(id,tenant_id,department_id,display_name,slug,created_by)
values ('91500000-0000-4000-8000-000000000001','91200000-0000-4000-8000-000000000001','91400000-0000-4000-8000-000000000001','Platform','platform','91100000-0000-4000-8000-000000000001');
insert into public.organization_groups(id,tenant_id,display_name,slug,description,created_by)
values ('91600000-0000-4000-8000-000000000001','91200000-0000-4000-8000-000000000001','Production access','production-access','Non-secret access classification','91100000-0000-4000-8000-000000000001');

select public.onboard_organization_member(
  '91200000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002',
  'Office Member','Platform Engineer','91400000-0000-4000-8000-000000000001'
);
insert into public.organization_team_memberships(tenant_id,team_id,identity_id,role,assigned_by)
values ('91200000-0000-4000-8000-000000000001','91500000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002','member','91100000-0000-4000-8000-000000000001');
insert into public.organization_group_memberships(tenant_id,group_id,identity_id,assigned_by)
values ('91200000-0000-4000-8000-000000000001','91600000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002','91100000-0000-4000-8000-000000000001');
insert into public.organization_admin_assignments(tenant_id,identity_id,role,scope_type,assigned_by)
values ('91200000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002','helpdesk_admin','tenant','91100000-0000-4000-8000-000000000001');
insert into public.organization_policies(tenant_id,scope_type,policy_type,configuration,created_by)
values ('91200000-0000-4000-8000-000000000001','tenant','passkey_required','{"required":true}'::jsonb,'91100000-0000-4000-8000-000000000001');

do $$ begin
  if (select count(*) from public.organization_departments) <> 1
    or (select count(*) from public.organization_teams) <> 1
    or (select count(*) from public.organization_groups) <> 1
    or (select count(*) from public.organization_profiles) <> 1
    or (select count(*) from public.identity_lifecycle_events where event_type='joined') <> 1 then
    raise exception 'Phase 5 creation failure';
  end if;
end $$;

do $$ begin
  update public.organization_departments
  set tenant_id='93200000-0000-4000-8000-000000000003'
  where id='91400000-0000-4000-8000-000000000001';
  raise exception 'Phase 5 tenant reassignment was accepted';
exception when check_violation then null;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','92000000-0000-4000-8000-000000000002',true);

do $$ begin
  insert into public.organization_departments(tenant_id,display_name,slug,created_by)
  values ('91200000-0000-4000-8000-000000000001','Unauthorized','unauthorized','92100000-0000-4000-8000-000000000002');
  raise exception 'Phase 5 scoped role escalation: helpdesk created department';
exception when insufficient_privilege then null;
end $$;

do $$ begin
  if (select count(*) from public.organization_departments where tenant_id='91200000-0000-4000-8000-000000000001') <> 1
    or exists (select 1 from public.organization_departments where tenant_id='93200000-0000-4000-8000-000000000003') then
    raise exception 'Phase 5 member read boundary failure';
  end if;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','93000000-0000-4000-8000-000000000003',true);

do $$ begin
  if exists (select 1 from public.organization_departments where tenant_id='91200000-0000-4000-8000-000000000001') then
    raise exception 'Phase 5 cross-tenant read failure';
  end if;
end $$;

do $$ begin
  insert into public.organization_departments(tenant_id,display_name,slug,created_by)
  values ('93200000-0000-4000-8000-000000000003','Free bypass','free-bypass','93100000-0000-4000-8000-000000000003');
  raise exception 'Phase 5 Business entitlement was bypassed';
exception when check_violation then null;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','91000000-0000-4000-8000-000000000001',true);
select public.manage_organization_member_lifecycle(
  '91200000-0000-4000-8000-000000000001','92100000-0000-4000-8000-000000000002',
  'suspended',null,'security'
);

set local role service_role;
do $$ begin
  if (select status from public.tenant_memberships where tenant_id='91200000-0000-4000-8000-000000000001' and identity_id='92100000-0000-4000-8000-000000000002') <> 'suspended'
    or (select status from public.workspace_memberships where workspace_id='91300000-0000-4000-8000-000000000001' and identity_id='92100000-0000-4000-8000-000000000002') <> 'suspended'
    or not (select key_rotation_required from public.workspaces where id='91300000-0000-4000-8000-000000000001')
    or not exists (select 1 from public.key_envelopes where recipient_identity_id='92100000-0000-4000-8000-000000000002' and revoked_at is not null)
    or not exists (select 1 from public.identity_lifecycle_events where subject_identity_id='92100000-0000-4000-8000-000000000002' and event_type='suspended') then
    raise exception 'Phase 5 lifecycle revocation failure';
  end if;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','91000000-0000-4000-8000-000000000001',true);

select public.create_shared_workspace(
  '94200000-0000-4000-8000-000000000004','94300000-0000-4000-8000-000000000004',
  'business','shared',decode(repeat('31',16),'hex'),decode(repeat('32',12),'hex'),
  decode(repeat('33',32),'hex'),decode(repeat('34',12),'hex'),decode(repeat('35',48),'hex')
);
do $$ begin
  if not exists (
    select 1 from public.workspaces
    where id='94300000-0000-4000-8000-000000000004' and suite='business'
  ) or not exists (
    select 1 from public.tenant_entitlements
    where tenant_id='94200000-0000-4000-8000-000000000004' and plan_code='free'
  ) then raise exception 'Phase 5 Business workspace bootstrap failure';
  end if;
end $$;

do $$ begin
  update public.identity_lifecycle_events set reason_code='other';
  raise exception 'Phase 5 append-only history was mutable';
exception when insufficient_privilege then null;
end $$;

rollback;
