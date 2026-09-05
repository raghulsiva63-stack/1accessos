begin;

insert into auth.users(
  id,instance_id,aud,role,email,email_confirmed_at,encrypted_password,created_at,updated_at
) values
  ('a1000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','governance-owner@example.invalid',now(),'',now(),now()),
  ('a2000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','governance-admin@example.invalid',now(),'',now(),now()),
  ('a3000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','governance-member@example.invalid',now(),'',now(),now()),
  ('a4000000-0000-4000-8000-000000000004','00000000-0000-0000-0000-000000000000','authenticated','authenticated','governance-other@example.invalid',now(),'',now(),now()),
  ('a5000000-0000-4000-8000-000000000005','00000000-0000-0000-0000-000000000000','authenticated','authenticated','governance-invitee@example.invalid',now(),'',now(),now());

insert into public.identities(id,auth_user_id,kind) values
  ('b1000000-0000-4000-8000-000000000001','a1000000-0000-4000-8000-000000000001','human'),
  ('b2000000-0000-4000-8000-000000000002','a2000000-0000-4000-8000-000000000002','human'),
  ('b3000000-0000-4000-8000-000000000003','a3000000-0000-4000-8000-000000000003','human'),
  ('b4000000-0000-4000-8000-000000000004','a4000000-0000-4000-8000-000000000004','human'),
  ('b5000000-0000-4000-8000-000000000005','a5000000-0000-4000-8000-000000000005','human');

insert into public.tenants(id,kind,created_by) values
  ('c1000000-0000-4000-8000-000000000001','organization','b1000000-0000-4000-8000-000000000001'),
  ('c4000000-0000-4000-8000-000000000004','organization','b4000000-0000-4000-8000-000000000004');
insert into public.tenant_memberships(tenant_id,identity_id,role,status) values
  ('c1000000-0000-4000-8000-000000000001','b1000000-0000-4000-8000-000000000001','owner','active'),
  ('c4000000-0000-4000-8000-000000000004','b4000000-0000-4000-8000-000000000004','owner','active');
update public.tenant_entitlements set
  plan_code = 'business',subscription_status = 'active',source = 'manual',
  max_members = 500,max_workspaces = 500,max_devices = null
where tenant_id = 'c1000000-0000-4000-8000-000000000001';
insert into public.tenant_memberships(tenant_id,identity_id,role,status) values
  ('c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002','member','active'),
  ('c1000000-0000-4000-8000-000000000001','b3000000-0000-4000-8000-000000000003','member','active');

insert into public.devices(id,identity_id,public_key,status,last_seen_at) values
  ('d5000000-0000-4000-8000-000000000005','b5000000-0000-4000-8000-000000000005',decode(repeat('51',33),'hex'),'trusted',now());

set local role authenticated;
select set_config('request.jwt.claim.sub','a1000000-0000-4000-8000-000000000001',true);

insert into public.organization_departments(id,tenant_id,display_name,slug,created_by) values
  ('d1000000-0000-4000-8000-000000000001','c1000000-0000-4000-8000-000000000001','Engineering','engineering-governance','b1000000-0000-4000-8000-000000000001'),
  ('d2000000-0000-4000-8000-000000000002','c1000000-0000-4000-8000-000000000001','Finance','finance-governance','b1000000-0000-4000-8000-000000000001');
insert into public.organization_departments(id,tenant_id,parent_department_id,display_name,slug,created_by)
values ('d1100000-0000-4000-8000-000000000011','c1000000-0000-4000-8000-000000000001','d1000000-0000-4000-8000-000000000001','Platform','platform-governance','b1000000-0000-4000-8000-000000000001');
insert into public.organization_teams(id,tenant_id,department_id,display_name,slug,created_by)
values ('e1000000-0000-4000-8000-000000000001','c1000000-0000-4000-8000-000000000001','d1100000-0000-4000-8000-000000000011','Runtime','runtime-governance','b1000000-0000-4000-8000-000000000001');

select public.onboard_organization_member(
  'c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002',
  'Scoped Admin','Engineering Admin','d1000000-0000-4000-8000-000000000001'
);
select public.onboard_organization_member(
  'c1000000-0000-4000-8000-000000000001','b3000000-0000-4000-8000-000000000003',
  'Platform Member','Engineer','d1100000-0000-4000-8000-000000000011'
);
insert into public.organization_team_memberships(tenant_id,team_id,identity_id,role,status,assigned_by)
values ('c1000000-0000-4000-8000-000000000001','e1000000-0000-4000-8000-000000000001','b3000000-0000-4000-8000-000000000003','member','active','b1000000-0000-4000-8000-000000000001');
insert into public.organization_admin_assignments(
  tenant_id,identity_id,role,scope_type,scope_id,status,assigned_by
) values
  ('c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002','organization_admin','department','d1000000-0000-4000-8000-000000000001','active','b1000000-0000-4000-8000-000000000001'),
  ('c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002','helpdesk_admin','department','d1000000-0000-4000-8000-000000000001','active','b1000000-0000-4000-8000-000000000001'),
  ('c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002','security_admin','department','d1000000-0000-4000-8000-000000000001','active','b1000000-0000-4000-8000-000000000001');

insert into public.organization_policies(
  tenant_id,scope_type,scope_id,policy_type,configuration,priority,enforced,version,created_by
) values
  ('c1000000-0000-4000-8000-000000000001','tenant',null,'passkey_required','{"required":true}'::jsonb,100,true,1,'b1000000-0000-4000-8000-000000000001'),
  ('c1000000-0000-4000-8000-000000000001','department','d1100000-0000-4000-8000-000000000011','passkey_required','{"required":false}'::jsonb,100,true,2,'b1000000-0000-4000-8000-000000000001'),
  ('c1000000-0000-4000-8000-000000000001','team','e1000000-0000-4000-8000-000000000001','device_approval_required','{"required":true}'::jsonb,100,true,1,'b1000000-0000-4000-8000-000000000001');

set local role authenticated;
select set_config('request.jwt.claim.sub','a2000000-0000-4000-8000-000000000002',true);

insert into public.organization_departments(id,tenant_id,parent_department_id,display_name,slug,created_by)
values ('d1200000-0000-4000-8000-000000000012','c1000000-0000-4000-8000-000000000001','d1100000-0000-4000-8000-000000000011','SRE','sre-governance','b2000000-0000-4000-8000-000000000002');

do $$ begin
  insert into public.organization_departments(tenant_id,parent_department_id,display_name,slug,created_by)
  values ('c1000000-0000-4000-8000-000000000001','d2000000-0000-4000-8000-000000000002','Payroll','payroll-denied','b2000000-0000-4000-8000-000000000002');
  raise exception 'Scoped administrator changed another department';
exception when insufficient_privilege then null;
end $$;

insert into public.organization_policies(
  tenant_id,scope_type,scope_id,policy_type,configuration,created_by
) values (
  'c1000000-0000-4000-8000-000000000001','department','d1000000-0000-4000-8000-000000000001',
  'export_policy','{"allowed":false}'::jsonb,'b2000000-0000-4000-8000-000000000002'
);

do $$ begin
  insert into public.organization_policies(
    tenant_id,scope_type,scope_id,policy_type,configuration,created_by
  ) values (
    'c1000000-0000-4000-8000-000000000001','department','d2000000-0000-4000-8000-000000000002',
    'export_policy','{"allowed":true}'::jsonb,'b2000000-0000-4000-8000-000000000002'
  );
  raise exception 'Scoped security administrator changed another department';
exception when insufficient_privilege then null;
end $$;

insert into public.organization_invitations(
  id,tenant_id,created_by,recipient_email_hash,token_hash,display_name,job_title,
  department_id,team_id,team_role,status,expires_at
) values (
  'f1000000-0000-4000-8000-000000000001','c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002',
  extensions.digest(convert_to('governance-invitee@example.invalid','UTF8'),'sha256'),
  decode(repeat('71',32),'hex'),'Invited Engineer','Software Engineer',
  'd1100000-0000-4000-8000-000000000011','e1000000-0000-4000-8000-000000000001','member','pending',now() + interval '7 days'
);

do $$ begin
  insert into public.organization_invitations(
    id,tenant_id,created_by,recipient_email_hash,token_hash,display_name,
    department_id,status,expires_at
  ) values (
    'f2000000-0000-4000-8000-000000000002','c1000000-0000-4000-8000-000000000001','b2000000-0000-4000-8000-000000000002',
    extensions.digest(convert_to('nobody@example.invalid','UTF8'),'sha256'),decode(repeat('72',32),'hex'),
    'Finance Invite','d2000000-0000-4000-8000-000000000002','pending',now() + interval '7 days'
  );
  raise exception 'Scoped helpdesk administrator invited into another department';
exception when insufficient_privilege then null;
end $$;

do $$ begin
  perform * from public.export_organization_audit('c1000000-0000-4000-8000-000000000001',0,100);
  raise exception 'Scoped administrator exported tenant-wide audit';
exception when insufficient_privilege then null;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','a5000000-0000-4000-8000-000000000005',true);

do $$ begin
  if not exists (
    select 1 from public.organization_invitations
    where id = 'f1000000-0000-4000-8000-000000000001'
  ) then raise exception 'Email-bound organization invitation was not readable';
  end if;
end $$;

select public.accept_organization_invitation(
  'f1000000-0000-4000-8000-000000000001',decode(repeat('71',32),'hex')
);

do $$ begin
  if not exists (
    select 1 from public.tenant_memberships
    where tenant_id = 'c1000000-0000-4000-8000-000000000001'
      and identity_id = 'b5000000-0000-4000-8000-000000000005'
      and status = 'active'
  ) or not exists (
    select 1 from public.organization_profiles
    where tenant_id = 'c1000000-0000-4000-8000-000000000001'
      and identity_id = 'b5000000-0000-4000-8000-000000000005'
      and department_id = 'd1100000-0000-4000-8000-000000000011'
  ) or not exists (
    select 1 from public.organization_team_memberships
    where team_id = 'e1000000-0000-4000-8000-000000000001'
      and identity_id = 'b5000000-0000-4000-8000-000000000005'
      and status = 'active'
  ) then raise exception 'Organization invitation acceptance did not provision directory scope';
  end if;
end $$;

do $$ begin
  perform public.accept_organization_invitation(
    'f1000000-0000-4000-8000-000000000001',decode(repeat('71',32),'hex')
  );
  raise exception 'Organization invitation replay unexpectedly succeeded';
exception when invalid_authorization_specification then null;
end $$;

do $$ begin
  if not exists (
    select 1 from public.resolve_organization_policies(
      'c1000000-0000-4000-8000-000000000001','b5000000-0000-4000-8000-000000000005'
    ) policy
    where policy.policy_type = 'passkey_required'
      and policy.source_scope_type = 'department'
      and policy.configuration = '{"required":false}'::jsonb
  ) or not exists (
    select 1 from public.resolve_organization_policies(
      'c1000000-0000-4000-8000-000000000001','b5000000-0000-4000-8000-000000000005'
    ) policy
    where policy.policy_type = 'device_approval_required'
      and policy.source_scope_type = 'team'
  ) then raise exception 'Effective policy precedence failed';
  end if;
end $$;

insert into public.organization_device_posture_reports(
  tenant_id,device_id,identity_id,source,verification_status,evaluation,os_family,
  screen_lock,disk_encrypted,security_patch_current,endpoint_protection,
  observed_at,valid_until,created_by
) values (
  'c1000000-0000-4000-8000-000000000001','d5000000-0000-4000-8000-000000000005','b5000000-0000-4000-8000-000000000005',
  'self_reported','unverified','unknown','linux',true,true,true,true,now(),now() + interval '1 day',
  'b5000000-0000-4000-8000-000000000005'
);

do $$ declare decision jsonb; begin
  decision := public.evaluate_organization_device_readiness(
    'c1000000-0000-4000-8000-000000000001','d5000000-0000-4000-8000-000000000005','b5000000-0000-4000-8000-000000000005'
  );
  if (decision ->> 'allowed')::boolean or decision ->> 'reason' <> 'verification_required' then
    raise exception 'Unverified self-report satisfied strict device policy';
  end if;
end $$;

reset role;
insert into public.organization_device_posture_reports(
  tenant_id,device_id,identity_id,source,verification_status,evaluation,os_family,
  screen_lock,disk_encrypted,security_patch_current,endpoint_protection,evidence_hash,
  observed_at,valid_until,created_by
) values (
  'c1000000-0000-4000-8000-000000000001','d5000000-0000-4000-8000-000000000005','b5000000-0000-4000-8000-000000000005',
  'mdm','verified','compliant','linux',true,true,true,true,decode(repeat('81',32),'hex'),
  now(),now() + interval '1 day','b1000000-0000-4000-8000-000000000001'
);

set local role authenticated;
select set_config('request.jwt.claim.sub','a5000000-0000-4000-8000-000000000005',true);
do $$ declare decision jsonb; begin
  decision := public.evaluate_organization_device_readiness(
    'c1000000-0000-4000-8000-000000000001','d5000000-0000-4000-8000-000000000005','b5000000-0000-4000-8000-000000000005'
  );
  if not (decision ->> 'allowed')::boolean or decision ->> 'reason' <> 'ready' then
    raise exception 'Verified compliant posture did not satisfy readiness policy';
  end if;
end $$;

update public.organization_profiles set lifecycle_status = 'suspended'
where tenant_id = 'c1000000-0000-4000-8000-000000000001'
  and identity_id = 'b5000000-0000-4000-8000-000000000005';
do $$ begin
  if exists (
    select 1 from public.organization_profiles
    where tenant_id = 'c1000000-0000-4000-8000-000000000001'
      and identity_id = 'b5000000-0000-4000-8000-000000000005'
      and lifecycle_status <> 'active'
  ) then raise exception 'Direct lifecycle bypass unexpectedly succeeded';
  end if;
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub','a1000000-0000-4000-8000-000000000001',true);
do $$ begin
  if (select count(*) from public.export_organization_audit(
    'c1000000-0000-4000-8000-000000000001',0,1000
  )) = 0 then raise exception 'Owner audit export returned no events';
  end if;
end $$;

rollback;
