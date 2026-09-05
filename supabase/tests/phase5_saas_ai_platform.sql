begin;

insert into auth.users(id,instance_id,aud,role,email,email_confirmed_at,encrypted_password,created_at,updated_at) values
('51000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase5-customer@example.invalid',now(),'',now(),now()),
('52000000-0000-4000-8000-000000000002','00000000-0000-0000-8000-000000000000','authenticated','authenticated','phase5-provider@example.invalid',now(),'',now(),now()),
('53000000-0000-4000-8000-000000000003','00000000-0000-0000-8000-000000000000','authenticated','authenticated','phase5-outsider@example.invalid',now(),'',now(),now());

insert into public.identities(id,auth_user_id,kind) values
('61000000-0000-4000-8000-000000000001','51000000-0000-4000-8000-000000000001','human'),
('62000000-0000-4000-8000-000000000002','52000000-0000-4000-8000-000000000002','human'),
('63000000-0000-4000-8000-000000000003','53000000-0000-4000-8000-000000000003','human');

insert into public.tenants(id,kind,created_by) values
('71000000-0000-4000-8000-000000000001','organization','61000000-0000-4000-8000-000000000001'),
('72000000-0000-4000-8000-000000000002','organization','62000000-0000-4000-8000-000000000002'),
('73000000-0000-4000-8000-000000000003','organization','63000000-0000-4000-8000-000000000003');
insert into public.tenant_memberships(tenant_id,identity_id,role,status) values
('71000000-0000-4000-8000-000000000001','61000000-0000-4000-8000-000000000001','owner','active'),
('72000000-0000-4000-8000-000000000002','62000000-0000-4000-8000-000000000002','owner','active'),
('73000000-0000-4000-8000-000000000003','63000000-0000-4000-8000-000000000003','owner','active');
update public.tenant_entitlements set plan_code='business',subscription_status='active',source='manual',max_members=500,max_workspaces=500
where tenant_id in ('71000000-0000-4000-8000-000000000001','72000000-0000-4000-8000-000000000002');

set local role authenticated;
select set_config('request.jwt.claim.sub','51000000-0000-4000-8000-000000000001',true);

insert into public.tenant_connectors(id,tenant_id,connector_key,display_name,status,granted_scopes,token_rotation_state,created_by) values
('81000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','microsoft-entra-id','Corporate Entra','draft',array[]::text[],'not_configured','61000000-0000-4000-8000-000000000001');
insert into public.saas_applications(id,tenant_id,connector_id,app_key,display_name,category,sanctioned_state,data_risk,discovery_source,external_ref_hash,confidence) values
('82000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','81000000-0000-4000-8000-000000000001','figma','Figma','design','sanctioned','medium','idp',decode(repeat('11',32),'hex'),0.9900),
('82000000-0000-4000-8000-000000000002','71000000-0000-4000-8000-000000000001','81000000-0000-4000-8000-000000000001','unknown-ai','Unknown AI','ai','unsanctioned','high','idp',decode(repeat('12',32),'hex'),0.8500);
insert into public.saas_identity_accounts(id,tenant_id,application_id,account_ref_hash,owner_state,account_status,privilege_tier,last_activity_bucket) values
('83000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','82000000-0000-4000-8000-000000000001',decode(repeat('21',32),'hex'),'unmatched','active','admin',current_date - 60);
insert into public.saas_contracts(id,tenant_id,application_id,sku,currency,unit_cost_minor,billing_interval,purchased_seats,renewal_at,source) values
('84000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','82000000-0000-4000-8000-000000000001','business','usd',1500,'month',10,current_date + 20,'manual');
insert into public.saas_licenses(id,tenant_id,contract_id,status) values
('85000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','84000000-0000-4000-8000-000000000001','assigned');
insert into public.spend_budgets(id,tenant_id,scope_type,metric,currency,soft_limit,hard_limit,consumed,period_start,period_end,enforcement,chargeback_tag,created_by) values
('86000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','tenant','ai_cost_minor','usd',8000,10000,8000,current_date - 5,current_date + 25,'block','engineering','61000000-0000-4000-8000-000000000001');
insert into public.lifecycle_workflows(id,tenant_id,display_name,trigger_type,action_type,execution_mode,destructive_action,approval_required,definition,enabled,created_by) values
('87000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','Unused license review','license_reclaim','propose_reclaim','proposal',true,true,'{"inactive_days":45}'::jsonb,true,'61000000-0000-4000-8000-000000000001');

do $$ declare generated integer; dashboard jsonb; begin
  generated := public.refresh_saas_recommendations('71000000-0000-4000-8000-000000000001');
  if generated < 4 then raise exception 'Phase 5 recommendations were not generated'; end if;
  dashboard := public.phase5_saas_dashboard('71000000-0000-4000-8000-000000000001');
  if (dashboard->>'applications')::integer <> 2
    or (dashboard->>'unsanctioned_apps')::integer <> 1
    or (dashboard->>'ghost_accounts')::integer <> 1
    or (dashboard->>'open_recommendations')::integer < 4 then
    raise exception 'Phase 5 dashboard correctness failure';
  end if;
end $$;

do $$ begin
  insert into public.connector_credentials(connector_id,tenant_id,encrypted_token_ref,key_version,ciphertext_sha256)
  values ('81000000-0000-4000-8000-000000000001','71000000-0000-4000-8000-000000000001','kms://phase5/test',1,decode(repeat('91',32),'hex'));
  raise exception 'Browser inserted a connector credential reference';
exception when insufficient_privilege then null;
end $$;

do $$ begin
  update public.tenant_connectors set status='healthy',granted_scopes=array['Directory.Read.All','AuditLog.Read.All'],token_rotation_state='current'
  where id='81000000-0000-4000-8000-000000000001';
  raise exception 'Manifest-only connector was marked healthy';
exception when check_violation then null;
end $$;

do $$ begin
  update public.tenant_connectors set configuration_summary='{"access_token":"browser-secret"}'::jsonb
  where id='81000000-0000-4000-8000-000000000001';
  raise exception 'Secret-shaped connector configuration reached metadata storage';
exception when check_violation then null;
end $$;

do $$ begin
  update public.connector_catalog set display_name='Mutated' where connector_key='okta';
  raise exception 'Published connector catalog was mutable by browser role';
exception when insufficient_privilege then null;
end $$;

reset role;
set local role service_role;
do $$ declare decision jsonb; begin
  decision := public.reserve_phase5_budget('71000000-0000-4000-8000-000000000001','86000000-0000-4000-8000-000000000001',1500,decode(repeat('a1',32),'hex'));
  if decision->>'decision' <> 'allowed_with_alert' then raise exception 'Soft-limit alert decision failed'; end if;
  decision := public.reserve_phase5_budget('71000000-0000-4000-8000-000000000001','86000000-0000-4000-8000-000000000001',1000,decode(repeat('a2',32),'hex'));
  if decision->>'decision' <> 'blocked' then raise exception 'Hard-limit enforcement failed'; end if;
  if (select consumed from public.spend_budgets where id='86000000-0000-4000-8000-000000000001') <> 9500 then
    raise exception 'Blocked spend changed consumed budget';
  end if;
end $$;

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub','52000000-0000-4000-8000-000000000002',true);
insert into public.msp_tenant_access(id,provider_tenant_id,customer_tenant_id,permission,status,created_by) values
('88000000-0000-4000-8000-000000000001','72000000-0000-4000-8000-000000000002','71000000-0000-4000-8000-000000000001','view','pending','62000000-0000-4000-8000-000000000002');

select set_config('request.jwt.claim.sub','51000000-0000-4000-8000-000000000001',true);
update public.msp_tenant_access set status='active',approved_by='61000000-0000-4000-8000-000000000001',approved_at=now()
where id='88000000-0000-4000-8000-000000000001';

select set_config('request.jwt.claim.sub','52000000-0000-4000-8000-000000000002',true);
do $$ begin
  if public.phase5_saas_dashboard('71000000-0000-4000-8000-000000000001') is null then
    raise exception 'Approved MSP context could not read derived SaaS metrics';
  end if;
  if private.has_tenant_role('71000000-0000-4000-8000-000000000001',array['owner','admin','member','auditor']) then
    raise exception 'MSP metadata approval created customer tenant membership';
  end if;
  if exists (select 1 from public.key_envelopes where tenant_id='71000000-0000-4000-8000-000000000001') then
    raise exception 'MSP console exposed customer key envelopes';
  end if;
end $$;

select set_config('request.jwt.claim.sub','53000000-0000-4000-8000-000000000003',true);
do $$ begin
  if public.phase5_saas_dashboard('71000000-0000-4000-8000-000000000001') is not null
    or exists (select 1 from public.saas_applications where tenant_id='71000000-0000-4000-8000-000000000001') then
    raise exception 'Phase 5 cross-tenant read failure';
  end if;
end $$;

rollback;
