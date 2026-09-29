-- Sign-in tracking, notifications, health trends, breach watch, passkey nudges, rotation
-- campaigns, weekly reports and AI context.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('c8000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','owner@intel.example',now(),'',now(),now()),
  ('c8000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','member@intel.example',now(),'',now(),now());

create temporary table ident (actor text primary key, bootstrap jsonb) on commit drop;
grant all on ident to authenticated, service_role;
set local role authenticated;
select set_config('request.jwt.claim.sub','c8000000-0000-4000-8000-000000000001',true);
insert into ident values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','c8000000-0000-4000-8000-000000000002',true);
insert into ident values ('member', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));
select set_config('request.jwt.claim.sub','',true);
reset role;

create temporary table ctx (k text primary key, v text) on commit drop;
grant all on ctx to authenticated, service_role;
insert into ctx select 'org', bootstrap ->> 'tenant_id' from ident where actor = 'owner';
insert into ctx select 'ws', bootstrap ->> 'workspace_id' from ident where actor = 'owner';
insert into ctx select 'owner', bootstrap ->> 'identity_id' from ident where actor = 'owner';
insert into ctx select 'member', bootstrap ->> 'identity_id' from ident where actor = 'member';

update public.tenants set kind = 'organization' where id = (select v::uuid from ctx where k = 'org');
insert into public.tenant_entitlements (tenant_id, plan_code, subscription_status, source, max_members)
  select v::uuid, 'business', 'active', 'manual', 50 from ctx where k = 'org'
  on conflict (tenant_id) do update set plan_code = 'business', subscription_status = 'active', source = 'manual', max_members = 50;
update public.tenant_entitlements set ai_credits_remaining = 10 where tenant_id = (select v::uuid from ctx where k = 'org');
insert into public.tenant_memberships (tenant_id, identity_id, role, status)
  select (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'member'), 'member', 'active';

-- ---------------------------------------------------------------------------
-- Sign-in tracking
-- ---------------------------------------------------------------------------
insert into auth.sessions (id, user_id, user_agent, ip, aal, created_at) values
  ('d8000000-0000-4000-8000-000000000001','c8000000-0000-4000-8000-000000000001',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36','203.0.113.5','aal1', now() - interval '2 days'),
  ('d8000000-0000-4000-8000-000000000002','c8000000-0000-4000-8000-000000000001',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36','203.0.113.77','aal1', now() - interval '1 day');
insert into auth.sessions (id, user_id, user_agent, ip, aal) values
  ('d8000000-0000-4000-8000-000000000003','c8000000-0000-4000-8000-000000000001',
   'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0','198.51.100.7','aal1');
-- A session for a user without an identity must not fail.
insert into auth.users (id, email) values ('c8000000-0000-4000-8000-0000000000ff', 'service@intel.example');
insert into auth.sessions (user_id, user_agent, ip) values ('c8000000-0000-4000-8000-0000000000ff', null, null);
-- Organization alerts are raised by the per-minute job, outside the Auth transaction.
do $$ begin
  if exists (select 1 from public.security_alerts where kind = 'sign_in.unfamiliar') then raise exception 'alert raised inside the sign-in transaction'; end if;
end $$;
select private.process_sign_in_alerts();

do $$
declare v_owner uuid := (select v::uuid from ctx where k = 'owner'); v_org uuid := (select v::uuid from ctx where k = 'org');
begin
  if (select count(*) from public.account_sign_ins where identity_id = v_owner) <> 3 then raise exception 'sign-ins not recorded'; end if;
  if exists (select 1 from public.account_sign_ins where identity_id = v_owner and (network_label !~ '\.x$' or network_label like '%203.0.113.5%')) then
    raise exception 'full IP stored';
  end if;
  if (select device_label from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000003') <> 'Firefox on Linux' then
    raise exception 'device label wrong: %', (select device_label from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000003');
  end if;
  if exists (select 1 from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000002' and (new_device or new_network)) then
    raise exception 'known device flagged';
  end if;
  if not exists (select 1 from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000003' and new_device and new_network) then
    raise exception 'new device not flagged';
  end if;
  if not exists (select 1 from private.notification_outbox where recipient_identity_id = v_owner and template = 'new_sign_in') then
    raise exception 'new device email not queued';
  end if;
  if not exists (select 1 from public.security_alerts where tenant_id = v_org and kind = 'sign_in.unfamiliar') then
    raise exception 'unfamiliar sign-in alert missing';
  end if;
  if exists (select 1 from public.security_alerts where kind like 'sign_in.%' and detail ? 'network') then
    raise exception 'member network shared with the organization';
  end if;
end $$;

-- Many networks within an hour: high alert, emailed to administrators.
insert into auth.sessions (user_id, user_agent, ip) values
  ('c8000000-0000-4000-8000-000000000001','Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0','192.0.2.10'),
  ('c8000000-0000-4000-8000-000000000001','Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0','100.64.9.9'),
  ('c8000000-0000-4000-8000-000000000001','Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0','2001:db8:1234::1');
select private.process_sign_in_alerts();
do $$ begin
  if not exists (select 1 from public.security_alerts where kind = 'sign_in.many_networks' and severity = 'high') then
    raise exception 'velocity alert missing';
  end if;
  if not exists (select 1 from private.notification_outbox where template = 'security_alert' and params ->> 'kind' = 'sign_in.many_networks') then
    raise exception 'high alert not emailed to admins';
  end if;
  if exists (select 1 from private.notification_outbox where template = 'security_alert' and params ->> 'kind' = 'sign_in.unfamiliar') then
    raise exception 'medium alert emailed';
  end if;
end $$;

-- Sessions list and revoke.
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001","session_id":"d8000000-0000-4000-8000-000000000003","aal":"aal1"}',true);
do $$ begin
  if (select count(*) from public.my_sessions()) < 6 then raise exception 'sessions not listed'; end if;
  if not (select is_current from public.my_sessions() where session_id = 'd8000000-0000-4000-8000-000000000003') then raise exception 'current session not marked'; end if;
  if (select count(*) from public.account_sign_ins) <> 6 then raise exception 'own sign-ins not readable'; end if;
  begin perform public.revoke_my_session('d8000000-0000-4000-8000-000000000003'); raise exception 'revoked current session';
  exception when invalid_parameter_value then null; end;
  if not public.revoke_my_session('d8000000-0000-4000-8000-000000000001') then raise exception 'revoke failed'; end if;
end $$;
-- Another person can neither see nor revoke those sessions.
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002","session_id":"d8000000-0000-4000-8000-0000000000aa","aal":"aal1"}',true);
do $$ begin
  if (select count(*) from public.my_sessions()) <> 0 then raise exception 'saw other sessions'; end if;
  if (select count(*) from public.account_sign_ins) <> 0 then raise exception 'saw other sign-ins'; end if;
  if public.revoke_my_session('d8000000-0000-4000-8000-000000000002') then raise exception 'revoked another person''s session'; end if;
end $$;
reset role;
do $$ begin
  if exists (select 1 from auth.sessions where id = 'd8000000-0000-4000-8000-000000000001') then raise exception 'session not deleted'; end if;
  if not exists (select 1 from auth.sessions where id = 'd8000000-0000-4000-8000-000000000002') then raise exception 'wrong session deleted'; end if;
end $$;

-- Country attestation (HMAC from the Netlify function).
insert into ctx values ('geo', (select value from private.app_settings where key = 'geo_attestation_key'));
insert into ctx values ('now', extract(epoch from now())::bigint::text);
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001","session_id":"d8000000-0000-4000-8000-000000000002"}',true);
do $$
declare v_key text := (select v from ctx where k = 'geo'); v_now bigint := (select v::bigint from ctx where k = 'now');
begin
  if public.attest_sign_in_country('US', v_now, repeat('0', 64)) then raise exception 'bad signature accepted'; end if;
  if public.attest_sign_in_country('KP', v_now, null) then raise exception 'null signature accepted'; end if;
  if public.attest_sign_in_country(null, v_now, repeat('0', 64)) then raise exception 'null country accepted'; end if;
  if public.attest_sign_in_country('US', null, repeat('0', 64)) then raise exception 'null time accepted'; end if;
  if not public.attest_sign_in_country('US', v_now,
    encode(extensions.hmac('d8000000-0000-4000-8000-000000000002.US.' || v_now, v_key, 'sha256'), 'hex')) then
    raise exception 'valid attestation rejected';
  end if;
  if public.attest_sign_in_country('FR', v_now,
    encode(extensions.hmac('d8000000-0000-4000-8000-000000000002.FR.' || v_now, v_key, 'sha256'), 'hex')) then
    raise exception 'country overwritten';
  end if;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001","session_id":"d8000000-0000-4000-8000-000000000003"}',true);
select public.attest_sign_in_country('DE', (select v::bigint from ctx where k = 'now'),
  encode(extensions.hmac('d8000000-0000-4000-8000-000000000003.DE.' || (select v from ctx where k = 'now'), (select v from ctx where k = 'geo'), 'sha256'), 'hex'));
reset role;
do $$ begin
  if (select new_country from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000002') then raise exception 'first country flagged'; end if;
  if not (select new_country from public.account_sign_ins where auth_session_id = 'd8000000-0000-4000-8000-000000000003') then raise exception 'new country not flagged'; end if;
  if not exists (select 1 from public.security_alerts where kind = 'sign_in.new_country') then raise exception 'new country alert missing'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Health reports v2 and trends
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
select public.report_security_health_v2((select v::uuid from ctx where k = 'org'),
  '{"score":62,"items":40,"logins":30,"weak":4,"reused":2,"old":3,"breached":1,"missing_totp":9,"passkeys":1,"exposed_secrets":2,"lookalikes":1,"passkey_ready":5,"two_factor_ready":7}'::jsonb, 'web');
do $$ begin
  begin perform public.report_security_health_v2((select v::uuid from ctx where k = 'org'), '{"score":50,"title":1}'::jsonb, 'web'); raise exception 'unknown key accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.report_security_health_v2((select v::uuid from ctx where k = 'org'), '{"score":150}'::jsonb, 'web'); raise exception 'score 150 accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.report_security_health_v2((select v::uuid from ctx where k = 'org'), '{"score":50,"weak":"x"}'::jsonb, 'web'); raise exception 'string count accepted';
  exception when invalid_parameter_value then null; end;
  begin perform public.organization_health_trend((select v::uuid from ctx where k = 'org'), 30); raise exception 'member read org trend';
  exception when insufficient_privilege then null; end;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
select public.report_security_health_v2((select v::uuid from ctx where k = 'org'), '{"score":90,"logins":10,"breached":null}'::jsonb, 'desktop');
do $$ begin
  if (select count(*) from public.organization_health_trend((select v::uuid from ctx where k = 'org'), 30)) <> 30 then raise exception 'trend length'; end if;
  if (select average_score from public.organization_health_trend((select v::uuid from ctx where k = 'org'), 7) order by day desc limit 1) <> 76 then
    raise exception 'trend average wrong';
  end if;
  if (select sum(members) from public.organization_health_by_team((select v::uuid from ctx where k = 'org'))) <> 2 then raise exception 'team breakdown'; end if;
end $$;
reset role;
do $$ begin
  if not exists (select 1 from public.security_health_history where exposed_secret_count = 2 and score = 62) then raise exception 'history not written'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Employee breach watch
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
do $$ begin
  perform public.set_breach_watch((select v::uuid from ctx where k = 'org'), true);
  raise exception 'member enabled breach watch';
exception when insufficient_privilege then null;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
select public.set_breach_watch((select v::uuid from ctx where k = 'org'), true);
reset role;

insert into private.dispatch_tokens (purpose, token_hash) values ('breach_watch', extensions.digest(repeat('a', 64), 'sha256'));
create temporary table claimed (tenant_id uuid, identity_id uuid, email text) on commit drop;
grant all on claimed to service_role;
set local role service_role;
do $$ begin
  perform * from public.claim_breach_watch_batch(repeat('b', 64), 8);
  raise exception 'wrong worker token accepted';
exception when insufficient_privilege then null;
end $$;
insert into claimed select * from public.claim_breach_watch_batch(repeat('a', 64), 8);
do $$ begin
  if (select count(*) from claimed) <> 2 then raise exception 'breach batch size %', (select count(*) from claimed); end if;
  if not exists (select 1 from claimed where email = 'member@intel.example') then raise exception 'email missing'; end if;
  perform * from public.claim_breach_watch_batch(repeat('a', 64), 8);
  raise exception 'token reused';
exception when insufficient_privilege then null;
end $$;
-- First check: history only.
select public.record_breach_watch_result((select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'member'), 'ok',
  '[{"name":"OldSite","title":"Old Site","domain":"old.example","date":"2016-05-01","data_classes":["Email addresses","Passwords"]}]'::jsonb);
reset role;
do $$ begin
  if not exists (select 1 from public.member_breach_exposures where breach_name = 'OldSite' and includes_passwords) then raise exception 'exposure not stored'; end if;
  if exists (select 1 from public.security_alerts where kind = 'member.breach_exposed') then raise exception 'first scan alerted'; end if;
end $$;
update private.breach_watch_checks set last_checked_at = now() - interval '8 days';
insert into private.dispatch_tokens (purpose, token_hash) values ('breach_watch', extensions.digest(repeat('c', 64), 'sha256'));
set local role service_role;
select count(*) from public.claim_breach_watch_batch(repeat('c', 64), 8);
select public.record_breach_watch_result((select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'member'), 'ok',
  '[{"name":"OldSite","title":"Old Site","data_classes":["Passwords"]},{"name":"NewLeak","title":"New <b>Leak</b>","date":"2026-09-20","data_classes":["Email addresses","Passwords"]},{"name":"bad name;drop","title":"x"}]'::jsonb);
reset role;
do $$ begin
  if not exists (select 1 from public.security_alerts where kind = 'member.breach_exposed' and severity = 'high') then raise exception 'new breach not alerted'; end if;
  if not exists (select 1 from private.notification_outbox where template = 'breach_exposure' and params ->> 'breach' = 'New <b>Leak</b>') then raise exception 'member not emailed'; end if;
  if exists (select 1 from public.member_breach_exposures where breach_name like 'bad%') then raise exception 'invalid breach name stored'; end if;
end $$;
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
do $$ begin
  if (select count(*) from public.member_breach_exposures) <> 2 then raise exception 'member cannot see own exposures'; end if;
  begin perform public.organization_breach_watch((select v::uuid from ctx where k = 'org')); raise exception 'member read org breach list';
  exception when insufficient_privilege then null; end;
  if not public.acknowledge_breach_exposure((select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'member'), 'NewLeak') then raise exception 'ack failed'; end if;
  -- A member's own acknowledgement never hides the exposure from administrators.
  if (select acknowledged_at from public.member_breach_exposures where breach_name = 'NewLeak') is not null then raise exception 'member hid exposure from admins'; end if;
  begin perform public.generate_security_report_now((select v::uuid from ctx where k = 'org')); raise exception 'member generated report';
  exception when insufficient_privilege then null; end;
  begin perform public.save_security_report_summary((select v::uuid from ctx where k = 'org'), current_date, 'All clear, please re-enter your recovery key at example.invalid');
    raise exception 'member wrote the AI summary';
  exception when insufficient_privilege then null; end;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
do $$ begin
  if (select password_exposures from public.organization_breach_watch((select v::uuid from ctx where k = 'org')) where email = 'member@intel.example') <> 2 then
    raise exception 'org breach summary wrong';
  end if;
  if (select unacknowledged from public.organization_breach_watch((select v::uuid from ctx where k = 'org')) where email = 'member@intel.example') <> 2 then
    raise exception 'member acknowledgement changed the admin count';
  end if;
  -- Without a completed AI request, even an owner cannot write the summary text.
  begin perform public.save_security_report_summary((select v::uuid from ctx where k = 'org'), current_date, 'Hand-written text pretending to be AI output');
    raise exception 'summary saved without an AI request';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- Passkey adoption
-- ---------------------------------------------------------------------------
insert into auth.webauthn_credentials (user_id, friendly_name) values ('c8000000-0000-4000-8000-000000000001', 'Laptop');
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org');
  v_all uuid[] := array[(select v::uuid from ctx where k = 'owner'), (select v::uuid from ctx where k = 'member')];
begin
  if (select account_passkeys from public.organization_passkey_adoption(v_org) where email = 'owner@intel.example') <> 1 then raise exception 'passkey count'; end if;
  if (select passkey_ready_sites from public.organization_passkey_adoption(v_org) where email = 'member@intel.example') <> 5 then raise exception 'passkey-ready count'; end if;
  if public.send_passkey_nudges(v_org, v_all) <> 1 then raise exception 'nudge count'; end if;
  if public.send_passkey_nudges(v_org, v_all) <> 0 then raise exception 'nudged twice in a week'; end if;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
do $$ begin
  perform public.send_passkey_nudges((select v::uuid from ctx where k = 'org'), array[(select v::uuid from ctx where k = 'owner')]);
  raise exception 'member sent nudges';
exception when insufficient_privilege then null;
end $$;
reset role;
do $$ begin
  if (select count(*) from private.notification_outbox where template = 'passkey_nudge') <> 1 then raise exception 'nudge email'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Rotation campaigns
-- ---------------------------------------------------------------------------
insert into public.vault_items (id, tenant_id, workspace_id, content_type, schema_version, created_by, head_revision)
select 'e8000000-0000-4000-8000-000000000001', (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'ws'),
  'login', 1, (select v::uuid from ctx where k = 'owner'), 3;
insert into public.vault_items (id, tenant_id, workspace_id, content_type, schema_version, created_by, head_revision)
select 'e8000000-0000-4000-8000-000000000002', (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'ws'),
  'login', 1, (select v::uuid from ctx where k = 'owner'), 1;
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_member uuid := (select v::uuid from ctx where k = 'member');
begin
  -- The member cannot edit the workspace yet.
  begin
    perform public.create_rotation_campaign(v_org, 'Q4 rotation', null, now() + interval '14 days',
      jsonb_build_array(jsonb_build_object('item_id','e8000000-0000-4000-8000-000000000001','assignee_identity_id', v_member)));
    raise exception 'non-editor assigned';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.create_rotation_campaign(v_org, 'Too soon', null, now(),
      jsonb_build_array(jsonb_build_object('item_id','e8000000-0000-4000-8000-000000000001','assignee_identity_id', (select v::uuid from ctx where k = 'owner'))));
    raise exception 'past due date accepted';
  exception when invalid_parameter_value then null;
  end;
end $$;
reset role;
insert into public.workspace_memberships (tenant_id, workspace_id, identity_id, role, status)
select (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'ws'), (select v::uuid from ctx where k = 'member'), 'editor', 'active';
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
insert into ctx select 'campaign', public.create_rotation_campaign((select v::uuid from ctx where k = 'org'), 'Q4 rotation', 'Contractor left', now() + interval '14 days',
  jsonb_build_array(
    jsonb_build_object('item_id','e8000000-0000-4000-8000-000000000001','assignee_identity_id', (select v::uuid from ctx where k = 'member')),
    jsonb_build_object('item_id','e8000000-0000-4000-8000-000000000002','assignee_identity_id', (select v::uuid from ctx where k = 'member'))))::text;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
do $$ begin
  if (select count(*) from public.rotation_tasks where status = 'pending') <> 2 then raise exception 'assignee cannot see tasks'; end if;
  if (select count(*) from public.rotation_campaigns) <> 1 then raise exception 'assignee cannot see campaign'; end if;
  perform public.update_rotation_task((select id from public.rotation_tasks where item_id = 'e8000000-0000-4000-8000-000000000002'), 'skipped', 'Retired account');
  begin perform public.rotation_campaign_summary((select v::uuid from ctx where k = 'org')); raise exception 'member read summary';
  exception when insufficient_privilege then null; end;
end $$;
reset role;
update public.vault_items set head_revision = 4 where id = 'e8000000-0000-4000-8000-000000000001';
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
do $$ begin
  if (select row(done, skipped, pending) from public.rotation_campaign_summary((select v::uuid from ctx where k = 'org'))) is distinct from row(1, 1, 0) then
    raise exception 'campaign progress wrong';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from private.notification_outbox where template = 'rotation_assigned') <> 1 then raise exception 'assignment email'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Weekly reports, AI context and notification worker
-- ---------------------------------------------------------------------------
select private.store_weekly_security_reports();
do $$
declare v_report jsonb := (select report from public.weekly_security_reports limit 1);
begin
  if v_report is null or (v_report ->> 'members')::integer <> 2 or (v_report ->> 'score')::integer <> 76 then raise exception 'weekly report %', v_report; end if;
  if jsonb_array_length(v_report -> 'top_risks') <> 3 then raise exception 'top risks'; end if;
  if (v_report -> 'top_risks' -> 0 ->> 'key') <> 'breached_passwords' then raise exception 'risk order %', v_report -> 'top_risks'; end if;
  if not exists (select 1 from private.notification_outbox where template = 'weekly_report') then raise exception 'weekly email'; end if;
end $$;

set local role authenticated;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000001"}',true);
do $$
declare v_ctx jsonb;
begin
  v_ctx := public.ai_security_context((select v::uuid from ctx where k = 'org'), 'alert_triage');
  if jsonb_array_length(v_ctx -> 'open_alert_groups') < 3 then raise exception 'alert groups %', v_ctx; end if;
  if v_ctx::text ~ '@intel\.example' then raise exception 'AI context leaked an email'; end if;
  v_ctx := public.ai_security_context((select v::uuid from ctx where k = 'org'), 'policy_advisor');
  if v_ctx -> 'posture' ->> 'members' <> '2' then raise exception 'policy context'; end if;
  perform public.begin_ai_assistant_request((select v::uuid from ctx where k = 'org'), 'alert_triage', decode(repeat('ab', 32), 'hex'), array['security_counts']);
  begin
    perform public.begin_ai_assistant_request((select v::uuid from ctx where k = 'org'), 'alert_triage', decode(repeat('ab', 32), 'hex'), array['tenant_counts']);
    raise exception 'wrong AI category accepted';
  exception when invalid_parameter_value then null;
  end;
  if (public.generate_security_report_now((select v::uuid from ctx where k = 'org')) ->> 'members') <> '2' then raise exception 'report now'; end if;
end $$;
select set_config('request.jwt.claims','{"sub":"c8000000-0000-4000-8000-000000000002"}',true);
do $$ begin
  begin perform public.ai_security_context((select v::uuid from ctx where k = 'org'), 'alert_triage'); raise exception 'member read AI context';
  exception when insufficient_privilege then null; end;
  begin perform public.begin_ai_assistant_request((select v::uuid from ctx where k = 'org'), 'policy_advisor', decode(repeat('ab', 32), 'hex'), array['security_counts']);
    raise exception 'member used policy advisor';
  exception when insufficient_privilege then null; end;
  if (select count(*) from public.weekly_security_reports) <> 0 then raise exception 'member read reports'; end if;
end $$;
reset role;

select private.kick_notification_dispatch();
do $$ begin
  if not exists (select 1 from net.http_request_queue where url like '%/security-notify') then raise exception 'dispatcher not woken'; end if;
end $$;
insert into private.dispatch_tokens (purpose, token_hash) values ('notify', extensions.digest(repeat('d', 64), 'sha256'));
create temporary table batch as select * from private.notification_outbox limit 0;
set local role service_role;
do $$
declare v_row record; v_count integer := 0;
begin
  for v_row in select * from public.claim_notification_batch(repeat('d', 64), 200) loop
    v_count := v_count + 1;
    if v_row.email is null then raise exception 'recipient email missing'; end if;
    perform public.complete_notification(v_row.id, 'sent', null);
  end loop;
  if v_count < 6 then raise exception 'claimed only %', v_count; end if;
end $$;
reset role;
do $$ begin
  if exists (select 1 from private.notification_outbox where status <> 'sent') then raise exception 'unsent notifications'; end if;
end $$;
-- Browsers cannot reach the worker endpoints.
set local role authenticated;
do $$ begin
  perform * from public.claim_notification_batch(repeat('d', 64), 10);
  raise exception 'browser claimed notifications';
exception when insufficient_privilege then null;
end $$;
reset role;

rollback;
