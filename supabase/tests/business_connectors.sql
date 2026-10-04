-- Chat alerts, SIEM destinations, API keys, sealed workspace key grants, SCIM groups,
-- organization workspaces and SSO activation state.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('c9000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','owner@conn.example',now(),'',now(),now()),
  ('c9000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','dev@conn.example',now(),'',now(),now()),
  ('c9000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','outsider@conn.example',now(),'',now(),now());

create temporary table ident (actor text primary key, bootstrap jsonb) on commit drop;
grant all on ident to authenticated, service_role;
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
insert into ident values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
insert into ident values ('dev', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000003',true);
insert into ident values ('outsider', public.bootstrap_personal_vault(
  decode(repeat('31',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'), decode(repeat('34',12),'hex'), decode(repeat('35',48),'hex'),
  decode(repeat('36',32),'hex'), decode(repeat('37',12),'hex'), decode(repeat('38',48),'hex'), decode(repeat('39',65),'hex')));
select set_config('request.jwt.claim.sub','',true);
reset role;

create temporary table ctx (k text primary key, v text) on commit drop;
grant all on ctx to authenticated, service_role;
insert into ctx select 'org', bootstrap ->> 'tenant_id' from ident where actor = 'owner';
insert into ctx select 'owner', bootstrap ->> 'identity_id' from ident where actor = 'owner';
insert into ctx select 'dev', bootstrap ->> 'identity_id' from ident where actor = 'dev';
insert into ctx select 'outsider', bootstrap ->> 'identity_id' from ident where actor = 'outsider';

update public.tenants set kind = 'organization' where id = (select v::uuid from ctx where k = 'org');
insert into public.tenant_entitlements (tenant_id, plan_code, subscription_status, source, max_members, max_workspaces)
  select v::uuid, 'business', 'active', 'manual', 50, 20 from ctx where k = 'org'
  on conflict (tenant_id) do update set plan_code = 'business', subscription_status = 'active', source = 'manual', max_members = 50, max_workspaces = 20;
insert into public.tenant_memberships (tenant_id, identity_id, role, status)
  select (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'dev'), 'member', 'active';

-- ---------------------------------------------------------------------------
-- Slack / Teams channels
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_id uuid;
begin
  begin
    perform public.create_chat_channel(v_org, 'slack', 'Bad', 'https://evil.example.com/services/T000/B000/XXXX');
    raise exception 'non-slack url accepted';
  exception when sqlstate '22023' then null; end;
  begin
    perform public.create_chat_channel(v_org, 'teams', 'Bad', 'https://hooks.slack.com/services/T000/B000/XXXXXXXX');
    raise exception 'slack url accepted for teams';
  exception when sqlstate '22023' then null; end;
  v_id := public.create_chat_channel(v_org, 'slack', '#security', 'https://hooks.slack.com/services/T0001/B0001/abcdefghijkl', null, 'high');
  insert into ctx values ('slack', v_id);
  insert into ctx values ('teams', public.create_chat_channel(v_org, 'teams', 'Security team',
    'https://prod-12.westeurope.logic.azure.com:443/workflows/0123456789abcdef/triggers/manual/paths/invoke?api-version=2016-06-01&sig=abc',
    array['weekly_report'], 'critical'));
end $$;
-- The webhook URL is write-only.
do $$ begin
  perform 1 from private.chat_channel_secrets;
  raise exception 'chat secrets readable';
exception when insufficient_privilege then null; end $$;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform public.create_chat_channel((select v::uuid from ctx where k = 'org'), 'slack', 'Dev', 'https://hooks.slack.com/services/T0001/B0002/abcdefghijkl');
  raise exception 'member created a channel';
exception when insufficient_privilege then null; end $$;
do $$ begin
  if exists (select 1 from public.chat_channels) then raise exception 'member can read channels'; end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;

insert into public.security_alerts (tenant_id, severity, kind, title, dedupe_key)
  select v::uuid, 'high', 'vault.exported', 'Vault exported', 'conn-1' from ctx where k = 'org';
insert into public.security_alerts (tenant_id, severity, kind, title, dedupe_key)
  select v::uuid, 'low', 'policy.changed', 'Policy changed', 'conn-2' from ctx where k = 'org';
insert into public.weekly_security_reports (tenant_id, week_start, report)
  select v::uuid, '2026-10-05', '{"score": 81, "score_week_ago": 77, "top_risks": []}'::jsonb from ctx where k = 'org';
do $$
declare v_slack uuid := (select v::uuid from ctx where k = 'slack'); v_teams uuid := (select v::uuid from ctx where k = 'teams');
begin
  if (select count(*) from private.chat_queue where channel_id = v_slack and event = 'alerts') <> 1 then raise exception 'severity filter wrong'; end if;
  if (select count(*) from private.chat_queue where channel_id = v_slack and event = 'weekly_report') <> 1 then raise exception 'weekly report not queued for slack'; end if;
  if (select count(*) from private.chat_queue where channel_id = v_teams) <> 1 then raise exception 'teams subscription wrong'; end if;
  if private.deliver_chat_notifications() <> 3 then raise exception 'chat messages not sent'; end if;
  if (select count(*) from private.audit_webhook_outbox where format in ('slack','teams')) <> 3 then raise exception 'chat not queued through relay'; end if;
  if exists (select 1 from private.audit_webhook_outbox where format = 'slack' and url not like 'https://hooks.slack.com/%') then raise exception 'wrong url'; end if;
end $$;
-- Relay answers: one success, the rest fail and are retried with backoff.
insert into net._http_response (id, status_code)
  select request_id, case when row_number() over (order by id) = 1 then 200 else 500 end from private.chat_queue where request_id is not null;
select private.deliver_chat_notifications();
do $$ begin
  if (select count(*) from private.chat_queue) <> 2 then raise exception 'delivered message not removed'; end if;
  if exists (select 1 from private.chat_queue where request_id is not null or attempts <> 1 or next_attempt_at <= now()) then raise exception 'retry backoff wrong'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- SIEM destinations
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_row record;
begin
  select * into v_row from public.create_audit_destination(v_org, 'Datadog', 'datadog', null, '{"site":"datadoghq.eu"}', '0123456789abcdef0123456789abcdef');
  if v_row.secret is not null then raise exception 'vendor destination returned a secret'; end if;
  if (select url from public.audit_webhooks where id = v_row.id) <> 'https://http-intake.logs.datadoghq.eu/api/v2/logs' then raise exception 'datadog url wrong'; end if;
  insert into ctx values ('dd', v_row.id);
  begin
    perform public.create_audit_destination(v_org, 'DD', 'datadog', null, '{"site":"evil.example.com"}', '0123456789abcdef0123456789abcdef');
    raise exception 'unknown datadog site accepted';
  exception when sqlstate '22023' then null; end;
  begin
    perform public.create_audit_destination(v_org, 'Sentinel', 'sentinel', null,
      '{"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"11111111-2222-3333-4444-666666666666","endpoint":"https://evil.example.com","dcr_id":"dcr-0123456789abcdef0123456789abcdef","stream":"Custom-PasskeyX"}', 'secret-value-123');
    raise exception 'sentinel endpoint not validated';
  exception when sqlstate '22023' then null; end;
  select * into v_row from public.create_audit_destination(v_org, 'Sentinel', 'sentinel', null,
    '{"tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"11111111-2222-3333-4444-666666666666","endpoint":"https://px-abc1.westeurope-1.ingest.monitor.azure.com","dcr_id":"dcr-0123456789abcdef0123456789abcdef","stream":"Custom-PasskeyX"}', 'secret-value-123');
  if (select url from public.audit_webhooks where id = v_row.id) not like 'https://px-abc1.westeurope-1.ingest.monitor.azure.com/dataCollectionRules/dcr-0123456789abcdef0123456789abcdef/streams/Custom-PasskeyX?api-version=%' then
    raise exception 'sentinel url wrong';
  end if;
  select * into v_row from public.create_audit_destination(v_org, 'Splunk', 'splunk_hec', 'https://splunk.example.com:8088', '{"index":"security"}', '12345678-aaaa-bbbb-cccc-1234567890ab');
  if (select url from public.audit_webhooks where id = v_row.id) <> 'https://splunk.example.com:8088/services/collector/event' then raise exception 'splunk url wrong'; end if;
  select * into v_row from public.create_audit_destination(v_org, 'Generic', 'generic', 'https://siem.example.com/hook');
  if v_row.secret !~ '^pxwh_' then raise exception 'generic secret missing'; end if;
  begin
    perform public.create_audit_destination(v_org, 'Too many', 'generic', 'https://siem.example.com/hook2');
    perform public.create_audit_destination(v_org, 'Too many', 'generic', 'https://siem.example.com/hook3');
    raise exception 'webhook limit not enforced';
  exception when sqlstate 'P0001' then null; end;
end $$;
do $$ begin
  perform 1 from private.audit_webhook_credentials;
  raise exception 'credentials readable';
exception when insufficient_privilege then null; end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
-- Vendor deliveries carry format, settings and credential to the relay; the generic one is signed.
do $$
declare v_dd public.audit_webhooks; v_out record;
begin
  select * into v_dd from public.audit_webhooks where id = (select v::uuid from ctx where k = 'dd');
  perform private.post_audit_webhook(v_dd, '{"events":[]}'::jsonb);
  select * into v_out from private.audit_webhook_outbox where webhook_id = v_dd.id order by id desc limit 1;
  if v_out.format <> 'datadog' or v_out.credential <> '0123456789abcdef0123456789abcdef' or v_out.config ->> 'site' <> 'datadoghq.eu' then
    raise exception 'datadog delivery not shaped for relay';
  end if;
  if v_out.headers ? 'X-PasskeyX-Signature' then raise exception 'vendor delivery should not be HMAC signed'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Organization API keys
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_row record;
begin
  begin
    perform public.create_org_api_key(v_org, 'Bad', array['vault:read']);
    raise exception 'unknown scope accepted';
  exception when sqlstate '22023' then null; end;
  select * into v_row from public.create_org_api_key(v_org, 'SIEM pull', array['audit:read','alerts:read'], 30);
  if v_row.token !~ '^pxk_[0-9a-f]{64}$' then raise exception 'token format'; end if;
  insert into ctx values ('key', v_row.id), ('token', v_row.token);
end $$;
do $$ begin
  perform 1 from private.org_api_key_hashes;
  raise exception 'key hashes readable';
exception when insufficient_privilege then null; end $$;
do $$ begin
  begin
    perform public.authenticate_org_api_key((select v from ctx where k = 'token'));
    raise exception 'authenticated role can authenticate keys';
  exception when insufficient_privilege then null; end;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
set local role service_role;
do $$
declare v_auth record; v_key uuid := (select v::uuid from ctx where k = 'key');
begin
  select * into v_auth from public.authenticate_org_api_key((select v from ctx where k = 'token'));
  if v_auth.key_id is distinct from v_key or v_auth.rate_limited then raise exception 'api key did not authenticate'; end if;
  if exists (select 1 from public.authenticate_org_api_key('pxk_' || repeat('0', 64))) then raise exception 'wrong key accepted'; end if;
  if (select count(*) from public.api_audit_events(v_key, 0, 500)) = 0 then raise exception 'no audit events'; end if;
  if (select count(*) from public.api_alerts(v_key, 'open', 50)) <> 2 then raise exception 'alerts api'; end if;
  begin
    perform public.api_members(v_key, 0, 10);
    raise exception 'scope not enforced';
  exception when sqlstate '42501' then null; end;
  begin
    perform public.api_update_alert(v_key, (select id from public.security_alerts where dedupe_key = 'conn-1'), 'resolved');
    raise exception 'write scope not enforced';
  exception when sqlstate '42501' then null; end;
end $$;
reset role;
update public.org_api_keys set revoked_at = now() where id = (select v::uuid from ctx where k = 'key');
set local role service_role;
do $$ begin
  if exists (select 1 from public.authenticate_org_api_key((select v from ctx where k = 'token'))) then raise exception 'revoked key accepted'; end if;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- Organization workspace + sealed key grant
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
select public.publish_sharing_key(decode('04' || repeat('aa',64),'hex'), 'aaaa:bbbb:cccc:dddd:eeee:ffff', decode(repeat('01',12),'hex'), decode(repeat('02',80),'hex'));
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000003',true);
select public.publish_sharing_key(decode('04' || repeat('cc',64),'hex'), '1111:2222:3333:4444:5555:6666', decode(repeat('01',12),'hex'), decode(repeat('02',80),'hex'));
-- An outsider cannot see the organization's keys and nobody sees another person's private half.
do $$ begin
  if (select count(*) from public.identity_sharing_keys) <> 1 then raise exception 'outsider sees other sharing keys'; end if;
end $$;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_ws uuid := 'e9000000-0000-4000-8000-0000000000aa'; v_grant uuid;
begin
  if (select count(*) from public.identity_sharing_key_secrets) <> 0 then raise exception 'owner sees others'' private keys'; end if;
  perform public.create_organization_workspace(v_org, v_ws, decode(repeat('41',32),'hex'), decode(repeat('42',12),'hex'),
    decode(repeat('43',32),'hex'), decode(repeat('44',12),'hex'), decode(repeat('45',48),'hex'), 'migration');
  insert into ctx values ('ws', v_ws);
  begin
    perform public.grant_workspace_access(v_ws, (select v::uuid from ctx where k = 'outsider'), 'editor', 1,
      '1111:2222:3333:4444:5555:6666', decode('04' || repeat('bb',64),'hex'), decode(repeat('46',12),'hex'), decode(repeat('47',48),'hex'), 'migration');
    raise exception 'granted access to a non-member';
  exception when sqlstate '22023' then null; end;
  begin
    perform public.grant_workspace_access(v_ws, (select v::uuid from ctx where k = 'dev'), 'editor', 1,
      'ffff:ffff:ffff:ffff:ffff:ffff', decode('04' || repeat('bb',64),'hex'), decode(repeat('46',12),'hex'), decode(repeat('47',48),'hex'), 'migration');
    raise exception 'stale fingerprint accepted';
  exception when sqlstate '40001' then null; end;
  v_grant := public.grant_workspace_access(v_ws, (select v::uuid from ctx where k = 'dev'), 'editor', 1,
    'aaaa:bbbb:cccc:dddd:eeee:ffff', decode('04' || repeat('bb',64),'hex'), decode(repeat('46',12),'hex'), decode(repeat('47',48),'hex'), 'migration');
  insert into ctx values ('grant', v_grant);
end $$;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
do $$
declare v_ws uuid := (select v::uuid from ctx where k = 'ws');
begin
  if (select status from public.workspace_key_grants where id = (select v::uuid from ctx where k = 'grant')) <> 'sealed' then raise exception 'grant not sealed'; end if;
  if public.accept_workspace_key_grant((select v::uuid from ctx where k = 'grant'), decode(repeat('48',12),'hex'), decode(repeat('49',48),'hex')) <> v_ws then
    raise exception 'grant not accepted';
  end if;
  if not exists (select 1 from public.key_envelopes where workspace_id = v_ws and recipient_identity_id = (select v::uuid from ctx where k = 'dev') and revoked_at is null) then
    raise exception 'member key envelope missing';
  end if;
  if exists (select 1 from public.workspace_key_grants where ciphertext is not null) then raise exception 'consumed grant keeps ciphertext'; end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;

-- ---------------------------------------------------------------------------
-- SCIM groups mapped to workspaces
-- ---------------------------------------------------------------------------
insert into public.scim_provisioned_users (tenant_id, external_id, user_name, email_hash, display_name, active)
  select v::uuid, 'okta-dev', 'dev@conn.example', extensions.digest('dev@conn.example', 'sha256'), 'Dev', true from ctx where k = 'org';
insert into ctx select 'scim_dev', id from public.scim_provisioned_users where user_name = 'dev@conn.example';
-- A second workspace the developer is not in yet.
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
select public.create_organization_workspace((select v::uuid from ctx where k = 'org'), 'e9000000-0000-4000-8000-0000000000bb',
  decode(repeat('51',32),'hex'), decode(repeat('52',12),'hex'), decode(repeat('53',32),'hex'), decode(repeat('54',12),'hex'), decode(repeat('55',48),'hex'));
select set_config('request.jwt.claim.sub','',true);
reset role;
set local role service_role;
select public.scim_upsert_group((select v::uuid from ctx where k = 'org'), null, 'grp-1', 'Engineering',
  array[(select v::uuid from ctx where k = 'scim_dev')]);
reset role;
insert into ctx select 'group', id from public.scim_groups where display_name = 'Engineering';
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
select public.set_group_mapping((select v::uuid from ctx where k = 'group'), 'e9000000-0000-4000-8000-0000000000bb', 'viewer');
-- The developer has not joined through SCIM yet: no access.
do $$ begin
  if exists (select 1 from public.workspace_memberships where workspace_id = 'e9000000-0000-4000-8000-0000000000bb' and identity_id = (select v::uuid from ctx where k = 'dev')) then
    raise exception 'access before the SCIM user joined';
  end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
update public.scim_provisioned_users set identity_id = (select v::uuid from ctx where k = 'dev') where id = (select v::uuid from ctx where k = 'scim_dev');
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$
declare v_dev uuid := (select v::uuid from ctx where k = 'dev');
begin
  if (select role from public.workspace_memberships where workspace_id = 'e9000000-0000-4000-8000-0000000000bb' and identity_id = v_dev and status = 'active') <> 'viewer' then
    raise exception 'group mapping did not add the member';
  end if;
  if (select count(*) from public.grants_to_seal((select v::uuid from ctx where k = 'org'))) <> 1 then raise exception 'pending grant not listed'; end if;
  if (select fingerprint from public.grants_to_seal((select v::uuid from ctx where k = 'org'))) <> 'aaaa:bbbb:cccc:dddd:eeee:ffff' then raise exception 'recipient key missing'; end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
-- Removed from the group: access removed, workspace flagged for rotation, grant cancelled.
set local role service_role;
select public.scim_patch_group_members((select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'group'),
  null, array[(select v::uuid from ctx where k = 'scim_dev')]);
reset role;
do $$
declare v_dev uuid := (select v::uuid from ctx where k = 'dev');
begin
  if (select status from public.workspace_memberships where workspace_id = 'e9000000-0000-4000-8000-0000000000bb' and identity_id = v_dev) <> 'revoked' then
    raise exception 'group removal kept access';
  end if;
  if exists (select 1 from public.workspace_key_grants where workspace_id = 'e9000000-0000-4000-8000-0000000000bb' and status in ('pending','sealed')) then
    raise exception 'open grant not cancelled';
  end if;
  -- Access given directly (migration) is not touched by group sync.
  if (select status from public.workspace_memberships where workspace_id = (select v::uuid from ctx where k = 'ws') and identity_id = v_dev) <> 'active' then
    raise exception 'group sync removed manually given access';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- SSO activation state
-- ---------------------------------------------------------------------------
insert into public.sso_connections (tenant_id, domain, verification_token, metadata_url, domain_verified_at)
  select v::uuid, 'conn.example', 'passkey-x-verification=abc', 'https://idp.conn.example/metadata', now() from ctx where k = 'org';
set local role service_role;
select public.set_sso_provider((select v::uuid from ctx where k = 'org'), null, 'saml_not_enabled');
do $$ begin
  if (select status from public.sso_connections where domain = 'conn.example') <> 'requested' then raise exception 'failed activation state'; end if;
end $$;
select public.set_sso_provider((select v::uuid from ctx where k = 'org'), 'f9000000-0000-4000-8000-000000000001', null);
do $$ begin
  if (select status from public.sso_connections where domain = 'conn.example') <> 'active' then raise exception 'sso not active'; end if;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- Hardening: SSO-asserted emails outside the provider's domains are not verified
-- ---------------------------------------------------------------------------
insert into auth.users (id, email, email_confirmed_at, is_sso_user) values
  ('c9000000-0000-4000-8000-0000000000a1', 'alice@victim.example', now(), true),
  ('c9000000-0000-4000-8000-0000000000a2', 'bob@conn.example', now(), true);
insert into auth.sso_domains (sso_provider_id, domain) values ('f9000000-0000-4000-8000-000000000001', 'conn.example');
insert into auth.identities (user_id, provider) values
  ('c9000000-0000-4000-8000-0000000000a1', 'sso:f9000000-0000-4000-8000-000000000001'),
  ('c9000000-0000-4000-8000-0000000000a2', 'sso:f9000000-0000-4000-8000-000000000001');
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-0000000000a1',true);
do $$ begin
  if private.current_verified_email_hash() is not null then raise exception 'foreign-domain SSO email treated as verified'; end if;
end $$;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-0000000000a2',true);
do $$ begin
  if private.current_verified_email_hash() is distinct from extensions.digest('bob@conn.example', 'sha256') then raise exception 'own-domain SSO email not verified'; end if;
end $$;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000001',true);
do $$ begin
  if private.current_verified_email_hash() is null then raise exception 'password account email not verified'; end if;
end $$;
-- The provider stays bound to its domain.
do $$ begin
  update public.sso_connections set domain = 'other.example' where domain = 'conn.example';
  raise exception 'domain changed while SSO is connected';
exception when sqlstate '22023' then null; when insufficient_privilege then null; end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
do $$ begin
  update public.sso_connections set domain = 'other.example' where domain = 'conn.example';
  raise exception 'domain changed while SSO is connected (definer)';
exception when sqlstate '22023' then null; end $$;

-- Hardening: a workspace manager cannot add managers or restore removed access.
update public.workspace_memberships set role = 'manager'
  where workspace_id = (select v::uuid from ctx where k = 'ws') and identity_id = (select v::uuid from ctx where k = 'dev');
insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('c9000000-0000-4000-8000-000000000004','00000000-0000-0000-0000-000000000000','authenticated','authenticated','third@conn.example',now(),'',now(),now());
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000004',true);
insert into ctx values ('third', (public.bootstrap_personal_vault(
  decode(repeat('41',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('42',12),'hex'), decode(repeat('43',48),'hex'), decode(repeat('44',12),'hex'), decode(repeat('45',48),'hex'),
  decode(repeat('46',32),'hex'), decode(repeat('47',12),'hex'), decode(repeat('48',48),'hex'), decode(repeat('49',65),'hex'))) ->> 'identity_id');
select set_config('request.jwt.claim.sub','',true);
reset role;
insert into public.tenant_memberships (tenant_id, identity_id, role, status)
  select (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'third'), 'member', 'active';
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
do $$
declare v_ws uuid := (select v::uuid from ctx where k = 'ws'); v_third uuid := (select v::uuid from ctx where k = 'third');
begin
  begin
    perform public.request_member_access(v_ws, v_third, 'manager');
    raise exception 'manager added a manager';
  exception when insufficient_privilege then null; end;
  perform public.request_member_access(v_ws, v_third, 'viewer');
  begin
    perform public.request_member_access(v_ws, (select v::uuid from ctx where k = 'owner'), 'viewer');
    raise exception 'manager changed the owner';
  exception when insufficient_privilege then null; end;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
update public.workspace_memberships set status = 'revoked'
  where workspace_id = (select v::uuid from ctx where k = 'ws') and identity_id = (select v::uuid from ctx where k = 'third');
set local role authenticated;
select set_config('request.jwt.claim.sub','c9000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform public.request_member_access((select v::uuid from ctx where k = 'ws'), (select v::uuid from ctx where k = 'third'), 'viewer');
  raise exception 'manager restored removed access';
exception when insufficient_privilege then null; end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;

rollback;
