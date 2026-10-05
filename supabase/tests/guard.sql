-- Passkey-X Guard: device/finding reports, alerts, visibility, policy, phishing reports and threat lists.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('ca000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','owner@guard.example',now(),'',now(),now()),
  ('ca000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','member@guard.example',now(),'',now(),now()),
  ('ca000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','outsider@guard.example',now(),'',now(),now());

create temporary table ident (actor text primary key, bootstrap jsonb) on commit drop;
grant all on ident to authenticated, service_role;
set local role authenticated;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000001',true);
insert into ident values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
insert into ident values ('member', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000003',true);
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
insert into ctx select 'member', bootstrap ->> 'identity_id' from ident where actor = 'member';
insert into ctx select 'outsider', bootstrap ->> 'identity_id' from ident where actor = 'outsider';
insert into ctx select 'outsider_tenant', bootstrap ->> 'tenant_id' from ident where actor = 'outsider';

update public.tenants set kind = 'organization' where id = (select v::uuid from ctx where k = 'org');
insert into public.tenant_entitlements (tenant_id, plan_code, subscription_status, source, max_members)
  select v::uuid, 'business', 'active', 'manual', 50 from ctx where k = 'org'
  on conflict (tenant_id) do update set plan_code = 'business', subscription_status = 'active', source = 'manual', max_members = 50;
insert into public.tenant_memberships (tenant_id, identity_id, role, status)
  select (select v::uuid from ctx where k = 'org'), (select v::uuid from ctx where k = 'member'), 'member', 'active';

-- ---------------------------------------------------------------------------
-- Policy: only security administrators set it; members receive the merged policy.
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
do $$ begin
  begin
    perform public.set_guard_policy((select v::uuid from ctx where k = 'org'), '{"webMode":"off"}');
    raise exception 'member changed the policy';
  exception when insufficient_privilege then null; end;
  if (public.my_guard_policy() ->> 'webMode') <> 'warn' or (public.my_guard_policy() ->> 'managed')::boolean then
    raise exception 'default policy wrong: %', public.my_guard_policy();
  end if;
end $$;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000001',true);
select public.set_guard_policy((select v::uuid from ctx where k = 'org'), jsonb_build_object(
  'webMode', 'block', 'blockSuspicious', true, 'requireExtension', true, 'organizationName', 'Acme Corp',
  'blockDomains', jsonb_build_array('https://Casino.example/path', '*.bad.example', 'not a domain', 'x'),
  'protectedDomains', jsonb_build_array('acme.example'), 'softwareBlock', jsonb_build_array(' uTorrent ', 'AnyDesk')));
do $$ begin
  begin
    perform public.set_guard_policy((select v::uuid from ctx where k = 'org'), '{"webMode":"explode"}');
    raise exception 'invalid mode accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
do $$
declare v_policy jsonb := public.my_guard_policy();
begin
  if v_policy ->> 'webMode' <> 'block' or not (v_policy ->> 'blockSuspicious')::boolean or not (v_policy ->> 'requireExtension')::boolean
     or v_policy ->> 'organizationName' <> 'Acme Corp' or not (v_policy ->> 'managed')::boolean then
    raise exception 'merged policy wrong: %', v_policy;
  end if;
  if (select array_agg(value order by value) from jsonb_array_elements_text(v_policy -> 'blockDomains')) <> array['bad.example','casino.example'] then
    raise exception 'domains not cleaned: %', v_policy -> 'blockDomains';
  end if;
  if (select array_agg(value order by value) from jsonb_array_elements_text(v_policy -> 'softwareBlock')) <> array['anydesk','utorrent'] then
    raise exception 'software names not cleaned: %', v_policy -> 'softwareBlock';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Devices and findings
-- ---------------------------------------------------------------------------
create temporary table ep (id uuid) on commit drop;
grant all on ep to authenticated;
insert into ep select public.report_guard_endpoint('ea000000-0000-4000-8000-000000000001', 'desktop', 'windows', 'Windows laptop',
  'Windows 11 23H2', '1.2.0', '{"disk_encrypted": false, "firewall": true, "screen_lock": true}', 412, 1);
select public.report_guard_endpoint('ea000000-0000-4000-8000-000000000002', 'extension', 'chrome', 'Chrome', null, '0.6.0', '{}');
do $$ begin
  begin
    perform public.report_guard_endpoint('ea000000-0000-4000-8000-000000000003', 'desktop', 'windows', 'x', null, null, '{"browsing_history": []}');
    raise exception 'unknown posture key accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select public.report_guard_findings('ea000000-0000-4000-8000-000000000001', jsonb_build_array(
  jsonb_build_object('source','extension','category','web','kind','phishing_site','severity','critical','subject','paypa1-login.example',
    'action','blocked','detail', jsonb_build_object('reason','threat_list')),
  jsonb_build_object('source','desktop','category','software','kind','risky_software','severity','high','subject','uTorrent 3.5',
    'action','detected','key','software:utorrent'),
  jsonb_build_object('source','desktop','category','device','kind','disk_not_encrypted','severity','medium','subject','Disk encryption is off',
    'action','detected','key','device:disk_encrypted')));
-- Seen again: one open finding with two occurrences.
select public.report_guard_findings('ea000000-0000-4000-8000-000000000001', jsonb_build_array(
  jsonb_build_object('source','extension','category','web','kind','phishing_site','severity','critical','subject','paypa1-login.example','action','proceeded')));
do $$ begin
  begin
    perform public.report_guard_findings('ea000000-0000-4000-8000-000000000001',
      jsonb_build_array(jsonb_build_object('source','extension','category','web','kind','phishing_site','severity','apocalyptic','subject','x','action','blocked')));
    raise exception 'invalid severity accepted';
  exception when invalid_parameter_value then null; end;
end $$;
do $$
declare v_member uuid := (select v::uuid from ctx where k = 'member');
begin
  if (select occurrences from public.guard_findings where identity_id = v_member and kind = 'phishing_site') <> 2 then raise exception 'duplicate not merged'; end if;
  if (select action from public.guard_findings where identity_id = v_member and kind = 'phishing_site') <> 'proceeded' then raise exception 'latest action not kept'; end if;
  if (select count(*) from public.guard_findings) <> 3 then raise exception 'member cannot see own findings'; end if;
  if (select count(*) from public.guard_endpoints) <> 2 then raise exception 'member cannot see own devices'; end if;
  if public.resolve_guard_findings('ea000000-0000-4000-8000-000000000001', array['device:disk_encrypted','phishing_site:paypa1-login.example']) <> 1 then
    raise exception 'only device/software findings may be resolved by the app';
  end if;
end $$;

-- Outsider: sees nothing; cannot read the dashboard.
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000003',true);
do $$ begin
  if (select count(*) from public.guard_findings) <> 0 or (select count(*) from public.guard_endpoints) <> 0 then raise exception 'outsider sees findings'; end if;
  begin
    perform public.organization_guard_overview((select v::uuid from ctx where k = 'org'));
    raise exception 'outsider read the overview';
  exception when insufficient_privilege then null; end;
end $$;

-- Owner (organization admin): sees the member's devices and findings, and the alerts.
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000001',true);
do $$
declare v_org uuid := (select v::uuid from ctx where k = 'org'); v_overview jsonb;
begin
  if (select count(*) from public.guard_findings) <> 3 then raise exception 'admin cannot see member findings'; end if;
  v_overview := public.organization_guard_overview(v_org);
  if (v_overview -> 'open' ->> 'critical')::int <> 1 or (v_overview -> 'open' ->> 'high')::int <> 1
     or (v_overview -> 'coverage' ->> 'extension')::int <> 1 or (v_overview -> 'coverage' ->> 'desktop')::int <> 1
     or (v_overview -> 'devices' ->> 'atRisk')::int <> 1 or (v_overview -> 'last7Days' ->> 'proceeded')::int <> 2 then
    raise exception 'overview wrong: %', v_overview;
  end if;
  if (select count(*) from public.organization_guard_findings(v_org, 'open', null, 50) where member_email = 'member@guard.example') <> 2 then
    raise exception 'findings list wrong';
  end if;
  if (select count(*) from public.organization_guard_endpoints(v_org) where kind = 'desktop' and open_findings = 2) <> 1 then
    raise exception 'endpoint list wrong';
  end if;
  if (select count(*) from public.security_alerts where tenant_id = v_org and kind like 'guard.%') <> 2 then
    raise exception 'alerts: %', (select array_agg(kind) from public.security_alerts where tenant_id = v_org);
  end if;
  perform public.set_guard_finding_status(v_org, (select id from public.guard_findings where kind = 'risky_software'), 'dismissed');
  if (select status from public.guard_findings where kind = 'risky_software') <> 'dismissed' then raise exception 'status not set'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- Phishing reports and threat lists
-- ---------------------------------------------------------------------------
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
select public.report_phishing('evil-login.example/sign-in', 'evil-login.example',
  encode(extensions.digest('evil-login.example/sign-in', 'sha256'), 'base64'), 'Fake Microsoft login');
do $$ begin
  if public.report_phishing('evil-login.example/sign-in', 'evil-login.example',
       encode(extensions.digest('evil-login.example/sign-in', 'sha256'), 'base64')) is not null then
    raise exception 'duplicate pending report';
  end if;
  begin
    perform public.report_phishing('x', 'BAD HOST', encode(extensions.digest('x', 'sha256'), 'base64'));
    raise exception 'invalid host accepted';
  exception when invalid_parameter_value then null; end;
  if exists (select 1 from public.threat_matches(array[encode(substring(extensions.digest('evil-login.example/sign-in', 'sha256') from 1 for 4), 'base64')])) then
    raise exception 'unreviewed report already blocks';
  end if;
end $$;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000001',true);
select public.review_threat_report((select v::uuid from ctx where k = 'org'), (select id from public.organization_threat_reports((select v::uuid from ctx where k = 'org'))), true);
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
do $$
declare v_prefix text := encode(substring(extensions.digest('evil-login.example/sign-in', 'sha256') from 1 for 4), 'base64');
begin
  if not exists (select 1 from public.threat_matches(array[v_prefix]) where source = 'your organization' and threat = 'phishing'
      and hash = encode(extensions.digest('evil-login.example/sign-in', 'sha256'), 'base64')) then
    raise exception 'confirmed report not matched';
  end if;
  if not v_prefix = any(public.my_threat_prefixes()) then raise exception 'organization prefix missing'; end if;
  begin
    perform public.threat_matches(array['AAAA']);
    raise exception 'short prefix accepted';
  exception when invalid_parameter_value then null; end;
end $$;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000003',true);
do $$ begin
  if exists (select 1 from public.threat_matches(array[encode(substring(extensions.digest('evil-login.example/sign-in', 'sha256') from 1 for 4), 'base64')])) then
    raise exception 'another organization''s list leaked';
  end if;
  begin
    perform public.replace_threat_feed('urlhaus', 'malware', array['x'], null);
    raise exception 'member replaced a feed';
  exception when insufficient_privilege then null; end;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;

-- Community intelligence: confirmed by three organizations → blocked for every customer.
-- Two other organizations already confirmed the same page; this organization is the first one.
do $$
declare v_hash bytea := extensions.digest('evil-login.example/sign-in', 'sha256'); v_tenant uuid; v_owner uuid := (select v::uuid from ctx where k = 'owner');
begin
  insert into public.tenants (kind, created_by) values ('organization', v_owner) returning id into v_tenant;
  insert into public.threat_reports (tenant_id, identity_id, expression, host, hash, status)
  values (v_tenant, v_owner, 'evil-login.example/sign-in', 'evil-login.example', v_hash, 'confirmed');
end $$;
set local role authenticated;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000003',true);
do $$ begin
  if exists (select 1 from public.threat_matches(array[encode(substring(extensions.digest('evil-login.example/sign-in', 'sha256') from 1 for 4), 'base64')])) then
    raise exception 'community block with only two confirmations';
  end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;
do $$
declare v_hash bytea := extensions.digest('evil-login.example/sign-in', 'sha256'); v_tenant uuid; v_owner uuid := (select v::uuid from ctx where k = 'owner');
begin
  insert into public.tenants (kind, created_by) values ('organization', v_owner) returning id into v_tenant;
  insert into public.threat_reports (tenant_id, identity_id, expression, host, hash, status)
  values (v_tenant, v_owner, 'evil-login.example/sign-in', 'evil-login.example', v_hash, 'confirmed');
end $$;
-- A new report in this organization is confirmed: three organizations now agree.
set local role authenticated;
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000002',true);
select public.report_phishing('evil-login.example/sign-in', 'evil-login.example',
  encode(extensions.digest('evil-login.example/sign-in', 'sha256'), 'base64'));
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000001',true);
select public.review_threat_report((select v::uuid from ctx where k = 'org'), (select id from public.organization_threat_reports((select v::uuid from ctx where k = 'org'))), true);
select set_config('request.jwt.claim.sub','ca000000-0000-4000-8000-000000000003',true);
do $$ begin
  if not exists (select 1 from public.threat_matches(array[encode(substring(extensions.digest('evil-login.example/sign-in', 'sha256') from 1 for 4), 'base64')])
      where source = 'Passkey-X community') then
    raise exception 'community block missing after three confirmations';
  end if;
end $$;
select set_config('request.jwt.claim.sub','',true);
reset role;

-- Feeds (service role) and the background-job token.
set local role service_role;
select public.replace_threat_feed('urlhaus', 'malware',
  array[encode(extensions.digest('malware.example/payload.exe', 'sha256'), 'base64'), 'bm90LWEtaGFzaA=='],
  array['malware.example/payload.exe', 'x']);
do $$ begin
  if not encode(substring(extensions.digest('malware.example/payload.exe', 'sha256') from 1 for 4), 'base64') = any(public.global_threat_prefixes()) then
    raise exception 'feed prefix not published';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from private.threat_indicators where source = 'urlhaus') <> 1 then raise exception 'invalid hash stored'; end if;
end $$;
insert into private.dispatch_tokens (purpose, token_hash) values ('threat_sync', extensions.digest('t', 'sha256'));
do $$ begin
  if not exists (select 1 from storage.buckets where id = 'threat-intel' and not public) then raise exception 'bucket missing or public'; end if;
end $$;

rollback;
