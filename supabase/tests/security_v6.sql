-- v6: two-step enforcement, emergency access, security alerts, compliance,
-- SMS verification atomicity, self-expiry protection and the webhook relay outbox.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('a6000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','v6-owner@example.invalid',now(),'',now(),now()),
  ('a6000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','v6-contact@example.invalid',now(),'',now(),now()),
  ('a6000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','v6-outsider@example.invalid',now(),'',now(),now());

create temporary table v6 (actor text primary key, bootstrap jsonb) on commit drop;
grant all on v6 to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000001',true);
insert into v6 values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
insert into v6 values ('contact', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000003',true);
insert into v6 values ('outsider', public.bootstrap_personal_vault(
  decode(repeat('31',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'), decode(repeat('34',12),'hex'), decode(repeat('35',48),'hex'),
  decode(repeat('36',32),'hex'), decode(repeat('37',12),'hex'), decode(repeat('38',48),'hex'), decode(repeat('39',65),'hex')));
reset role;

-- ---------------------------------------------------------------------------
-- 1. Two-step enforcement: a verified factor makes aal1 sessions see no secrets.
-- ---------------------------------------------------------------------------
insert into auth.mfa_factors (user_id, status, factor_type) values ('a6000000-0000-4000-8000-000000000001','verified','totp');
set local role authenticated;
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000001',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000001","aal":"aal1"}',true);
do $$ begin
  if (select count(*) from public.account_crypto_profiles) <> 0 then raise exception 'aal1 session read the crypto profile'; end if;
  if (select count(*) from public.key_envelopes) <> 0 then raise exception 'aal1 session read key envelopes'; end if;
end $$;
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000001","aal":"aal2"}',true);
do $$ begin
  if (select count(*) from public.account_crypto_profiles) <> 1 then raise exception 'aal2 session cannot read its crypto profile'; end if;
end $$;
-- A user without factors is unaffected at aal1.
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000002","aal":"aal1"}',true);
do $$ begin
  if (select count(*) from public.account_crypto_profiles) <> 1 then raise exception 'user without factors lost access'; end if;
end $$;

-- Vault password rotation needs a recent sign-in (amr), not a fresh iat.
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
select set_config('request.jwt.claims', jsonb_build_object('sub','a6000000-0000-4000-8000-000000000002','aal','aal1',
  'iat', extract(epoch from now())::bigint, 'amr', jsonb_build_array(jsonb_build_object('method','password','timestamp', extract(epoch from now() - interval '2 days')::bigint)))::text, true);
do $$ begin
  perform public.rotate_master_with_session(decode(repeat('22',12),'hex'), decode(repeat('41',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('42',12),'hex'), decode(repeat('43',48),'hex'));
  raise exception 'stale sign-in rotated the vault password';
exception when invalid_authorization_specification then null;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- 2. Emergency access: invite -> accept -> request -> approve -> claim -> activate.
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000001',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000001","aal":"aal2"}',true);
do $$ begin
  perform public.create_emergency_access('e6000000-0000-4000-8000-000000000001',
    ((select bootstrap ->> 'workspace_id' from v6 where actor='owner'))::uuid, 'personal',
    extensions.digest(convert_to('v6-contact@example.invalid','UTF8'),'sha256'), 'Partner',
    1, 72, extensions.digest(decode(repeat('aa',32),'hex'),'sha256'),
    1, decode(repeat('51',12),'hex'), decode(repeat('52',48),'hex'), decode(repeat('53',32),'hex'));
  raise exception 'personal emergency access accepted a 1 hour wait';
exception when invalid_parameter_value then null;
end $$;
select public.create_emergency_access('e6000000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'workspace_id' from v6 where actor='owner'))::uuid, 'personal',
  extensions.digest(convert_to('v6-contact@example.invalid','UTF8'),'sha256'), 'Partner',
  48, 72, extensions.digest(decode(repeat('aa',32),'hex'),'sha256'),
  1, decode(repeat('51',12),'hex'), decode(repeat('52',48),'hex'), decode(repeat('53',32),'hex'));

-- Outsider cannot see or accept it.
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000003',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000003","aal":"aal1"}',true);
do $$ begin
  if exists (select 1 from public.emergency_access_grants) then raise exception 'outsider can see an emergency grant'; end if;
  perform public.accept_emergency_access('e6000000-0000-4000-8000-000000000001', extensions.digest(decode(repeat('aa',32),'hex'),'sha256'),
    decode(repeat('61',12),'hex'), decode(repeat('62',48),'hex'));
  raise exception 'outsider accepted an emergency grant';
exception when invalid_authorization_specification then null;
end $$;

-- Contact sees the invitation, cannot read key columns, and accepts with the token.
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000002","aal":"aal1"}',true);
do $$ begin
  if (select count(*) from public.emergency_access_grants where status = 'invited') <> 1 then raise exception 'contact cannot see invitation'; end if;
  begin
    perform wrapped_workspace_key from public.emergency_access_grants;
    raise exception 'wrapped workspace key column is selectable';
  exception when insufficient_privilege then null;
  end;
end $$;
select public.accept_emergency_access('e6000000-0000-4000-8000-000000000001', extensions.digest(decode(repeat('aa',32),'hex'),'sha256'),
  decode(repeat('61',12),'hex'), decode(repeat('62',48),'hex'));
select public.request_emergency_access('e6000000-0000-4000-8000-000000000001');
do $$ begin
  perform public.claim_emergency_access('e6000000-0000-4000-8000-000000000001');
  raise exception 'claimed before approval or waiting period';
exception when insufficient_privilege then null;
end $$;
do $$ begin
  perform public.decide_emergency_access('e6000000-0000-4000-8000-000000000001', true);
  raise exception 'grantee approved their own request';
exception when insufficient_privilege then null;
end $$;

-- Owner approves; contact claims and activates as a time-limited viewer.
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000001',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000001","aal":"aal2"}',true);
select public.decide_emergency_access('e6000000-0000-4000-8000-000000000001', true);
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000002","aal":"aal1"}',true);
do $$
declare v record;
begin
  select * into v from public.claim_emergency_access('e6000000-0000-4000-8000-000000000001');
  if v.wrapped_workspace_key <> decode(repeat('52',48),'hex') or v.grantee_wrapped_secret <> decode(repeat('62',48),'hex') then
    raise exception 'claim returned wrong envelopes';
  end if;
end $$;
select public.activate_emergency_access('e6000000-0000-4000-8000-000000000001', decode(repeat('71',12),'hex'), decode(repeat('72',48),'hex'));
reset role;
do $$ begin
  if not exists (select 1 from public.workspace_memberships wm
    where wm.workspace_id = (select (bootstrap ->> 'workspace_id')::uuid from v6 where actor='owner')
      and wm.identity_id = (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='contact')
      and wm.role = 'viewer' and wm.expires_at between now() + interval '71 hours' and now() + interval '73 hours') then
    raise exception 'activation did not create a time-limited viewer membership';
  end if;
  if (select status from public.emergency_access_grants where id = 'e6000000-0000-4000-8000-000000000001') <> 'used'
     or (select wrapped_workspace_key from public.emergency_access_grants where id = 'e6000000-0000-4000-8000-000000000001') is not null then
    raise exception 'activated grant kept its key material';
  end if;
  if (select count(*) from public.audit_events where target_type = 'emergency_access_grants') < 5 then
    raise exception 'emergency access is not audited';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Temporary members cannot extend their own access.
-- ---------------------------------------------------------------------------
update public.workspace_memberships set role = 'manager'
  where workspace_id = (select (bootstrap ->> 'workspace_id')::uuid from v6 where actor='owner')
    and identity_id = (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='contact');
set local role authenticated;
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform private.set_workspace_member_expiry((select (bootstrap ->> 'workspace_id')::uuid from v6 where actor='owner'),
    (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='contact'), null);
  raise exception 'temporary manager removed their own expiry';
exception when insufficient_privilege then null;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- 4. Security alerts and compliance snapshot for an organisation.
-- ---------------------------------------------------------------------------
update public.tenants set kind = 'organization' where id = (select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner');
select private.detect_security_alerts(); -- first run initialises the cursor
select private.append_audit_event((select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner'),
  (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='owner'), 'vault.exported', 'client_activity', null, '{}'::jsonb);
select private.append_audit_event((select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner'),
  (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='owner'), 'audit_webhook.deleted', 'audit_webhooks', null, '{}'::jsonb);
do $$
declare v_tenant uuid := (select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner');
begin
  if private.detect_security_alerts() < 2 then raise exception 'alerts not raised'; end if;
  if (select count(*) from public.security_alerts where tenant_id = v_tenant and severity = 'high') <> 2 then
    raise exception 'expected two high alerts';
  end if;
  perform private.detect_security_alerts();
  if (select count(*) from public.security_alerts where tenant_id = v_tenant) <> 2 then raise exception 'alerts duplicated'; end if;
  if not exists (select 1 from public.audit_events where tenant_id = v_tenant and action = 'security_alert.raised') then
    raise exception 'alert not written to the audit log';
  end if;
  if (private.compute_compliance_snapshot(v_tenant) -> 'members' ->> 'active')::integer < 1 then
    raise exception 'compliance snapshot missing members';
  end if;
  if private.store_monthly_compliance_snapshots() < 1 then raise exception 'monthly snapshot not stored'; end if;
end $$;

-- Outsider cannot read the organisation's alerts or report.
set local role authenticated;
select set_config('request.jwt.claim.sub','a6000000-0000-4000-8000-000000000003',true);
select set_config('request.jwt.claims','{"sub":"a6000000-0000-4000-8000-000000000003","aal":"aal1"}',true);
do $$ begin
  if exists (select 1 from public.security_alerts) then raise exception 'outsider read security alerts'; end if;
  perform public.organization_compliance_snapshot((select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner'));
  raise exception 'outsider read the compliance report';
exception when insufficient_privilege then null;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- 5. SMS verification: atomic limits and one attempt per guess.
-- ---------------------------------------------------------------------------
do $$
declare
  v_tenant uuid := (select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner');
  v_identity uuid := (select (bootstrap ->> 'identity_id')::uuid from v6 where actor='owner');
  v_id uuid;
  v_outcome text;
begin
  for i in 1..5 loop
    if not private.create_sms_verification_challenge(gen_random_uuid(), v_tenant, v_identity, decode(repeat('01',32),'hex'), decode(repeat('02',32),'hex')) then
      raise exception 'challenge % refused', i;
    end if;
  end loop;
  if private.create_sms_verification_challenge(gen_random_uuid(), v_tenant, v_identity, decode(repeat('01',32),'hex'), decode(repeat('02',32),'hex')) then
    raise exception 'sixth challenge in an hour was allowed';
  end if;
  select c.id into v_id from public.sms_verification_challenges c where c.identity_id = v_identity limit 1;
  for i in 1..4 loop
    select outcome into v_outcome from private.check_sms_verification_code(v_id, v_tenant, v_identity, decode(repeat('ff',32),'hex'));
    if v_outcome <> 'invalid' then raise exception 'guess % returned %', i, v_outcome; end if;
  end loop;
  select outcome into v_outcome from private.check_sms_verification_code(v_id, v_tenant, v_identity, decode(repeat('01',32),'hex'));
  if v_outcome <> 'verified' then raise exception 'correct fifth guess returned %', v_outcome; end if;
  select outcome into v_outcome from private.check_sms_verification_code(v_id, v_tenant, v_identity, decode(repeat('01',32),'hex'));
  if v_outcome <> 'expired' then raise exception 'verified challenge reusable: %', v_outcome; end if;
end $$;

-- ---------------------------------------------------------------------------
-- 6. Webhook delivery goes through the relay outbox with a one-time token.
-- ---------------------------------------------------------------------------
do $$
declare
  v_hook public.audit_webhooks%rowtype;
  v_request bigint;
  v_body jsonb;
  v_claimed integer;
begin
  insert into public.audit_webhooks (tenant_id, name, url, secret)
  values ((select (bootstrap ->> 'tenant_id')::uuid from v6 where actor='owner'), 'Test', 'https://siem.example.com/hook', 'pxwh_test')
  returning * into v_hook;
  v_request := private.post_audit_webhook(v_hook, '{"hello":"world"}'::jsonb);
  select q.body into v_body from net.http_request_queue q where q.id = v_request;
  if (select q.url from net.http_request_queue q where q.id = v_request) not like '%/functions/v1/audit-relay' then
    raise exception 'webhook was not routed through the relay';
  end if;
  if (select count(*) from private.claim_audit_webhook_delivery((v_body ->> 'id')::bigint, repeat('0', 64))) <> 0 then
    raise exception 'wrong token claimed a delivery';
  end if;
  select count(*) into v_claimed from private.claim_audit_webhook_delivery((v_body ->> 'id')::bigint, v_body ->> 'token')
    where url = 'https://siem.example.com/hook' and body = '{"hello": "world"}';
  if v_claimed <> 1 then raise exception 'relay could not claim the delivery'; end if;
  if (select count(*) from private.claim_audit_webhook_delivery((v_body ->> 'id')::bigint, v_body ->> 'token')) <> 0 then
    raise exception 'delivery token reusable';
  end if;
end $$;

-- Event filters match literal prefixes ("_" is not a wildcard).
do $$ begin
  if position('like prefix' in pg_get_functiondef('private.deliver_audit_webhooks'::regproc)) > 0 then
    raise exception 'webhook filters still use LIKE';
  end if;
end $$;

rollback;
