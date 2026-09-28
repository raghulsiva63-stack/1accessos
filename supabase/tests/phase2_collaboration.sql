begin;

insert into auth.users (
  id, instance_id, aud, role, email, email_confirmed_at,
  encrypted_password, created_at, updated_at
) values
  ('71000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase2-owner@example.invalid',now(),'',now(),now()),
  ('72000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase2-member@example.invalid',now(),'',now(),now()),
  ('73000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase2-outsider@example.invalid',now(),'',now(),now());

create temporary table phase2_fixtures (actor text primary key, bootstrap jsonb) on commit drop;
grant all on phase2_fixtures to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','71000000-0000-4000-8000-000000000001',true);
insert into phase2_fixtures values ('owner', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'),
  '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'),
  decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'), decode(repeat('16',32),'hex'),
  decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')
));

select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);
insert into phase2_fixtures values ('member', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'),
  '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'),
  decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'), decode(repeat('26',32),'hex'),
  decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')
));

select set_config('request.jwt.claim.sub','73000000-0000-4000-8000-000000000003',true);
insert into phase2_fixtures values ('outsider', public.bootstrap_personal_vault(
  decode(repeat('31',16),'hex'),
  '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'),
  decode(repeat('34',12),'hex'), decode(repeat('35',48),'hex'), decode(repeat('36',32),'hex'),
  decode(repeat('37',12),'hex'), decode(repeat('38',48),'hex'), decode(repeat('39',65),'hex')
));

select set_config('request.jwt.claim.sub','71000000-0000-4000-8000-000000000001',true);
select public.create_shared_workspace(
  '71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001',
  'team','shared',decode(repeat('41',48),'hex'),decode(repeat('42',12),'hex'),
  decode(repeat('43',32),'hex'),decode(repeat('44',12),'hex'),decode(repeat('45',48),'hex')
);

insert into public.workspace_invites(
  id,tenant_id,workspace_id,created_by,recipient_email_hash,role,token_hash,
  key_nonce,wrapped_workspace_key,key_aad_hash,status,expires_at
) values (
  '71120000-0000-4000-8000-000000000001',
  '71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='owner'))::uuid,
  extensions.digest(convert_to('phase2-member@example.invalid','UTF8'),'sha256'),
  'viewer',decode(repeat('46',32),'hex'),decode(repeat('47',12),'hex'),
  decode(repeat('48',48),'hex'),decode(repeat('49',32),'hex'),'pending',now()+interval '1 day'
);

select public.create_vault_item(
  '71130000-0000-4000-8000-000000000001',
  '71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001',
  'login',1,decode(repeat('4a',12),'hex'),decode(repeat('4b',48),'hex'),decode(repeat('4c',32),'hex')
);

-- A non-recipient cannot enumerate the invite, workspace, or encrypted item.
select set_config('request.jwt.claim.sub','73000000-0000-4000-8000-000000000003',true);
do $$ begin
  if exists (select 1 from public.workspace_invites where id='71120000-0000-4000-8000-000000000001')
    or exists (select 1 from public.workspaces where id='71110000-0000-4000-8000-000000000001')
    or exists (select 1 from public.vault_items where id='71130000-0000-4000-8000-000000000001') then
    raise exception 'Phase 2 RLS failure: outsider saw collaboration data';
  end if;
end $$;

-- The verified recipient sees the pending invite but a wrong token cannot accept it.
select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);
do $$ begin
  if (select count(*) from public.workspace_invites where id='71120000-0000-4000-8000-000000000001') <> 1 then
    raise exception 'Phase 2 invite failure: verified recipient cannot see invite';
  end if;
  perform public.accept_workspace_invite(
    '71120000-0000-4000-8000-000000000001',decode(repeat('ff',32),'hex'),
    decode(repeat('4d',12),'hex'),decode(repeat('4e',48),'hex')
  );
  raise exception 'Phase 2 invite failure: wrong token was accepted';
exception when invalid_authorization_specification then null;
end $$;

-- New Team tenants start with the free entitlement until explicitly upgraded.
-- A denied invitation must not consume its token or grant membership.
do $$ begin
  perform public.accept_workspace_invite(
    '71120000-0000-4000-8000-000000000001',decode(repeat('46',32),'hex'),
    decode(repeat('4d',12),'hex'),decode(repeat('4e',48),'hex')
  );
  raise exception 'Free tenant bypassed the member limit';
exception when check_violation then
  if sqlerrm <> 'tenant member limit reached' then raise; end if;
end $$;

reset role;
update public.tenant_entitlements
set plan_code='team',source='manual',subscription_status='active',max_members=50,max_workspaces=50
where tenant_id='71100000-0000-4000-8000-000000000001';
-- Give the outsider fixture quota so membership-injection tests reach RLS,
-- rather than being rejected earlier by the entitlement trigger.
update public.tenant_entitlements set max_members=50
where tenant_id=((select bootstrap ->> 'tenant_id' from phase2_fixtures where actor='outsider'))::uuid;
set local role authenticated;
select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);

select public.accept_workspace_invite(
  '71120000-0000-4000-8000-000000000001',decode(repeat('46',32),'hex'),
  decode(repeat('4d',12),'hex'),decode(repeat('4e',48),'hex')
);

-- An accepted invite cannot be replayed to inject membership into a different
-- tenant/workspace or escalate beyond the invited role.
do $$ begin
  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
  values (
    ((select bootstrap ->> 'tenant_id' from phase2_fixtures where actor='outsider'))::uuid,
    ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid,
    'member','active'
  );
  raise exception 'Phase 2 invite failure: cross-tenant membership injection succeeded';
exception when insufficient_privilege then null;
end $$;

do $$ begin
  insert into public.workspace_memberships(tenant_id,workspace_id,identity_id,role,status)
  values (
    ((select bootstrap ->> 'tenant_id' from phase2_fixtures where actor='outsider'))::uuid,
    ((select bootstrap ->> 'workspace_id' from phase2_fixtures where actor='outsider'))::uuid,
    ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid,
    'manager','active'
  );
  raise exception 'Phase 2 invite failure: cross-workspace role injection succeeded';
exception when insufficient_privilege then null;
end $$;

do $$ begin
  if (select role from public.workspace_memberships
      where workspace_id='71110000-0000-4000-8000-000000000001'
        and identity_id=((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid) <> 'viewer' then
    raise exception 'Phase 2 invite failure: accepted role missing';
  end if;
  if (select count(*) from public.key_envelopes
      where workspace_id='71110000-0000-4000-8000-000000000001' and revoked_at is null) <> 1 then
    raise exception 'Phase 2 invite failure: recipient key envelope unavailable';
  end if;
  if (select count(*) from public.vault_items where id='71130000-0000-4000-8000-000000000001') <> 1 then
    raise exception 'Phase 2 invite failure: shared item unavailable';
  end if;
end $$;

do $$ begin
  perform public.create_vault_item(
    '72220000-0000-4000-8000-000000000002','71100000-0000-4000-8000-000000000001',
    '71110000-0000-4000-8000-000000000001','login',1,
    decode(repeat('51',12),'hex'),decode(repeat('52',48),'hex'),decode(repeat('53',32),'hex')
  );
  raise exception 'Phase 2 role failure: viewer created an item';
exception when insufficient_privilege then null;
end $$;

insert into public.access_requests(
  id,tenant_id,workspace_id,item_id,requester_identity_id,requested_scope,purpose_nonce,
  encrypted_purpose,purpose_aad_hash,requested_duration_minutes,status,expires_at
) values (
  '72230000-0000-4000-8000-000000000002','71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001','71130000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid,
  'reveal',decode(repeat('54',12),'hex'),decode(repeat('55',48),'hex'),decode(repeat('56',32),'hex'),
  60,'pending',now()+interval '1 day'
);

-- Owner approves the encrypted-purpose request and receives an attributable grant.
select set_config('request.jwt.claim.sub','71000000-0000-4000-8000-000000000001',true);
select public.decide_access_request('72230000-0000-4000-8000-000000000002','approved');
do $$ begin
  if (select status from public.access_requests where id='72230000-0000-4000-8000-000000000002') <> 'approved'
    or (select count(*) from public.access_grants where source_request_id='72230000-0000-4000-8000-000000000002' and status='active') <> 1 then
    raise exception 'Phase 2 approval failure: grant was not created';
  end if;
end $$;

insert into public.missions(
  id,tenant_id,workspace_id,created_by,definition_nonce,encrypted_definition,
  definition_aad_hash,status
) values (
  '71140000-0000-4000-8000-000000000001','71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='owner'))::uuid,
  decode(repeat('57',12),'hex'),decode(repeat('58',48),'hex'),decode(repeat('59',32),'hex'),'active'
);
insert into public.mission_items(mission_id,tenant_id,workspace_id,item_id,sort_order)
values ('71140000-0000-4000-8000-000000000001','71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001','71130000-0000-4000-8000-000000000001',0);

-- Create a one-use Access Capsule; the verified recipient accepts and consumes it.
insert into public.access_capsules(
  id,tenant_id,workspace_id,item_id,created_by,recipient_email_hash,reveal_policy,purpose_code,
  payload_nonce,payload_ciphertext,payload_aad_hash,token_hash,invite_key_nonce,
  invite_wrapped_key,invite_key_aad_hash,status,expires_at,max_uses
) values (
  '71150000-0000-4000-8000-000000000001','71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001','71130000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='owner'))::uuid,
  extensions.digest(convert_to('phase2-member@example.invalid','UTF8'),'sha256'),'fill_only','support',
  decode(repeat('61',12),'hex'),decode(repeat('62',48),'hex'),decode(repeat('63',32),'hex'),
  decode(repeat('64',32),'hex'),decode(repeat('65',12),'hex'),decode(repeat('66',48),'hex'),
  decode(repeat('67',32),'hex'),'pending',now()+interval '1 day',1
);

select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);
select public.accept_access_capsule(
  '71150000-0000-4000-8000-000000000001',decode(repeat('64',32),'hex'),
  decode(repeat('68',12),'hex'),decode(repeat('69',48),'hex'),decode(repeat('6a',32),'hex')
);
select public.consume_access_capsule('71150000-0000-4000-8000-000000000001');
select set_config('request.passkey_x_capsule_consume','',true);
do $$ begin
  if exists (select 1 from public.access_capsules where id='71150000-0000-4000-8000-000000000001') then
    raise exception 'Phase 2 capsule failure: consumed one-time capsule remained available';
  end if;
end $$;

-- Revocation removes future server access and requires cryptographic rotation.
select set_config('request.jwt.claim.sub','71000000-0000-4000-8000-000000000001',true);
select public.revoke_workspace_member(
  '71110000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid
);
do $$ begin
  if not (select key_rotation_required from public.workspaces where id='71110000-0000-4000-8000-000000000001') then
    raise exception 'Phase 2 revocation failure: rotation was not required';
  end if;
  if (select count(*) from public.audit_events where tenant_id='71100000-0000-4000-8000-000000000001') < 8 then
    raise exception 'Phase 2 audit failure: collaboration events missing';
  end if;
end $$;

select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);
do $$ begin
  if exists (select 1 from public.vault_items where id='71130000-0000-4000-8000-000000000001')
    or exists (select 1 from public.key_envelopes where workspace_id='71110000-0000-4000-8000-000000000001')
    or exists (select 1 from public.missions where id='71140000-0000-4000-8000-000000000001') then
    raise exception 'Phase 2 revocation failure: revoked member retained server access';
  end if;
end $$;

-- A removed member who is invited again becomes active again (re-invite).
select set_config('request.jwt.claim.sub','71000000-0000-4000-8000-000000000001',true);
insert into public.workspace_invites(
  id,tenant_id,workspace_id,created_by,recipient_email_hash,role,token_hash,
  key_nonce,wrapped_workspace_key,key_aad_hash,status,expires_at
) values (
  '71120000-0000-4000-8000-000000000002',
  '71100000-0000-4000-8000-000000000001',
  '71110000-0000-4000-8000-000000000001',
  ((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='owner'))::uuid,
  extensions.digest(convert_to('phase2-member@example.invalid','UTF8'),'sha256'),
  'editor',decode(repeat('56',32),'hex'),decode(repeat('57',12),'hex'),
  decode(repeat('58',48),'hex'),decode(repeat('59',32),'hex'),'pending',now()+interval '1 day'
);
select set_config('request.jwt.claim.sub','72000000-0000-4000-8000-000000000002',true);
select public.accept_workspace_invite(
  '71120000-0000-4000-8000-000000000002',decode(repeat('56',32),'hex'),
  decode(repeat('5d',12),'hex'),decode(repeat('5e',48),'hex')
);
do $$ begin
  if not exists (select 1 from public.workspace_memberships
      where workspace_id='71110000-0000-4000-8000-000000000001'
        and identity_id=((select bootstrap ->> 'identity_id' from phase2_fixtures where actor='member'))::uuid
        and status='active' and role='editor') then
    raise exception 'Re-invited member was not reactivated';
  end if;
end $$;

reset role;
set local role anon;
do $$ begin
  perform 1 from public.workspace_invites limit 1;
  raise exception 'Phase 2 anonymous access failure';
exception when insufficient_privilege then null;
end $$;

rollback;
