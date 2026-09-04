begin;

insert into auth.users (id, instance_id, aud, role, email, encrypted_password, created_at, updated_at)
values
  ('50000000-0000-4000-8000-000000000005','00000000-0000-0000-0000-000000000000','authenticated','authenticated','completion-a@example.invalid','',now(),now()),
  ('60000000-0000-4000-8000-000000000006','00000000-0000-0000-0000-000000000000','authenticated','authenticated','completion-b@example.invalid','',now(),now());

create temporary table phase1_completion_fixtures (actor text primary key, bootstrap jsonb) on commit drop;
grant all on phase1_completion_fixtures to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','50000000-0000-4000-8000-000000000005',true);
insert into phase1_completion_fixtures values (
  'a',
  public.bootstrap_personal_vault(
    decode(repeat('41',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('42',12),'hex'), decode(repeat('43',48),'hex'),
    decode(repeat('44',12),'hex'), decode(repeat('45',48),'hex'),
    decode(repeat('60',32),'hex'),
    decode(repeat('46',12),'hex'), decode(repeat('47',48),'hex'),
    decode(repeat('48',65),'hex')
  )
);

select set_config('request.jwt.claim.sub','60000000-0000-4000-8000-000000000006',true);
insert into phase1_completion_fixtures values (
  'b',
  public.bootstrap_personal_vault(
    decode(repeat('51',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('52',12),'hex'), decode(repeat('53',48),'hex'),
    decode(repeat('54',12),'hex'), decode(repeat('55',48),'hex'),
    decode(repeat('59',32),'hex'),
    decode(repeat('56',12),'hex'), decode(repeat('57',48),'hex'),
    decode(repeat('58',65),'hex')
  )
);

select set_config('request.jwt.claim.sub','50000000-0000-4000-8000-000000000005',true);

do $$
begin
  if (select plan_code from public.account_entitlements) <> 'free' then
    raise exception 'Phase 1 entitlement failure: Free plan was not provisioned';
  end if;
  if (select count(*) from public.account_entitlements) <> 1 then
    raise exception 'Phase 1 RLS failure: cross-user entitlement visible';
  end if;
end
$$;

do $$
begin
  perform public.rotate_master_with_recovery(
    decode(repeat('99',32),'hex'),
    decode(repeat('61',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('62',12),'hex'),
    decode(repeat('63',48),'hex')
  );
  raise exception 'Phase 1 recovery failure: wrong proof rotated master wrapper';
exception when invalid_authorization_specification then
  null;
end
$$;

select public.rotate_master_with_recovery(
  decode(repeat('60',32),'hex'),
  decode(repeat('61',16),'hex'),
  '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('62',12),'hex'),
  decode(repeat('63',48),'hex')
);

do $$
begin
  if (select salt from public.account_crypto_profiles) <> decode(repeat('61',16),'hex') then
    raise exception 'Phase 1 recovery failure: own password wrapper did not rotate';
  end if;
end
$$;

update public.devices
set status = 'revoked', revoked_at = now()
where id = ((select bootstrap ->> 'device_id' from phase1_completion_fixtures where actor = 'a'))::uuid;

update public.devices
set status = 'trusted', revoked_at = null
where id = ((select bootstrap ->> 'device_id' from phase1_completion_fixtures where actor = 'a'))::uuid;

do $$
begin
  if (select status from public.devices where id = ((select bootstrap ->> 'device_id' from phase1_completion_fixtures where actor = 'a'))::uuid) <> 'revoked' then
    raise exception 'Phase 1 device failure: revoked device was trusted again';
  end if;
end
$$;

select public.create_vault_item(
  '55555000-0000-4000-8000-000000000005',
  ((select bootstrap ->> 'tenant_id' from phase1_completion_fixtures where actor = 'a'))::uuid,
  ((select bootstrap ->> 'workspace_id' from phase1_completion_fixtures where actor = 'a'))::uuid,
  'passkey', 1,
  decode(repeat('71',12),'hex'), decode(repeat('72',48),'hex'), decode(repeat('73',32),'hex')
);
select public.delete_vault_item('55555000-0000-4000-8000-000000000005', 1);
select public.restore_vault_item('55555000-0000-4000-8000-000000000005', 1);

select public.create_attachment(
  '55555900-0000-4000-8000-000000000005',
  ((select bootstrap ->> 'tenant_id' from phase1_completion_fixtures where actor = 'a'))::uuid,
  ((select bootstrap ->> 'workspace_id' from phase1_completion_fixtures where actor = 'a'))::uuid,
  '55555000-0000-4000-8000-000000000005',
  decode(repeat('81',48),'hex'),
  decode(repeat('82',12),'hex'),
  decode(repeat('83',32),'hex'),
  (select bootstrap ->> 'tenant_id' from phase1_completion_fixtures where actor = 'a') || '/' ||
    (select bootstrap ->> 'workspace_id' from phase1_completion_fixtures where actor = 'a') ||
    '/55555900-0000-4000-8000-000000000005/1',
  48,
  decode(repeat('84',32),'hex'),
  1,
  decode(repeat('85',12),'hex'),
  decode(repeat('86',32),'hex')
);

do $$
begin
  if exists (select 1 from public.vault_items where id = '55555000-0000-4000-8000-000000000005' and deleted_at is not null) then
    raise exception 'Phase 1 restore failure: item remained deleted';
  end if;
  if (select count(*) from public.sync_changes where entity_id = '55555000-0000-4000-8000-000000000005') <> 3 then
    raise exception 'Phase 1 sync failure: create/delete/restore changes missing';
  end if;
  if (select count(*) from public.sync_changes where entity_id = '55555900-0000-4000-8000-000000000005') <> 1 then
    raise exception 'Phase 1 attachment sync failure: create change missing';
  end if;
  if not private.can_access_attachment_path(
    (select bootstrap ->> 'tenant_id' from phase1_completion_fixtures where actor = 'a') || '/' ||
    (select bootstrap ->> 'workspace_id' from phase1_completion_fixtures where actor = 'a') || '/attachment/1',
    array['owner','manager','editor','viewer']
  ) then
    raise exception 'Phase 1 attachment failure: owner path denied';
  end if;
  if private.can_access_attachment_path(
    (select bootstrap ->> 'tenant_id' from phase1_completion_fixtures where actor = 'b') || '/' ||
    (select bootstrap ->> 'workspace_id' from phase1_completion_fixtures where actor = 'b') || '/attachment/1',
    array['owner','manager','editor','viewer']
  ) then
    raise exception 'Phase 1 attachment RLS failure: cross-tenant path allowed';
  end if;
end
$$;

do $$
begin
  update public.account_entitlements set plan_code = 'personal';
  raise exception 'Phase 1 entitlement RLS failure: browser changed its plan';
exception when insufficient_privilege then
  null;
end
$$;

rollback;
