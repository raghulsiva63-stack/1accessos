begin;

insert into auth.users (id, instance_id, aud, role, email, encrypted_password, created_at, updated_at)
values
  ('30000000-0000-4000-8000-000000000003','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase1-a@example.invalid','',now(),now()),
  ('40000000-0000-4000-8000-000000000004','00000000-0000-0000-0000-000000000000','authenticated','authenticated','phase1-b@example.invalid','',now(),now());

create temporary table phase1_fixtures (actor text primary key, bootstrap jsonb) on commit drop;
grant all on phase1_fixtures to authenticated;

set local role authenticated;
select set_config('request.jwt.claim.sub','30000000-0000-4000-8000-000000000003',true);
insert into phase1_fixtures values (
  'a',
  public.bootstrap_personal_vault(
    decode(repeat('01',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('02',12),'hex'), decode(repeat('03',48),'hex'),
    decode(repeat('04',12),'hex'), decode(repeat('05',48),'hex'),
    decode(repeat('06',12),'hex'), decode(repeat('07',48),'hex'),
    decode(repeat('08',65),'hex')
  )
);

select set_config('request.jwt.claim.sub','40000000-0000-4000-8000-000000000004',true);
insert into phase1_fixtures values (
  'b',
  public.bootstrap_personal_vault(
    decode(repeat('11',16),'hex'),
    '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'),
    decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
    decode(repeat('16',12),'hex'), decode(repeat('17',48),'hex'),
    decode(repeat('18',65),'hex')
  )
);

select set_config('request.jwt.claim.sub','30000000-0000-4000-8000-000000000003',true);
select public.create_vault_item(
  '33333000-0000-4000-8000-000000000003',
  (select (bootstrap ->> 'tenant_id')::uuid from phase1_fixtures where actor = 'a'),
  (select (bootstrap ->> 'workspace_id')::uuid from phase1_fixtures where actor = 'a'),
  'api-key', 1,
  decode(repeat('21',12),'hex'), decode(repeat('22',48),'hex'), decode(repeat('23',32),'hex')
);

select public.update_vault_item(
  '33333000-0000-4000-8000-000000000003', 1,
  decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'), decode(repeat('26',32),'hex')
);

do $$
begin
  if (select head_revision from public.vault_items where id = '33333000-0000-4000-8000-000000000003') <> 2 then
    raise exception 'Phase 1 RPC failure: expected head revision 2';
  end if;
  if (select count(*) from public.vault_item_revisions where item_id = '33333000-0000-4000-8000-000000000003') <> 2 then
    raise exception 'Phase 1 RPC failure: immutable revisions missing';
  end if;
  if (select count(*) from public.sync_changes where entity_id = '33333000-0000-4000-8000-000000000003') <> 2 then
    raise exception 'Phase 1 RPC failure: create/update sync changes missing';
  end if;
end
$$;

do $$
begin
  perform public.create_vault_item(
    '44444000-0000-4000-8000-000000000004',
    (select (bootstrap ->> 'tenant_id')::uuid from phase1_fixtures where actor = 'b'),
    (select (bootstrap ->> 'workspace_id')::uuid from phase1_fixtures where actor = 'b'),
    'login', 1,
    decode(repeat('31',12),'hex'), decode(repeat('32',48),'hex'), decode(repeat('33',32),'hex')
  );
  raise exception 'Phase 1 RLS failure: cross-tenant insert succeeded';
exception when insufficient_privilege then
  null;
end
$$;

select public.delete_vault_item('33333000-0000-4000-8000-000000000003', 2);

do $$
begin
  if exists (select 1 from public.vault_items where id = '33333000-0000-4000-8000-000000000003' and deleted_at is null) then
    raise exception 'Phase 1 RPC failure: item not soft deleted';
  end if;
  if (select count(*) from public.sync_changes where entity_id = '33333000-0000-4000-8000-000000000003') <> 3 then
    raise exception 'Phase 1 RPC failure: delete sync change missing';
  end if;
end
$$;

rollback;
