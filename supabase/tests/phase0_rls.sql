begin;

-- This test is designed for a disposable local database after the Phase 0 migration.
-- It uses synthetic UUIDs and rolls back all fixtures.
insert into auth.users (id, instance_id, aud, role, email, encrypted_password, created_at, updated_at)
values
 ('10000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','a@example.invalid','',now(),now()),
 ('20000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','b@example.invalid','',now(),now());

insert into public.identities (id, auth_user_id, kind) values
 ('11000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','human'),
 ('22000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000002','human');
insert into public.tenants (id,kind,created_by) values
 ('11100000-0000-4000-8000-000000000001','personal','11000000-0000-4000-8000-000000000001'),
 ('22200000-0000-4000-8000-000000000002','personal','22000000-0000-4000-8000-000000000002');
insert into public.tenant_memberships (tenant_id,identity_id,role) values
 ('11100000-0000-4000-8000-000000000001','11000000-0000-4000-8000-000000000001','owner'),
 ('22200000-0000-4000-8000-000000000002','22000000-0000-4000-8000-000000000002','owner');
insert into public.workspaces (id,tenant_id,created_by) values
 ('11110000-0000-4000-8000-000000000001','11100000-0000-4000-8000-000000000001','11000000-0000-4000-8000-000000000001'),
 ('22220000-0000-4000-8000-000000000002','22200000-0000-4000-8000-000000000002','22000000-0000-4000-8000-000000000002');
insert into public.workspace_memberships (tenant_id,workspace_id,identity_id,role) values
 ('11100000-0000-4000-8000-000000000001','11110000-0000-4000-8000-000000000001','11000000-0000-4000-8000-000000000001','owner'),
 ('22200000-0000-4000-8000-000000000002','22220000-0000-4000-8000-000000000002','22000000-0000-4000-8000-000000000002','owner');
insert into public.vault_items (id,tenant_id,workspace_id,content_type,schema_version,created_by) values
 ('11111000-0000-4000-8000-000000000001','11100000-0000-4000-8000-000000000001','11110000-0000-4000-8000-000000000001','com.1accessos.login',1,'11000000-0000-4000-8000-000000000001'),
 ('22222000-0000-4000-8000-000000000002','22200000-0000-4000-8000-000000000002','22220000-0000-4000-8000-000000000002','com.1accessos.login',1,'22000000-0000-4000-8000-000000000002');

set local role authenticated;
select set_config('request.jwt.claim.sub','10000000-0000-4000-8000-000000000001',true);
do $$ begin
  if (select count(*) from public.vault_items) <> 1 then
    raise exception 'RLS failure: tenant A did not see exactly its own item';
  end if;
  if exists (select 1 from public.vault_items where tenant_id = '22200000-0000-4000-8000-000000000002') then
    raise exception 'RLS failure: cross-tenant item visible';
  end if;
end $$;

reset role;
set local role anon;
do $$ begin
  if exists (select 1 from public.vault_items) then
    raise exception 'RLS failure: anonymous item access';
  end if;
exception when insufficient_privilege then
  null;
end $$;

rollback;
