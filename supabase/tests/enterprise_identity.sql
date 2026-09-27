-- SCIM provisioning, SSO connection lifecycle and opt-in organisation recovery.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('b7000000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','idp-admin@acme.example',now(),'',now(),now()),
  ('b7000000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','new.hire@acme.example',now(),'',now(),now());

create temporary table ident (actor text primary key, bootstrap jsonb) on commit drop;
grant all on ident to authenticated;
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
insert into ident values ('admin', public.bootstrap_personal_vault(
  decode(repeat('11',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('12',12),'hex'), decode(repeat('13',48),'hex'), decode(repeat('14',12),'hex'), decode(repeat('15',48),'hex'),
  decode(repeat('16',32),'hex'), decode(repeat('17',12),'hex'), decode(repeat('18',48),'hex'), decode(repeat('19',65),'hex')));
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
insert into ident values ('hire', public.bootstrap_personal_vault(
  decode(repeat('21',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('22',12),'hex'), decode(repeat('23',48),'hex'), decode(repeat('24',12),'hex'), decode(repeat('25',48),'hex'),
  decode(repeat('26',32),'hex'), decode(repeat('27',12),'hex'), decode(repeat('28',48),'hex'), decode(repeat('29',65),'hex')));
reset role;

-- Turn the admin's tenant into an organisation with room for members.
update public.tenants set kind = 'organization' where id = (select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin');
insert into public.tenant_entitlements (tenant_id, plan_code, subscription_status, source, max_members)
  select (bootstrap ->> 'tenant_id')::uuid, 'business', 'active', 'manual', 50 from ident where actor = 'admin'
  on conflict (tenant_id) do update set plan_code = 'business', subscription_status = 'active', source = 'manual', max_members = 50;

-- ---------------------------------------------------------------------------
-- SCIM
-- ---------------------------------------------------------------------------
create temporary table scim_ctx (token text, user_id uuid) on commit drop;
grant all on scim_ctx to authenticated;
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
insert into scim_ctx (token) select token from public.create_scim_token((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), 'Okta');
do $$ begin
  if (select count(*) from public.scim_tokens) <> 1 then raise exception 'admin cannot list scim tokens'; end if;
  begin perform token_hash from public.scim_tokens; raise exception 'scim token hash selectable';
  exception when insufficient_privilege then null; end;
end $$;
-- The new hire cannot create tokens.
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform public.create_scim_token((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), 'Rogue');
  raise exception 'member created a scim token';
exception when insufficient_privilege then null;
end $$;
reset role;

do $$
declare
  v_tenant uuid := (select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin');
  v_row public.scim_provisioned_users;
begin
  if private.scim_tenant_for_token((select token from scim_ctx)) is distinct from v_tenant then raise exception 'token did not resolve'; end if;
  if private.scim_tenant_for_token('pxscim_wrong') is not null then raise exception 'wrong token resolved'; end if;
  v_row := private.scim_upsert_user(v_tenant, null, 'okta-123', 'New.Hire@Acme.example', 'New Hire', 'Engineer', true);
  update scim_ctx set user_id = v_row.id;
  if (select total from private.scim_list_users(v_tenant, 'new.hire@acme.example', null, 0, 10)) <> 1 then raise exception 'filter by userName failed'; end if;
  begin
    perform private.scim_upsert_user(v_tenant, null, 'okta-999', 'not-an-email', 'X', null, true);
    raise exception 'non-email userName accepted';
  exception when invalid_parameter_value then null;
  end;
end $$;

-- The provisioned person sees and claims the membership after signing in.
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
do $$ begin
  if (select count(*) from public.scim_provisioned_users) <> 1 then raise exception 'hire cannot see pending provisioning'; end if;
end $$;
select public.claim_provisioned_membership((select user_id from scim_ctx));
reset role;

-- Give the hire workspace access, then deprovision through SCIM.
insert into public.workspace_memberships (tenant_id, workspace_id, identity_id, role, status)
  select (a.bootstrap ->> 'tenant_id')::uuid, (a.bootstrap ->> 'workspace_id')::uuid, (h.bootstrap ->> 'identity_id')::uuid, 'editor', 'active'
  from ident a, ident h where a.actor = 'admin' and h.actor = 'hire';
insert into public.key_envelopes (tenant_id, workspace_id, key_kind, key_version, recipient_identity_id, algorithm, nonce, wrapped_key)
  select (a.bootstrap ->> 'tenant_id')::uuid, (a.bootstrap ->> 'workspace_id')::uuid, 'workspace', 1, (h.bootstrap ->> 'identity_id')::uuid,
    'AES-256-GCM', decode(repeat('81',12),'hex'), decode(repeat('82',48),'hex')
  from ident a, ident h where a.actor = 'admin' and h.actor = 'hire';
do $$
declare
  v_tenant uuid := (select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin');
  v_hire uuid := (select (bootstrap ->> 'identity_id')::uuid from ident where actor='hire');
begin
  if (select status from public.tenant_memberships where tenant_id = v_tenant and identity_id = v_hire) <> 'active' then
    raise exception 'claim did not create an active membership';
  end if;
  perform private.scim_upsert_user(v_tenant, (select user_id from scim_ctx), null, 'new.hire@acme.example', null, null, false);
  if (select status from public.tenant_memberships where tenant_id = v_tenant and identity_id = v_hire) <> 'suspended' then
    raise exception 'deactivation did not suspend the membership';
  end if;
  if exists (select 1 from public.workspace_memberships where tenant_id = v_tenant and identity_id = v_hire and status = 'active') then
    raise exception 'deactivation left workspace access';
  end if;
  if exists (select 1 from public.key_envelopes where tenant_id = v_tenant and recipient_identity_id = v_hire and revoked_at is null) then
    raise exception 'deactivation left key envelopes';
  end if;
  if not (select key_rotation_required from public.workspaces where tenant_id = v_tenant limit 1) then
    raise exception 'workspace not flagged for rotation';
  end if;
  if not private.scim_delete_user(v_tenant, (select user_id from scim_ctx)) then raise exception 'delete failed'; end if;
end $$;

-- ---------------------------------------------------------------------------
-- SSO
-- ---------------------------------------------------------------------------
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
do $$ begin
  perform public.save_sso_connection((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), 'gmail.com', null);
  raise exception 'public email domain accepted';
exception when invalid_parameter_value then null;
end $$;
select public.save_sso_connection((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), 'Acme.example', 'https://idp.acme.example/metadata');
do $$ begin
  perform public.request_sso_activation((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'));
  raise exception 'activation requested before domain verification';
exception when invalid_parameter_value then null;
end $$;
reset role;
select private.mark_sso_domain_verified((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), 'acme.example');
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
select public.request_sso_activation((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'));
do $$ begin
  perform public.set_sso_enforcement((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'), true);
  raise exception 'SSO enforced before activation';
exception when invalid_parameter_value then null;
end $$;
reset role;
update public.sso_connections set status = 'active' where domain = 'acme.example';
set local role anon;
do $$ begin
  if not (select sso_available from public.sso_status_for_email('someone@ACME.example')) then raise exception 'sso not reported for domain'; end if;
  if (select sso_available from public.sso_status_for_email('someone@other.example')) then raise exception 'sso reported for other domain'; end if;
end $$;
reset role;

-- ---------------------------------------------------------------------------
-- Organisation recovery
-- ---------------------------------------------------------------------------
-- Rejoin the hire so they can enroll.
update public.tenant_memberships set status = 'active'
  where identity_id = (select (bootstrap ->> 'identity_id')::uuid from ident where actor='hire')
    and tenant_id = (select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin');

set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
select public.set_organization_recovery_key((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'),
  'c7000000-0000-4000-8000-000000000001', '\x04'::bytea || decode(repeat('aa',64),'hex'), 'ab:cd');
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform public.enroll_organization_recovery((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'),
    'c7000000-0000-4000-8000-000000000001', '\x04'::bytea || decode(repeat('bb',64),'hex'), decode(repeat('01',12),'hex'), decode(repeat('02',48),'hex'));
  raise exception 'enrolled while recovery is disabled';
exception when invalid_parameter_value then null;
end $$;
reset role;
insert into public.organization_policies (tenant_id, scope_type, policy_type, configuration, created_by)
  select (bootstrap ->> 'tenant_id')::uuid, 'tenant', 'organization_recovery', '{"enabled": true}'::jsonb, (bootstrap ->> 'identity_id')::uuid
  from ident where actor = 'admin';

create temporary table rec (request_id uuid) on commit drop;
grant all on rec to authenticated;
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
select public.enroll_organization_recovery((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'),
  'c7000000-0000-4000-8000-000000000001', '\x04'::bytea || decode(repeat('bb',64),'hex'), decode(repeat('01',12),'hex'), decode(repeat('02',48),'hex'));
insert into rec select public.request_organization_recovery((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'));
do $$ begin
  perform public.organization_recovery_queue((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'));
  raise exception 'member read the recovery queue';
exception when insufficient_privilege then null;
end $$;

select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
do $$ begin
  if (select count(*) from public.organization_recovery_queue((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'))) <> 1 then
    raise exception 'admin cannot see the pending request';
  end if;
end $$;
select public.decide_organization_recovery((select request_id from rec), true, decode(repeat('03',12),'hex'), decode(repeat('04',48),'hex'),
  extensions.digest(decode(repeat('05',32),'hex'),'sha256'));

select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000002',true);
do $$ begin
  perform public.complete_organization_recovery((select request_id from rec), extensions.digest(decode(repeat('06',32),'hex'),'sha256'),
    decode(repeat('31',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
    decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'));
  raise exception 'wrong recovery code accepted';
exception when invalid_authorization_specification then null;
end $$;
select public.complete_organization_recovery((select request_id from rec), extensions.digest(decode(repeat('05',32),'hex'),'sha256'),
  decode(repeat('31',16),'hex'), '{"algorithm":"ARGON2ID","memoryKib":65536,"iterations":3,"parallelism":1,"hashLength":32}'::jsonb,
  decode(repeat('32',12),'hex'), decode(repeat('33',48),'hex'));
reset role;
do $$ begin
  if (select master_wrapped_root from public.account_crypto_profiles
      where identity_id = (select (bootstrap ->> 'identity_id')::uuid from ident where actor='hire')) <> decode(repeat('33',48),'hex') then
    raise exception 'recovery did not replace the vault password wrap';
  end if;
  if (select status from public.organization_recovery_requests where id = (select request_id from rec)) <> 'completed' then
    raise exception 'request not completed';
  end if;
end $$;

-- Replacing the organisation key drops enrollments made to the old key.
set local role authenticated;
select set_config('request.jwt.claim.sub','b7000000-0000-4000-8000-000000000001',true);
select public.set_organization_recovery_key((select (bootstrap ->> 'tenant_id')::uuid from ident where actor='admin'),
  'c7000000-0000-4000-8000-000000000002', '\x04'::bytea || decode(repeat('cc',64),'hex'), 'ef:01');
reset role;
do $$ begin
  if exists (select 1 from public.organization_recovery_enrollments) then raise exception 'stale enrollment kept after key rotation'; end if;
end $$;

rollback;
