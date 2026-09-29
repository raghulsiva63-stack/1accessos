-- Desktop sign-in handoff: one-time codes bound to the app's PKCE secret.
begin;

insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, encrypted_password, created_at, updated_at) values
  ('a7100000-0000-4000-8000-000000000001','00000000-0000-0000-0000-000000000000','authenticated','authenticated','desk-a@example.invalid',now(),'',now(),now()),
  ('a7100000-0000-4000-8000-000000000002','00000000-0000-0000-0000-000000000000','authenticated','authenticated','desk-mfa@example.invalid',now(),'',now(),now());
insert into public.identities (auth_user_id, kind) values
  ('a7100000-0000-4000-8000-000000000001','human'),
  ('a7100000-0000-4000-8000-000000000002','human');
insert into auth.mfa_factors (user_id, status, factor_type) values ('a7100000-0000-4000-8000-000000000002','verified','totp');

-- verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" -> RFC 7636 example challenge
create temporary table handoff (label text primary key, code text) on commit drop;
grant all on handoff to authenticated, service_role;

set local role authenticated;
select set_config('request.jwt.claims','{"sub":"a7100000-0000-4000-8000-000000000001","aal":"aal1"}',true);
insert into handoff values ('good', public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'Raghul''s MacBook <script>'));
insert into handoff values ('burn', public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', ''));
insert into handoff values ('late', public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'Office PC'));
do $$ begin
  if (select code from handoff where label = 'good') !~ '^[A-Za-z0-9_-]{43}$' then raise exception 'bad code format'; end if;
  begin
    perform public.create_desktop_handoff('short', 'x');
    raise exception 'short challenge accepted';
  exception when invalid_parameter_value then null;
  end;
  -- Browsers cannot read the table or redeem codes.
  begin
    perform 1 from private.desktop_handoffs;
    raise exception 'client read handoffs';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.redeem_desktop_handoff((select code from handoff where label = 'good'), 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    raise exception 'client redeemed a code';
  exception when insufficient_privilege then null;
  end;
end $$;

-- An account with two-step verification must finish it before approving.
select set_config('request.jwt.claims','{"sub":"a7100000-0000-4000-8000-000000000002","aal":"aal1"}',true);
do $$ begin
  perform public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'Laptop');
  raise exception 'aal1 approval allowed';
exception when insufficient_privilege then null;
end $$;
select set_config('request.jwt.claims','{"sub":"a7100000-0000-4000-8000-000000000002","aal":"aal2"}',true);
select public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'Laptop');

-- Rate limit: at most 5 approvals in 10 minutes.
select set_config('request.jwt.claims','{"sub":"a7100000-0000-4000-8000-000000000001","aal":"aal1"}',true);
select public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'x');
select public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'x');
do $$ begin
  perform public.create_desktop_handoff('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'x');
  raise exception 'rate limit missing';
exception when program_limit_exceeded then null;
end $$;
reset role;

do $$ begin
  if (select device_name from private.desktop_handoffs order by created_at limit 1) ~ '[<>]' then
    raise exception 'device name not sanitised';
  end if;
end $$;

set local role service_role;
do $$
declare
  v_good text := (select code from handoff where label = 'good');
  v_burn text := (select code from handoff where label = 'burn');
begin
  -- Right code + right secret works exactly once.
  if public.redeem_desktop_handoff(v_good, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') is distinct from 'a7100000-0000-4000-8000-000000000001'::uuid then
    raise exception 'valid redeem failed';
  end if;
  if public.redeem_desktop_handoff(v_good, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') is not null then
    raise exception 'code redeemed twice';
  end if;
  -- A wrong secret burns the code, even if the right one follows.
  if public.redeem_desktop_handoff(v_burn, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') is not null then
    raise exception 'wrong verifier accepted';
  end if;
  if public.redeem_desktop_handoff(v_burn, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') is not null then
    raise exception 'burned code accepted';
  end if;
  if public.redeem_desktop_handoff('junk', 'junk') is not null then raise exception 'junk accepted'; end if;
end $$;
reset role;

-- Expired codes do not work.
update private.desktop_handoffs set expires_at = now() - interval '1 second'
  where code_hash = extensions.digest((select code from handoff where label = 'late'), 'sha256');
set local role service_role;
do $$ begin
  if public.redeem_desktop_handoff((select code from handoff where label = 'late'), 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') is not null then
    raise exception 'expired code accepted';
  end if;
end $$;
reset role;

rollback;
