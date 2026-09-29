begin;

-- Desktop sign-in handoff.
-- The desktop app never shows a password form: the person signs in (with the security
-- check, passkeys, SSO and two-step verification) in their normal browser, approves
-- "sign in to Passkey-X desktop", and the browser hands a one-time code back to the app.
-- The code is single-use, expires after two minutes and only works together with the
-- secret (PKCE verifier) that stayed inside the app that started the sign-in.
create table private.desktop_handoffs (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete cascade,
  auth_user_id uuid not null,
  code_hash bytea not null unique check (octet_length(code_hash) = 32),
  challenge text not null check (challenge ~ '^[A-Za-z0-9_-]{43}$'),
  device_name text not null check (char_length(device_name) between 1 and 60),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '2 minutes',
  redeemed_at timestamptz,
  failed_at timestamptz
);
create index desktop_handoffs_identity_idx on private.desktop_handoffs(identity_id, created_at desc);

revoke all on private.desktop_handoffs from public, anon, authenticated;
grant select, insert, update, delete on private.desktop_handoffs to service_role;

-- Browser side: the signed-in person approves a desktop sign-in. Returns the one-time code.
create or replace function private.create_desktop_handoff(p_challenge text, p_device_name text)
returns text language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_code text;
  v_device text := left(regexp_replace(coalesce(p_device_name, ''), '[^[:alnum:] ._()''-]', '', 'g'), 60);
begin
  if v_actor is null or auth.uid() is null then raise exception 'authentication required' using errcode = '42501'; end if;
  if not private.session_mfa_satisfied() then raise exception 'two-step verification required' using errcode = '42501'; end if;
  if p_challenge is null or p_challenge !~ '^[A-Za-z0-9_-]{43}$' then raise exception 'invalid challenge' using errcode = '22023'; end if;
  if btrim(v_device) = '' then v_device := 'Desktop app'; end if;
  if (select count(*) from private.desktop_handoffs
      where identity_id = v_actor and created_at > now() - interval '10 minutes') >= 5 then
    raise exception 'too many desktop sign-in attempts, wait a few minutes' using errcode = '54000';
  end if;
  delete from private.desktop_handoffs where expires_at < now() - interval '1 day';
  v_code := translate(encode(extensions.gen_random_bytes(32), 'base64'), '+/=', '-_');
  insert into private.desktop_handoffs(identity_id, auth_user_id, code_hash, challenge, device_name)
    values (v_actor, auth.uid(), extensions.digest(v_code, 'sha256'), p_challenge, btrim(v_device));
  return v_code;
end
$$;

-- Server side (desktop-session Edge Function, service role only): checks the code and the
-- app's secret once. Any wrong secret burns the code. Returns the account to sign in.
create or replace function private.redeem_desktop_handoff(p_code text, p_verifier text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  v_row private.desktop_handoffs;
  v_expected text;
begin
  if p_code is null or p_code !~ '^[A-Za-z0-9_-]{43}$' or p_verifier is null or p_verifier !~ '^[A-Za-z0-9_-]{43,128}$' then
    return null;
  end if;
  select * into v_row from private.desktop_handoffs
    where code_hash = extensions.digest(p_code, 'sha256') for update;
  if not found or v_row.redeemed_at is not null or v_row.failed_at is not null or v_row.expires_at < now() then
    return null;
  end if;
  v_expected := rtrim(translate(encode(extensions.digest(p_verifier, 'sha256'), 'base64'), '+/', '-_'), '=');
  if v_expected <> v_row.challenge then
    update private.desktop_handoffs set failed_at = now() where id = v_row.id;
    return null;
  end if;
  if not exists (select 1 from public.identities where id = v_row.identity_id and status = 'active') then
    update private.desktop_handoffs set failed_at = now() where id = v_row.id;
    return null;
  end if;
  update private.desktop_handoffs set redeemed_at = now() where id = v_row.id;
  return v_row.auth_user_id;
end
$$;

revoke all on function private.create_desktop_handoff(text, text), private.redeem_desktop_handoff(text, text) from public, anon, authenticated;
grant execute on function private.create_desktop_handoff(text, text) to authenticated;
grant execute on function private.redeem_desktop_handoff(text, text) to service_role;

create function public.create_desktop_handoff(p_challenge text, p_device_name text) returns text
language sql volatile security invoker set search_path = ''
as $$ select private.create_desktop_handoff(p_challenge, p_device_name) $$;
create function public.redeem_desktop_handoff(p_code text, p_verifier text) returns uuid
language sql volatile security invoker set search_path = ''
as $$ select private.redeem_desktop_handoff(p_code, p_verifier) $$;
revoke all on function public.create_desktop_handoff(text, text), public.redeem_desktop_handoff(text, text) from public, anon, authenticated;
grant execute on function public.create_desktop_handoff(text, text) to authenticated;
grant execute on function public.redeem_desktop_handoff(text, text) to service_role;

commit;
