-- Passkey-X security intelligence.
--
--  1. Background workers: one-time dispatch tokens for edge functions called by pg_cron.
--  2. Security notifications: a private outbox that the security-notify edge function really
--     delivers (email, and SMS where an organization has set it up).
--  3. Sign-in tracking: every new Supabase Auth session is recorded with a coarse device label
--     and network prefix (never the full IP). New devices, new networks, new countries and
--     sign-ins from many networks raise notifications and organization alerts. People can list
--     and sign out their own sessions.
--  4. Single security score: richer on-device health reports (still counts only) and a daily
--     history for trend charts.
--  5. Employee breach watch (Have I Been Pwned, opt-in per organization).
--  6. Passkey adoption tracking and nudges.
--  7. Guided password rotation campaigns.
--  8. Weekly security reports.
--  9. AI context for alert triage, the policy advisor and report summaries (counts only).
--
-- Zero knowledge is unchanged: the server never sees passwords, item titles, sites or usernames.

begin;

-- ---------------------------------------------------------------------------
-- 1. Background workers
-- ---------------------------------------------------------------------------
insert into private.app_settings (key, value) values
  ('notify_dispatch_url', 'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/security-notify'),
  ('breach_watch_url', 'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/breach-watch')
on conflict (key) do nothing;
-- Shared with the Netlify sign-in-context function (env GEO_ATTESTATION_KEY) so that country
-- information can be trusted without giving Netlify a service-role key.
insert into private.app_settings (key, value)
select 'geo_attestation_key', encode(extensions.gen_random_bytes(32), 'hex')
where not exists (select 1 from private.app_settings where key = 'geo_attestation_key');

create table if not exists private.dispatch_tokens (
  id bigint generated always as identity primary key,
  purpose text not null check (purpose in ('notify','breach_watch')),
  token_hash bytea not null unique,
  created_at timestamptz not null default now()
);
revoke all on private.dispatch_tokens from public, anon, authenticated;

-- Wakes an edge-function worker with a one-time token. The worker trades the token for work.
create or replace function private.kick_worker(p_purpose text, p_url_key text)
returns bigint language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_token text := encode(extensions.gen_random_bytes(32), 'hex');
  v_url text := (select s.value from private.app_settings s where s.key = p_url_key);
begin
  if v_url is null then return null; end if;
  delete from private.dispatch_tokens where created_at < now() - interval '15 minutes';
  insert into private.dispatch_tokens (purpose, token_hash) values (p_purpose, extensions.digest(v_token, 'sha256'));
  return net.http_post(
    url := v_url,
    body := jsonb_build_object('token', v_token),
    headers := jsonb_build_object('Content-Type', 'application/json'),
    timeout_milliseconds := 5000);
end
$$;
revoke all on function private.kick_worker(text,text) from public, anon, authenticated;

create or replace function private.consume_dispatch_token(p_purpose text, p_token text)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare v_id bigint;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{64}$' then return false; end if;
  delete from private.dispatch_tokens t
  where t.purpose = p_purpose and t.token_hash = extensions.digest(p_token, 'sha256')
    and t.created_at > now() - interval '10 minutes'
  returning t.id into v_id;
  return v_id is not null;
end
$$;
revoke all on function private.consume_dispatch_token(text,text) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. Security notifications
-- ---------------------------------------------------------------------------
create table if not exists public.account_notification_preferences (
  identity_id uuid primary key references public.identities(id) on delete cascade,
  new_sign_in_email boolean not null default true,
  breach_email boolean not null default true,
  weekly_report_email boolean not null default true,
  updated_at timestamptz not null default now()
);
alter table public.account_notification_preferences enable row level security;
revoke all on public.account_notification_preferences from anon, authenticated;
grant select on public.account_notification_preferences to authenticated;
drop policy if exists account_notification_preferences_own on public.account_notification_preferences;
create policy account_notification_preferences_own on public.account_notification_preferences
  for select to authenticated using (identity_id = (select private.current_identity_id()));

create or replace function private.set_my_notification_preferences(
  p_new_sign_in boolean, p_breach boolean, p_weekly_report boolean
) returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null then raise exception 'sign in required' using errcode = '42501'; end if;
  insert into public.account_notification_preferences as p (identity_id, new_sign_in_email, breach_email, weekly_report_email)
  values (v_actor, coalesce(p_new_sign_in, true), coalesce(p_breach, true), coalesce(p_weekly_report, true))
  on conflict (identity_id) do update set new_sign_in_email = excluded.new_sign_in_email,
    breach_email = excluded.breach_email, weekly_report_email = excluded.weekly_report_email, updated_at = now();
end
$$;

alter table public.notification_deliveries drop constraint if exists notification_deliveries_event_type_check;
alter table public.notification_deliveries add constraint notification_deliveries_event_type_check
  check (event_type in ('new_device','security_alert','access_requested','access_approved','recovery_changed',
    'billing_notice','agent_killed','verification','breach_exposure','passkey_nudge','rotation_assigned','weekly_report'));
alter table public.notification_deliveries drop constraint if exists notification_deliveries_provider_check;
alter table public.notification_deliveries add constraint notification_deliveries_provider_check
  check (provider in ('supabase','sent','smtp','resend'));

create table if not exists private.notification_outbox (
  id bigint generated always as identity primary key,
  tenant_id uuid references public.tenants(id) on delete cascade,
  recipient_identity_id uuid not null references public.identities(id) on delete cascade,
  event_type text not null check (event_type in ('new_device','security_alert','breach_exposure','passkey_nudge','rotation_assigned','weekly_report')),
  template text not null check (template ~ '^[a-z_]{3,40}$'),
  params jsonb not null default '{}' check (jsonb_typeof(params) = 'object' and octet_length(params::text) <= 4096),
  dedupe_key text not null check (char_length(dedupe_key) between 3 and 200),
  status text not null default 'pending' check (status in ('pending','claimed','sent','failed','skipped')),
  attempts smallint not null default 0,
  claimed_at timestamptz,
  sent_at timestamptz,
  error_code text check (error_code is null or error_code ~ '^[A-Za-z0-9_:-]{2,96}$'),
  created_at timestamptz not null default now(),
  unique (recipient_identity_id, dedupe_key)
);
create index if not exists notification_outbox_pending_idx on private.notification_outbox (status, id) where status in ('pending','claimed');
revoke all on private.notification_outbox from public, anon, authenticated;

create or replace function private.personal_tenant_of(p_identity uuid)
returns uuid language sql stable security definer set search_path = ''
as $$
  select coalesce(
    (select t.id from public.tenants t join public.tenant_memberships tm on tm.tenant_id = t.id
      where t.kind = 'personal' and tm.identity_id = p_identity and tm.status = 'active' order by t.created_at limit 1),
    (select tm.tenant_id from public.tenant_memberships tm where tm.identity_id = p_identity and tm.status = 'active'
      order by tm.created_at limit 1))
$$;
revoke all on function private.personal_tenant_of(uuid) from public, anon, authenticated;

create or replace function private.enqueue_notification(
  p_tenant uuid, p_recipient uuid, p_event text, p_template text, p_params jsonb, p_dedupe text
) returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if p_recipient is null then return; end if;
  insert into private.notification_outbox (tenant_id, recipient_identity_id, event_type, template, params, dedupe_key)
  values (coalesce(p_tenant, private.personal_tenant_of(p_recipient)), p_recipient, p_event, p_template,
    coalesce(p_params, '{}'::jsonb), p_dedupe)
  on conflict (recipient_identity_id, dedupe_key) do nothing;
end
$$;
revoke all on function private.enqueue_notification(uuid,uuid,text,text,jsonb,text) from public, anon, authenticated;

-- Worker claim: at most p_limit notifications, with recipient email and preferences.
create or replace function private.claim_notification_batch(p_token text, p_limit integer default 50)
returns table (id bigint, tenant_id uuid, recipient_identity_id uuid, email text, event_type text,
  template text, params jsonb, attempts smallint)
language plpgsql volatile security definer set search_path = ''
as $$
begin
  if not private.consume_dispatch_token('notify', p_token) then
    raise exception 'invalid worker token' using errcode = '42501';
  end if;
  return query
  with picked as (
    select o.id from private.notification_outbox o
    where (o.status = 'pending' or (o.status = 'claimed' and o.claimed_at < now() - interval '10 minutes'))
      and o.attempts < 5
    order by o.id
    limit least(greatest(coalesce(p_limit, 50), 1), 200)
    for update skip locked
  ), claimed as (
    update private.notification_outbox o set status = 'claimed', claimed_at = now(), attempts = o.attempts + 1
    from picked where o.id = picked.id
    returning o.*
  )
  select c.id, c.tenant_id, c.recipient_identity_id, u.email::text, c.event_type, c.template, c.params, c.attempts
  from claimed c
  join public.identities i on i.id = c.recipient_identity_id and i.status = 'active'
  left join auth.users u on u.id = i.auth_user_id and u.email_confirmed_at is not null and u.deleted_at is null
  order by c.id;
end
$$;
revoke all on function private.claim_notification_batch(text,integer) from public, anon, authenticated;
grant execute on function private.claim_notification_batch(text,integer) to service_role;

create or replace function private.complete_notification(p_id bigint, p_status text, p_error text default null)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if p_status not in ('sent','failed','skipped','pending') then raise exception 'invalid status' using errcode = '22023'; end if;
  update private.notification_outbox set status = p_status,
    sent_at = case when p_status = 'sent' then now() else sent_at end,
    error_code = case when p_error ~ '^[A-Za-z0-9_:-]{2,96}$' then p_error else null end
  where id = p_id and status = 'claimed';
end
$$;
revoke all on function private.complete_notification(bigint,text,text) from public, anon, authenticated;
grant execute on function private.complete_notification(bigint,text,text) to service_role;

create or replace function private.kick_notification_dispatch()
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform private.process_sign_in_alerts();
  delete from private.notification_outbox where created_at < now() - interval '30 days' and status in ('sent','failed','skipped');
  if exists (select 1 from private.notification_outbox o
             where (o.status = 'pending' or (o.status = 'claimed' and o.claimed_at < now() - interval '10 minutes')) and o.attempts < 5) then
    perform private.kick_worker('notify', 'notify_dispatch_url');
  end if;
end
$$;
revoke all on function private.kick_notification_dispatch() from public, anon, authenticated;

-- Administrators who receive organization security emails.
create or replace function private.security_contacts(p_tenant uuid)
returns setof uuid language sql stable security definer set search_path = ''
as $$
  select tm.identity_id from public.tenant_memberships tm
    where tm.tenant_id = p_tenant and tm.status = 'active' and tm.role in ('owner','admin')
  union
  select oa.identity_id from public.organization_admin_assignments oa
    join public.tenant_memberships tm on tm.tenant_id = oa.tenant_id and tm.identity_id = oa.identity_id and tm.status = 'active'
    where oa.tenant_id = p_tenant and oa.status = 'active' and oa.scope_type = 'tenant'
      and oa.role in ('organization_admin','security_admin')
$$;
revoke all on function private.security_contacts(uuid) from public, anon, authenticated;

-- Critical and high alerts are emailed to administrators (unless the organization turned
-- security emails off).
create or replace function private.notify_admins_of_alert()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
declare v_settings record; v_admin uuid;
begin
  if new.severity not in ('critical','high') then return new; end if;
  select s.security_email_enabled, s.event_types into v_settings
    from public.tenant_notification_settings s where s.tenant_id = new.tenant_id;
  if found and (not v_settings.security_email_enabled or not ('security_alert' = any(v_settings.event_types))) then
    return new;
  end if;
  for v_admin in select * from private.security_contacts(new.tenant_id) loop
    perform private.enqueue_notification(new.tenant_id, v_admin, 'security_alert', 'security_alert',
      jsonb_build_object('title', new.title, 'severity', new.severity, 'kind', new.kind),
      'alert:' || new.id);
  end loop;
  return new;
end
$$;
revoke all on function private.notify_admins_of_alert() from public, anon, authenticated;
drop trigger if exists security_alerts_notify on public.security_alerts;
create trigger security_alerts_notify after insert on public.security_alerts
  for each row execute function private.notify_admins_of_alert();

-- ---------------------------------------------------------------------------
-- 3. Sign-in tracking
-- ---------------------------------------------------------------------------
create table if not exists public.account_sign_ins (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete cascade,
  auth_session_id uuid not null unique,
  device_label text not null check (char_length(device_label) between 3 and 60),
  device_key text not null check (char_length(device_key) between 3 and 60),
  network_label text check (network_label is null or char_length(network_label) <= 60),
  network_key text check (network_key is null or char_length(network_key) <= 60),
  country text check (country is null or country ~ '^[A-Z]{2}$'),
  new_device boolean not null default false,
  new_network boolean not null default false,
  new_country boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists account_sign_ins_identity_idx on public.account_sign_ins (identity_id, created_at desc);
alter table public.account_sign_ins enable row level security;
revoke all on public.account_sign_ins from anon, authenticated;
grant select on public.account_sign_ins to authenticated;
drop policy if exists account_sign_ins_own on public.account_sign_ins;
create policy account_sign_ins_own on public.account_sign_ins for select to authenticated
  using (identity_id = (select private.current_identity_id()));

-- "Chrome on Windows". A fixed vocabulary: nothing from the user agent is copied verbatim.
create or replace function private.describe_user_agent(p_user_agent text)
returns text language sql immutable set search_path = ''
as $$
  select case
    when p_user_agent is null or btrim(p_user_agent) = '' then 'Unknown device'
    when p_user_agent ~* 'passkey-x-(desktop|cli)' then 'Passkey-X app'
    else
      (case
        when p_user_agent ~* 'edg(e|a|ios)?/' then 'Edge'
        when p_user_agent ~* '(opr|opera)/' then 'Opera'
        when p_user_agent ~* 'samsungbrowser/' then 'Samsung Internet'
        when p_user_agent ~* '(firefox|fxios)/' then 'Firefox'
        when p_user_agent ~* '(chrome|crios|chromium)/' then 'Chrome'
        when p_user_agent ~* 'version/.*safari/' then 'Safari'
        when p_user_agent ~* '(okhttp|dalvik)' then 'Android app'
        when p_user_agent ~* '(node|deno|bun|undici|axios|python|curl|go-http)' then 'Script or API client'
        else 'Browser' end)
      || ' on ' ||
      (case
        when p_user_agent ~* '(iphone|ipad|ipod|ios)' then 'iOS'
        when p_user_agent ~* 'android' then 'Android'
        when p_user_agent ~* 'cros' then 'ChromeOS'
        when p_user_agent ~* 'windows' then 'Windows'
        when p_user_agent ~* '(macintosh|mac os)' then 'macOS'
        when p_user_agent ~* 'linux' then 'Linux'
        else 'unknown system' end)
  end
$$;

-- Coarse network: /24 for IPv4, /48 for IPv6. The full address is never stored.
create or replace function private.network_key(p_ip inet)
returns text language sql immutable set search_path = ''
as $$
  select case
    when p_ip is null then null
    when family(p_ip) = 4 then host(network(set_masklen(p_ip, 24))) || '/24'
    else host(network(set_masklen(p_ip, 48))) || '/48' end
$$;

create or replace function private.network_label(p_ip inet)
returns text language sql immutable set search_path = ''
as $$
  select case
    when p_ip is null then null
    when family(p_ip) = 4 then regexp_replace(host(p_ip), '\.[0-9]+$', '.x')
    else host(network(set_masklen(p_ip, 48))) || '::/48' end
$$;

create or replace function private.org_tenants_of(p_identity uuid)
returns setof uuid language sql stable security definer set search_path = ''
as $$
  select tm.tenant_id from public.tenant_memberships tm join public.tenants t on t.id = tm.tenant_id
  where tm.identity_id = p_identity and tm.status = 'active' and t.kind = 'organization'
$$;
revoke all on function private.org_tenants_of(uuid) from public, anon, authenticated;

-- Organization alerts from sign-ins are queued here and raised by the per-minute job, so the
-- Auth transaction that creates a session never waits on audit-log locks.
create table if not exists private.sign_in_alert_queue (
  id bigint generated always as identity primary key,
  identity_id uuid not null references public.identities(id) on delete cascade,
  severity text not null check (severity in ('high','medium')),
  kind text not null,
  title text not null,
  detail jsonb not null default '{}',
  dedupe_key text not null,
  created_at timestamptz not null default now()
);
revoke all on private.sign_in_alert_queue from public, anon, authenticated;

create or replace function private.process_sign_in_alerts()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_row record; v_tenant uuid; v_count integer := 0;
begin
  for v_row in delete from private.sign_in_alert_queue q
      where q.id in (select id from private.sign_in_alert_queue order by id limit 500 for update skip locked)
      returning q.* loop
    for v_tenant in select * from private.org_tenants_of(v_row.identity_id) loop
      perform private.raise_security_alert(v_tenant, v_row.severity, v_row.kind, v_row.title, v_row.detail,
        v_row.identity_id, null, v_row.dedupe_key);
    end loop;
    v_count := v_count + 1;
  end loop;
  return v_count;
end
$$;
revoke all on function private.process_sign_in_alerts() from public, anon, authenticated;

create or replace function private.record_sign_in(p_session uuid, p_user uuid, p_user_agent text, p_ip inet)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_identity uuid;
  v_label text := private.describe_user_agent(p_user_agent);
  v_device_key text := lower(private.describe_user_agent(p_user_agent));
  v_network text := private.network_key(p_ip);
  v_history boolean;
  v_new_device boolean := false;
  v_new_network boolean := false;
  v_networks integer;
  v_notify boolean;
begin
  select i.id into v_identity from public.identities i where i.auth_user_id = p_user and i.kind = 'human';
  if v_identity is null then return; end if;
  v_history := exists (select 1 from public.account_sign_ins s where s.identity_id = v_identity);
  if v_history then
    v_new_device := not exists (select 1 from public.account_sign_ins s where s.identity_id = v_identity
      and s.device_key = v_device_key and s.created_at > now() - interval '180 days');
    v_new_network := v_network is not null and not exists (select 1 from public.account_sign_ins s
      where s.identity_id = v_identity and s.network_key = v_network and s.created_at > now() - interval '180 days');
  end if;
  insert into public.account_sign_ins (identity_id, auth_session_id, device_label, device_key, network_label, network_key, new_device, new_network)
  values (v_identity, p_session, v_label, v_device_key, private.network_label(p_ip), v_network, v_new_device, v_new_network)
  on conflict (auth_session_id) do nothing;

  select coalesce((select p.new_sign_in_email from public.account_notification_preferences p where p.identity_id = v_identity), true)
    into v_notify;
  if v_new_device and v_notify then
    perform private.enqueue_notification(null, v_identity, 'new_device', 'new_sign_in',
      jsonb_build_object('device', v_label, 'network', private.network_label(p_ip), 'at', now()),
      'signin:' || p_session);
  end if;
  -- Organizations see the device type only, never the member's network.
  if v_new_device and v_new_network then
    insert into private.sign_in_alert_queue (identity_id, severity, kind, title, detail, dedupe_key)
    values (v_identity, 'medium', 'sign_in.unfamiliar', 'A member signed in from a new device and network',
      jsonb_build_object('device', v_label), 'signin:' || p_session);
  end if;
  -- Sign-ins from many different networks within an hour can mean a stolen session or password.
  select count(distinct s.network_key) into v_networks from public.account_sign_ins s
    where s.identity_id = v_identity and s.created_at > now() - interval '1 hour' and s.network_key is not null;
  if v_networks >= 4 then
    insert into private.sign_in_alert_queue (identity_id, severity, kind, title, detail, dedupe_key)
    values (v_identity, 'high', 'sign_in.many_networks', 'A member signed in from many networks within an hour',
      jsonb_build_object('networks_1h', v_networks), 'signin-velocity:' || v_identity || ':' || to_char(now(), 'YYYYMMDDHH24'));
    if v_notify then
      perform private.enqueue_notification(null, v_identity, 'new_device', 'many_networks',
        jsonb_build_object('networks', v_networks), 'signin-velocity:' || to_char(now(), 'YYYYMMDDHH24'));
    end if;
  end if;
end
$$;
revoke all on function private.record_sign_in(uuid,uuid,text,inet) from public, anon, authenticated;

-- Never blocks sign-in: any failure here is swallowed.
create or replace function private.on_auth_session_created()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  begin
    perform private.record_sign_in(new.id, new.user_id, new.user_agent, new.ip);
  exception when others then
    null;
  end;
  return new;
end
$$;
revoke all on function private.on_auth_session_created() from public, anon, authenticated;
drop trigger if exists passkey_x_record_sign_in on auth.sessions;
create trigger passkey_x_record_sign_in after insert on auth.sessions
  for each row execute function private.on_auth_session_created();

-- The signed-in person's active sessions.
create or replace function private.my_sessions()
returns table (session_id uuid, created_at timestamptz, last_active_at timestamptz, device_label text,
  network_label text, country text, two_step boolean, is_current boolean)
language sql stable security definer set search_path = ''
as $$
  select s.id, s.created_at,
    greatest(s.updated_at, (s.refreshed_at at time zone 'UTC'), s.created_at),
    coalesce(si.device_label, private.describe_user_agent(s.user_agent)),
    coalesce(si.network_label, private.network_label(s.ip)),
    si.country,
    s.aal::text in ('aal2','aal3'),
    s.id::text = (auth.jwt() ->> 'session_id')
  from auth.sessions s
  left join public.account_sign_ins si on si.auth_session_id = s.id
  where s.user_id = auth.uid() and (s.not_after is null or s.not_after > now())
  order by 8 desc, 3 desc
  limit 100
$$;

create or replace function private.revoke_my_session(p_session_id uuid)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare v_deleted uuid; v_actor uuid := private.current_identity_id(); v_tenant uuid;
begin
  if auth.uid() is null or v_actor is null then raise exception 'sign in required' using errcode = '42501'; end if;
  if not private.session_mfa_satisfied() then raise exception 'two-step verification required' using errcode = '42501'; end if;
  if p_session_id::text = (auth.jwt() ->> 'session_id') then
    raise exception 'use sign out for this device' using errcode = '22023';
  end if;
  delete from auth.sessions s where s.id = p_session_id and s.user_id = auth.uid() returning s.id into v_deleted;
  if v_deleted is null then return false; end if;
  v_tenant := private.personal_tenant_of(v_actor);
  if v_tenant is not null then
    perform private.append_audit_event(v_tenant, v_actor, 'session.revoked', 'auth_sessions', v_deleted, '{}'::jsonb);
  end if;
  return true;
end
$$;

-- Country attestation from the Netlify sign-in-context function:
-- signature = hex(HMAC-SHA256(key, "<session_id>.<country>.<issued_at>")).
create or replace function private.attest_sign_in_country(p_country text, p_issued_at bigint, p_signature text)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_session text := auth.jwt() ->> 'session_id';
  v_key text := (select s.value from private.app_settings s where s.key = 'geo_attestation_key');
  v_row public.account_sign_ins%rowtype;
  v_new boolean;
  v_tenant uuid;
  v_notify boolean;
begin
  -- Every argument must be present: a NULL would make these comparisons NULL (not false).
  if v_session is null or v_key is null or p_country is null or p_signature is null or p_issued_at is null
     or p_country !~ '^[A-Z]{2}$' or p_signature !~ '^[0-9a-f]{64}$'
     or abs(extract(epoch from now())::bigint - p_issued_at) > 300 then
    return false;
  end if;
  if encode(extensions.hmac(v_session || '.' || p_country || '.' || p_issued_at::text, v_key, 'sha256'), 'hex') is distinct from p_signature then
    return false;
  end if;
  select * into v_row from public.account_sign_ins s where s.auth_session_id = v_session::uuid for update;
  if not found or v_row.country is not null then return false; end if;
  v_new := exists (select 1 from public.account_sign_ins s where s.identity_id = v_row.identity_id and s.country is not null
      and s.id <> v_row.id)
    and not exists (select 1 from public.account_sign_ins s where s.identity_id = v_row.identity_id
      and s.country = p_country and s.id <> v_row.id and s.created_at > now() - interval '180 days');
  update public.account_sign_ins set country = p_country, new_country = v_new where id = v_row.id;
  if v_new then
    select coalesce((select p.new_sign_in_email from public.account_notification_preferences p where p.identity_id = v_row.identity_id), true)
      into v_notify;
    if v_notify then
      perform private.enqueue_notification(null, v_row.identity_id, 'new_device', 'new_country',
        jsonb_build_object('device', v_row.device_label, 'country', p_country, 'at', v_row.created_at),
        'signin-country:' || v_row.auth_session_id);
    end if;
    for v_tenant in select * from private.org_tenants_of(v_row.identity_id) loop
      perform private.raise_security_alert(v_tenant, 'medium', 'sign_in.new_country',
        'A member signed in from a new country',
        jsonb_build_object('country', p_country, 'device', v_row.device_label),
        v_row.identity_id, null, 'signin-country:' || v_row.auth_session_id);
    end loop;
  end if;
  return true;
end
$$;

-- ---------------------------------------------------------------------------
-- 4. Single security score: richer reports and daily history
-- ---------------------------------------------------------------------------
alter table public.security_health_reports
  add column if not exists exposed_secret_count integer not null default 0 check (exposed_secret_count between 0 and 1000000),
  add column if not exists lookalike_count integer not null default 0 check (lookalike_count between 0 and 1000000),
  add column if not exists passkey_ready_count integer not null default 0 check (passkey_ready_count between 0 and 1000000),
  add column if not exists two_factor_ready_count integer not null default 0 check (two_factor_ready_count between 0 and 1000000);

create table if not exists public.security_health_history (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  day date not null,
  score smallint not null check (score between 0 and 100),
  login_count integer not null default 0,
  weak_count integer not null default 0,
  reused_count integer not null default 0,
  old_count integer not null default 0,
  breached_count integer,
  exposed_secret_count integer not null default 0,
  passkey_count integer not null default 0,
  primary key (tenant_id, identity_id, day)
);
create index if not exists security_health_history_day_idx on public.security_health_history (tenant_id, day);
alter table public.security_health_history enable row level security;
revoke all on public.security_health_history from anon, authenticated;
grant select on public.security_health_history to authenticated;
drop policy if exists security_health_history_read on public.security_health_history;
create policy security_health_history_read on public.security_health_history for select to authenticated
using (
  identity_id = (select private.current_identity_id())
  or (select private.can_read_organization_audit(tenant_id))
  or (select private.can_manage_organization(tenant_id, array['organization_admin','security_admin','auditor']))
);

create or replace function private.record_health_history()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  insert into public.security_health_history as h (tenant_id, identity_id, day, score, login_count, weak_count,
    reused_count, old_count, breached_count, exposed_secret_count, passkey_count)
  values (new.tenant_id, new.identity_id, (now() at time zone 'UTC')::date, new.score, new.login_count, new.weak_count,
    new.reused_count, new.old_count, new.breached_count, new.exposed_secret_count, new.passkey_count)
  on conflict (tenant_id, identity_id, day) do update set score = excluded.score, login_count = excluded.login_count,
    weak_count = excluded.weak_count, reused_count = excluded.reused_count, old_count = excluded.old_count,
    breached_count = coalesce(excluded.breached_count, h.breached_count),
    exposed_secret_count = excluded.exposed_secret_count, passkey_count = excluded.passkey_count;
  return new;
end
$$;
revoke all on function private.record_health_history() from public, anon, authenticated;
drop trigger if exists security_health_reports_history on public.security_health_reports;
create trigger security_health_reports_history after insert or update on public.security_health_reports
  for each row execute function private.record_health_history();

-- Version 2 of the on-device report: one JSON object of counts with a fixed set of keys.
create or replace function private.report_security_health_v2(p_tenant_id uuid, p_metrics jsonb, p_client_kind text default 'web')
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_key text;
  v_allowed text[] := array['score','items','logins','weak','reused','old','breached','missing_totp','passkeys',
    'exposed_secrets','lookalikes','passkey_ready','two_factor_ready'];
  v_breached integer;
begin
  if v_actor is null or not exists (select 1 from public.tenant_memberships tm
      where tm.tenant_id = p_tenant_id and tm.identity_id = v_actor and tm.status = 'active') then
    raise exception 'tenant membership required' using errcode = '42501';
  end if;
  if jsonb_typeof(p_metrics) <> 'object' then raise exception 'invalid report' using errcode = '22023'; end if;
  for v_key in select jsonb_object_keys(p_metrics) loop
    if not (v_key = any(v_allowed)) then raise exception 'invalid report' using errcode = '22023'; end if;
    if v_key = 'breached' and p_metrics -> v_key = 'null'::jsonb then continue; end if;
    if jsonb_typeof(p_metrics -> v_key) <> 'number' or (p_metrics ->> v_key)::numeric <> floor((p_metrics ->> v_key)::numeric)
       or (p_metrics ->> v_key)::numeric not between 0 and 1000000 then
      raise exception 'invalid report' using errcode = '22023';
    end if;
  end loop;
  if (p_metrics ->> 'score') is null or (p_metrics ->> 'score')::integer > 100 then
    raise exception 'invalid report' using errcode = '22023';
  end if;
  if coalesce(p_client_kind, 'web') not in ('web','desktop','mobile','android','extension') then
    raise exception 'invalid report' using errcode = '22023';
  end if;
  v_breached := case when p_metrics ? 'breached' and p_metrics -> 'breached' <> 'null'::jsonb then (p_metrics ->> 'breached')::integer end;
  insert into public.security_health_reports as r (tenant_id, identity_id, score, item_count, login_count, weak_count,
    reused_count, old_count, breached_count, missing_totp_count, passkey_count, breach_check_at, client_kind, reported_at,
    exposed_secret_count, lookalike_count, passkey_ready_count, two_factor_ready_count)
  values (p_tenant_id, v_actor, (p_metrics ->> 'score')::integer, coalesce((p_metrics ->> 'items')::integer, 0),
    coalesce((p_metrics ->> 'logins')::integer, 0), coalesce((p_metrics ->> 'weak')::integer, 0),
    coalesce((p_metrics ->> 'reused')::integer, 0), coalesce((p_metrics ->> 'old')::integer, 0), v_breached,
    coalesce((p_metrics ->> 'missing_totp')::integer, 0), coalesce((p_metrics ->> 'passkeys')::integer, 0),
    case when v_breached is null then null else now() end, coalesce(p_client_kind, 'web'), now(),
    coalesce((p_metrics ->> 'exposed_secrets')::integer, 0), coalesce((p_metrics ->> 'lookalikes')::integer, 0),
    coalesce((p_metrics ->> 'passkey_ready')::integer, 0), coalesce((p_metrics ->> 'two_factor_ready')::integer, 0))
  on conflict (tenant_id, identity_id) do update set
    score = excluded.score, item_count = excluded.item_count, login_count = excluded.login_count,
    weak_count = excluded.weak_count, reused_count = excluded.reused_count, old_count = excluded.old_count,
    breached_count = coalesce(excluded.breached_count, r.breached_count),
    breach_check_at = coalesce(excluded.breach_check_at, r.breach_check_at),
    missing_totp_count = excluded.missing_totp_count, passkey_count = excluded.passkey_count,
    client_kind = excluded.client_kind, reported_at = now(),
    exposed_secret_count = excluded.exposed_secret_count, lookalike_count = excluded.lookalike_count,
    passkey_ready_count = excluded.passkey_ready_count, two_factor_ready_count = excluded.two_factor_ready_count;
end
$$;

create or replace function private.can_view_security_posture(p_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.can_read_organization_audit(p_tenant)
    or private.can_manage_organization(p_tenant, array['organization_admin','security_admin','auditor'])
$$;
revoke all on function private.can_view_security_posture(uuid) from public, anon;
grant execute on function private.can_view_security_posture(uuid) to authenticated;

-- Organization score per day: each member's latest report in the 30 days up to that day.
create or replace function private.organization_health_trend(p_tenant_id uuid, p_days integer default 30)
returns table (day date, average_score integer, members_reporting integer, weak integer, reused integer,
  breached integer, exposed_secrets integer)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  return query
  select d.day::date, round(avg(h.score))::integer, count(h.identity_id)::integer,
    coalesce(sum(h.weak_count), 0)::integer, coalesce(sum(h.reused_count), 0)::integer,
    coalesce(sum(h.breached_count), 0)::integer, coalesce(sum(h.exposed_secret_count), 0)::integer
  from generate_series((now() at time zone 'UTC')::date - (least(greatest(coalesce(p_days, 30), 7), 180) - 1),
    (now() at time zone 'UTC')::date, interval '1 day') as d(day)
  left join lateral (
    select distinct on (x.identity_id) x.identity_id, x.score, x.weak_count, x.reused_count, x.breached_count, x.exposed_secret_count
    from public.security_health_history x
    join public.tenant_memberships tm on tm.tenant_id = x.tenant_id and tm.identity_id = x.identity_id and tm.status = 'active'
    where x.tenant_id = p_tenant_id and x.day <= d.day::date and x.day > d.day::date - 30
    order by x.identity_id, x.day desc
  ) h on true
  group by d.day
  order by d.day;
end
$$;

-- Score by department (current reports).
create or replace function private.organization_health_by_team(p_tenant_id uuid)
returns table (department_id uuid, department_name text, members integer, members_reporting integer,
  average_score integer, weak integer, reused integer, breached integer, exposed_secrets integer)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  return query
  select p.department_id, coalesce(d.display_name, 'No department'),
    count(*)::integer, count(h.identity_id)::integer, round(avg(h.score))::integer,
    coalesce(sum(h.weak_count), 0)::integer, coalesce(sum(h.reused_count), 0)::integer,
    coalesce(sum(h.breached_count), 0)::integer, coalesce(sum(h.exposed_secret_count), 0)::integer
  from public.tenant_memberships tm
  left join public.organization_profiles p on p.tenant_id = tm.tenant_id and p.identity_id = tm.identity_id
  left join public.organization_departments d on d.tenant_id = tm.tenant_id and d.id = p.department_id
  left join public.security_health_reports h on h.tenant_id = tm.tenant_id and h.identity_id = tm.identity_id
  where tm.tenant_id = p_tenant_id and tm.status = 'active'
  group by p.department_id, d.display_name
  order by 5 nulls last, 2;
end
$$;


-- ---------------------------------------------------------------------------
-- 5. Employee breach watch (Have I Been Pwned)
-- ---------------------------------------------------------------------------
create table if not exists public.breach_watch_settings (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  enabled boolean not null default false,
  updated_by uuid references public.identities(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.breach_watch_settings enable row level security;
revoke all on public.breach_watch_settings from anon, authenticated;
grant select on public.breach_watch_settings to authenticated;
drop policy if exists breach_watch_settings_read on public.breach_watch_settings;
create policy breach_watch_settings_read on public.breach_watch_settings for select to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner','admin','member','auditor'])));

create table if not exists public.member_breach_exposures (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  breach_name text not null check (breach_name ~ '^[A-Za-z0-9 _.()-]{1,100}$'),
  breach_title text not null check (char_length(breach_title) between 1 and 160),
  breach_domain text check (breach_domain is null or breach_domain ~ '^[a-z0-9.-]{1,253}$'),
  breach_date date,
  data_classes text[] not null default '{}' check (cardinality(data_classes) <= 60),
  includes_passwords boolean not null default false,
  first_seen_at timestamptz not null default now(),
  -- Set by an administrator: the exposure was followed up.
  acknowledged_at timestamptz,
  acknowledged_by uuid references public.identities(id) on delete set null,
  -- Set by the member: "I've dealt with it". Does not hide the exposure from administrators.
  member_acknowledged_at timestamptz,
  primary key (tenant_id, identity_id, breach_name)
);
alter table public.member_breach_exposures enable row level security;
revoke all on public.member_breach_exposures from anon, authenticated;
grant select on public.member_breach_exposures to authenticated;
drop policy if exists member_breach_exposures_read on public.member_breach_exposures;
create policy member_breach_exposures_read on public.member_breach_exposures for select to authenticated
  using (identity_id = (select private.current_identity_id()) or (select private.can_view_security_posture(tenant_id)));

create table if not exists private.breach_watch_checks (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  last_checked_at timestamptz not null,
  last_status text check (last_status is null or last_status in ('ok','error')),
  -- True after the first successful check: from then on, new breaches raise alerts.
  baseline_done boolean not null default false,
  primary key (tenant_id, identity_id)
);
revoke all on private.breach_watch_checks from public, anon, authenticated;

create or replace function private.set_breach_watch(p_tenant_id uuid, p_enabled boolean)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if not private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin'])
     or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement and security admin role required' using errcode = '42501';
  end if;
  insert into public.breach_watch_settings as s (tenant_id, enabled, updated_by, updated_at)
  values (p_tenant_id, coalesce(p_enabled, false), v_actor, now())
  on conflict (tenant_id) do update set enabled = excluded.enabled, updated_by = excluded.updated_by, updated_at = now();
  perform private.append_audit_event(p_tenant_id, v_actor,
    case when p_enabled then 'breach_watch.enabled' else 'breach_watch.disabled' end,
    'breach_watch_settings', p_tenant_id, '{}'::jsonb);
end
$$;

create or replace function private.kick_breach_watch()
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if exists (
    select 1 from public.breach_watch_settings s
    join public.tenant_memberships tm on tm.tenant_id = s.tenant_id and tm.status = 'active'
    left join private.breach_watch_checks c on c.tenant_id = tm.tenant_id and c.identity_id = tm.identity_id
    where s.enabled and private.has_business_entitlement(s.tenant_id)
      and (c.last_checked_at is null or c.last_checked_at < now() - interval '7 days')
  ) then
    perform private.kick_worker('breach_watch', 'breach_watch_url');
  end if;
end
$$;
revoke all on function private.kick_breach_watch() from public, anon, authenticated;

-- Worker claim: members due for a weekly check. The email is only ever sent to HIBP.
create or replace function private.claim_breach_watch_batch(p_token text, p_limit integer default 8)
returns table (tenant_id uuid, identity_id uuid, email text)
language plpgsql volatile security definer set search_path = ''
as $$
declare v_row record;
begin
  if not private.consume_dispatch_token('breach_watch', p_token) then
    raise exception 'invalid worker token' using errcode = '42501';
  end if;
  for v_row in
    select tm.tenant_id as t, tm.identity_id as i, u.email::text as e
    from public.breach_watch_settings s
    join public.tenant_memberships tm on tm.tenant_id = s.tenant_id and tm.status = 'active'
    join public.identities ident on ident.id = tm.identity_id and ident.kind = 'human' and ident.status = 'active'
    join auth.users u on u.id = ident.auth_user_id and u.email_confirmed_at is not null and u.deleted_at is null
    left join private.breach_watch_checks c on c.tenant_id = tm.tenant_id and c.identity_id = tm.identity_id
    where s.enabled and private.has_business_entitlement(s.tenant_id)
      and (c.last_checked_at is null or c.last_checked_at < now() - interval '7 days')
    order by c.last_checked_at nulls first
    limit least(greatest(coalesce(p_limit, 8), 1), 40)
  loop
    insert into private.breach_watch_checks as c (tenant_id, identity_id, last_checked_at, last_status)
    values (v_row.t, v_row.i, now(), null)
    on conflict on constraint breach_watch_checks_pkey do update set last_checked_at = now();
    tenant_id := v_row.t; identity_id := v_row.i; email := v_row.e;
    return next;
  end loop;
end
$$;
revoke all on function private.claim_breach_watch_batch(text,integer) from public, anon, authenticated;
grant execute on function private.claim_breach_watch_batch(text,integer) to service_role;

-- Stores one member's result. The first check of a member only records history; later checks
-- raise an alert and email the member for every newly listed breach.
create or replace function private.record_breach_watch_result(p_tenant_id uuid, p_identity_id uuid, p_status text, p_breaches jsonb)
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_first boolean;
  v_breach jsonb;
  v_name text;
  v_classes text[];
  v_passwords boolean;
  v_inserted text;
  v_new integer := 0;
  v_notify boolean;
begin
  if p_status not in ('ok','error') then raise exception 'invalid status' using errcode = '22023'; end if;
  select not c.baseline_done into v_first from private.breach_watch_checks c
    where c.tenant_id = p_tenant_id and c.identity_id = p_identity_id for update;
  if not found then raise exception 'check not claimed' using errcode = '22023'; end if;
  if p_status = 'ok' then
    if jsonb_typeof(coalesce(p_breaches, '[]'::jsonb)) <> 'array' or jsonb_array_length(coalesce(p_breaches, '[]'::jsonb)) > 1000 then
      raise exception 'invalid breaches' using errcode = '22023';
    end if;
    select coalesce((select p.breach_email from public.account_notification_preferences p where p.identity_id = p_identity_id), true)
      into v_notify;
    for v_breach in select value from jsonb_array_elements(coalesce(p_breaches, '[]'::jsonb)) loop
      v_name := v_breach ->> 'name';
      continue when v_name is null or v_name !~ '^[A-Za-z0-9 _.()-]{1,100}$';
      v_classes := array(select left(c, 60) from jsonb_array_elements_text(coalesce(v_breach -> 'data_classes', '[]'::jsonb)) as c limit 60);
      v_passwords := 'Passwords' = any(v_classes);
      v_inserted := null;
      insert into public.member_breach_exposures (tenant_id, identity_id, breach_name, breach_title, breach_domain,
        breach_date, data_classes, includes_passwords)
      values (p_tenant_id, p_identity_id, v_name, left(coalesce(nullif(btrim(v_breach ->> 'title'), ''), v_name), 160),
        case when lower(v_breach ->> 'domain') ~ '^[a-z0-9.-]{1,253}$' then lower(v_breach ->> 'domain') end,
        case when (v_breach ->> 'date') ~ '^\d{4}-\d{2}-\d{2}$' then (v_breach ->> 'date')::date end,
        v_classes, v_passwords)
      on conflict do nothing
      returning breach_name into v_inserted;
      if v_inserted is not null and not v_first then
        v_new := v_new + 1;
        perform private.raise_security_alert(p_tenant_id, case when v_passwords then 'high' else 'medium' end,
          'member.breach_exposed', 'A member''s email appeared in a new data breach',
          jsonb_build_object('breach', v_name, 'includes_passwords', v_passwords), p_identity_id, null,
          'breach:' || p_identity_id || ':' || v_name);
        if v_notify then
          perform private.enqueue_notification(p_tenant_id, p_identity_id, 'breach_exposure', 'breach_exposure',
            jsonb_build_object('breach', left(coalesce(nullif(btrim(v_breach ->> 'title'), ''), v_name), 160),
              'includes_passwords', v_passwords), 'breach:' || v_name);
        end if;
      end if;
    end loop;
  end if;
  update private.breach_watch_checks set last_status = p_status, baseline_done = baseline_done or p_status = 'ok'
    where tenant_id = p_tenant_id and identity_id = p_identity_id;
  return v_new;
end
$$;
revoke all on function private.record_breach_watch_result(uuid,uuid,text,jsonb) from public, anon, authenticated;
grant execute on function private.record_breach_watch_result(uuid,uuid,text,jsonb) to service_role;

create or replace function private.organization_breach_watch(p_tenant_id uuid)
returns table (identity_id uuid, email text, display_name text, exposures integer, password_exposures integer,
  unacknowledged integer, latest_breach_date date, last_checked_at timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  return query
  select tm.identity_id, u.email::text, coalesce(p.display_name, split_part(u.email::text, '@', 1)),
    count(e.breach_name)::integer, count(e.breach_name) filter (where e.includes_passwords)::integer,
    count(e.breach_name) filter (where e.acknowledged_at is null)::integer,
    max(e.breach_date), max(c.last_checked_at)
  from public.tenant_memberships tm
  join public.identities i on i.id = tm.identity_id
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles p on p.tenant_id = tm.tenant_id and p.identity_id = tm.identity_id
  left join public.member_breach_exposures e on e.tenant_id = tm.tenant_id and e.identity_id = tm.identity_id
  left join private.breach_watch_checks c on c.tenant_id = tm.tenant_id and c.identity_id = tm.identity_id
  where tm.tenant_id = p_tenant_id and tm.status = 'active'
  group by tm.identity_id, u.email, p.display_name
  order by 6 desc, 5 desc, 3;
end
$$;

create or replace function private.acknowledge_breach_exposure(p_tenant_id uuid, p_identity_id uuid, p_breach_name text)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_admin boolean := private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin']);
  v_done text;
begin
  if v_actor is null or not (v_actor = p_identity_id or v_admin) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if v_admin then
    update public.member_breach_exposures set acknowledged_at = now(), acknowledged_by = v_actor
      where tenant_id = p_tenant_id and identity_id = p_identity_id and breach_name = p_breach_name and acknowledged_at is null
      returning breach_name into v_done;
  else
    update public.member_breach_exposures set member_acknowledged_at = now()
      where tenant_id = p_tenant_id and identity_id = p_identity_id and breach_name = p_breach_name and member_acknowledged_at is null
      returning breach_name into v_done;
  end if;
  if v_done is not null then
    perform private.append_audit_event(p_tenant_id, v_actor, 'breach_exposure.acknowledged', 'identities', p_identity_id,
      jsonb_build_object('breach', p_breach_name));
  end if;
  return v_done is not null;
end
$$;

-- ---------------------------------------------------------------------------
-- 6. Passkey adoption
-- ---------------------------------------------------------------------------
create table if not exists public.passkey_nudges (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  nudged_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists passkey_nudges_member_idx on public.passkey_nudges (tenant_id, identity_id, created_at desc);
alter table public.passkey_nudges enable row level security;
revoke all on public.passkey_nudges from anon, authenticated;

create or replace function private.organization_passkey_adoption(p_tenant_id uuid)
returns table (identity_id uuid, email text, display_name text, account_passkeys integer, two_step_methods integer,
  vault_passkeys integer, passkey_ready_sites integer, last_nudged_at timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  return query
  select tm.identity_id, u.email::text, coalesce(p.display_name, split_part(u.email::text, '@', 1)),
    (select count(*)::integer from auth.webauthn_credentials w where w.user_id = u.id),
    (select count(*)::integer from auth.mfa_factors f where f.user_id = u.id and f.status = 'verified'),
    coalesce(h.passkey_count, 0), coalesce(h.passkey_ready_count, 0),
    (select max(n.created_at) from public.passkey_nudges n where n.tenant_id = tm.tenant_id and n.identity_id = tm.identity_id)
  from public.tenant_memberships tm
  join public.identities i on i.id = tm.identity_id and i.kind = 'human'
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles p on p.tenant_id = tm.tenant_id and p.identity_id = tm.identity_id
  left join public.security_health_reports h on h.tenant_id = tm.tenant_id and h.identity_id = tm.identity_id
  where tm.tenant_id = p_tenant_id and tm.status = 'active'
  order by 4, 3;
end
$$;

-- Emails members without an account passkey (at most once a week each).
create or replace function private.send_passkey_nudges(p_tenant_id uuid, p_identity_ids uuid[])
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_target uuid; v_count integer := 0;
begin
  if not private.can_admin_workspace_access(p_tenant_id) or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement and admin role required' using errcode = '42501';
  end if;
  if cardinality(p_identity_ids) > 500 then raise exception 'too many members' using errcode = '22023'; end if;
  for v_target in
    select tm.identity_id from public.tenant_memberships tm
    join public.identities i on i.id = tm.identity_id and i.kind = 'human' and i.status = 'active'
    where tm.tenant_id = p_tenant_id and tm.status = 'active' and tm.identity_id = any(p_identity_ids)
      and not exists (select 1 from auth.webauthn_credentials w where w.user_id = i.auth_user_id)
      and not exists (select 1 from public.passkey_nudges n where n.tenant_id = p_tenant_id and n.identity_id = tm.identity_id
        and n.created_at > now() - interval '7 days')
  loop
    insert into public.passkey_nudges (tenant_id, identity_id, nudged_by) values (p_tenant_id, v_target, v_actor);
    perform private.enqueue_notification(p_tenant_id, v_target, 'passkey_nudge', 'passkey_nudge', '{}'::jsonb,
      'passkey-nudge:' || p_tenant_id || ':' || to_char(now(), 'IYYYIW'));
    v_count := v_count + 1;
  end loop;
  if v_count > 0 then
    perform private.append_audit_event(p_tenant_id, v_actor, 'passkey.nudged', 'tenants', p_tenant_id,
      jsonb_build_object('members', v_count));
  end if;
  return v_count;
end
$$;

-- ---------------------------------------------------------------------------
-- 7. Guided password rotation
-- ---------------------------------------------------------------------------
create table if not exists public.rotation_campaigns (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  title text not null check (char_length(btrim(title)) between 3 and 120),
  reason text check (reason is null or char_length(reason) <= 500),
  due_at timestamptz not null,
  status text not null default 'open' check (status in ('open','closed')),
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  closed_at timestamptz,
  closed_by uuid references public.identities(id) on delete set null
);
create index if not exists rotation_campaigns_tenant_idx on public.rotation_campaigns (tenant_id, status, due_at);

create table if not exists public.rotation_tasks (
  id uuid primary key default gen_random_uuid(),
  campaign_id uuid not null references public.rotation_campaigns(id) on delete cascade,
  tenant_id uuid not null,
  item_id uuid not null,
  workspace_id uuid not null,
  assignee_identity_id uuid not null references public.identities(id) on delete cascade,
  baseline_revision bigint not null,
  status text not null default 'pending' check (status in ('pending','done','skipped','cancelled')),
  completed_at timestamptz,
  completed_by uuid references public.identities(id) on delete set null,
  note text check (note is null or char_length(note) <= 300),
  created_at timestamptz not null default now(),
  unique (campaign_id, item_id),
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade
);
create index if not exists rotation_tasks_assignee_idx on public.rotation_tasks (assignee_identity_id, status);
create index if not exists rotation_tasks_item_idx on public.rotation_tasks (item_id) where status = 'pending';

alter table public.rotation_campaigns enable row level security;
alter table public.rotation_tasks enable row level security;
revoke all on public.rotation_campaigns, public.rotation_tasks from anon, authenticated;
grant select on public.rotation_campaigns, public.rotation_tasks to authenticated;
drop policy if exists rotation_tasks_read on public.rotation_tasks;
create policy rotation_tasks_read on public.rotation_tasks for select to authenticated
  using (assignee_identity_id = (select private.current_identity_id()) or (select private.can_view_security_posture(tenant_id)));
drop policy if exists rotation_campaigns_read on public.rotation_campaigns;
create policy rotation_campaigns_read on public.rotation_campaigns for select to authenticated
  using ((select private.can_view_security_posture(tenant_id)) or exists (
    select 1 from public.rotation_tasks t where t.campaign_id = rotation_campaigns.id
      and t.assignee_identity_id = (select private.current_identity_id())));

create or replace function private.create_rotation_campaign(
  p_tenant_id uuid, p_title text, p_reason text, p_due_at timestamptz, p_tasks jsonb
) returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_campaign uuid;
  v_task jsonb;
  v_item public.vault_items%rowtype;
  v_assignee uuid;
  v_count integer := 0;
  v_assignee_row record;
begin
  if not private.can_admin_workspace_access(p_tenant_id) or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement and admin role required' using errcode = '42501';
  end if;
  if p_due_at is null or p_due_at < now() + interval '1 hour' or p_due_at > now() + interval '365 days' then
    raise exception 'choose a due date between tomorrow and one year from now' using errcode = '22023';
  end if;
  if jsonb_typeof(p_tasks) <> 'array' or jsonb_array_length(p_tasks) not between 1 and 500 then
    raise exception 'choose between 1 and 500 items' using errcode = '22023';
  end if;
  insert into public.rotation_campaigns (tenant_id, title, reason, due_at, created_by)
  values (p_tenant_id, btrim(p_title), nullif(btrim(coalesce(p_reason, '')), ''), p_due_at, v_actor)
  returning id into v_campaign;
  for v_task in select value from jsonb_array_elements(p_tasks) loop
    begin
      v_assignee := (v_task ->> 'assignee_identity_id')::uuid;
      select * into v_item from public.vault_items vi
        where vi.tenant_id = p_tenant_id and vi.id = (v_task ->> 'item_id')::uuid and vi.deleted_at is null;
    exception when invalid_text_representation then
      raise exception 'invalid item or assignee' using errcode = '22023';
    end;
    if v_item.id is null then raise exception 'item not found' using errcode = '22023'; end if;
    -- The creator must be a member of the item's workspace (items are chosen from a vault they can open)
    -- and the assignee must be able to edit it.
    if not exists (select 1 from public.workspace_memberships wm where wm.workspace_id = v_item.workspace_id
        and wm.identity_id = v_actor and wm.status = 'active')
       or not exists (select 1 from public.workspace_memberships wm
        join public.tenant_memberships tm on tm.tenant_id = wm.tenant_id and tm.identity_id = wm.identity_id and tm.status = 'active'
        where wm.workspace_id = v_item.workspace_id and wm.identity_id = v_assignee and wm.status = 'active'
          and wm.role in ('owner','manager','editor')) then
      raise exception 'the assignee cannot edit this item' using errcode = '42501';
    end if;
    insert into public.rotation_tasks (campaign_id, tenant_id, item_id, workspace_id, assignee_identity_id, baseline_revision)
    values (v_campaign, p_tenant_id, v_item.id, v_item.workspace_id, v_assignee, v_item.head_revision)
    on conflict (campaign_id, item_id) do nothing;
    v_count := v_count + 1;
    v_item := null;
  end loop;
  for v_assignee_row in
    select t.assignee_identity_id as who, count(*) as n from public.rotation_tasks t where t.campaign_id = v_campaign group by 1
  loop
    perform private.enqueue_notification(p_tenant_id, v_assignee_row.who, 'rotation_assigned', 'rotation_assigned',
      jsonb_build_object('title', btrim(p_title), 'count', v_assignee_row.n, 'due', to_char(p_due_at, 'YYYY-MM-DD')),
      'rotation:' || v_campaign);
  end loop;
  perform private.append_audit_event(p_tenant_id, v_actor, 'rotation_campaign.created', 'rotation_campaigns', v_campaign,
    jsonb_build_object('items', v_count, 'due_at', p_due_at));
  return v_campaign;
end
$$;

-- A saved change to an item completes its open rotation tasks; deleting the item cancels them.
create or replace function private.track_rotation_progress()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  if new.deleted_at is not null and old.deleted_at is null then
    update public.rotation_tasks set status = 'cancelled', completed_at = now()
      where item_id = new.id and status = 'pending';
  elsif new.head_revision > old.head_revision then
    update public.rotation_tasks set status = 'done', completed_at = now(), completed_by = private.current_identity_id()
      where item_id = new.id and status = 'pending' and new.head_revision > baseline_revision;
  end if;
  return new;
end
$$;
revoke all on function private.track_rotation_progress() from public, anon, authenticated;
drop trigger if exists vault_items_rotation_progress on public.vault_items;
create trigger vault_items_rotation_progress after update of head_revision, deleted_at on public.vault_items
  for each row execute function private.track_rotation_progress();

create or replace function private.update_rotation_task(p_task_id uuid, p_status text, p_note text default null)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_task public.rotation_tasks%rowtype;
begin
  select * into v_task from public.rotation_tasks where id = p_task_id for update;
  if not found or not (v_task.assignee_identity_id = v_actor or private.can_admin_workspace_access(v_task.tenant_id)) then
    raise exception 'task not found' using errcode = '42501';
  end if;
  if p_status not in ('skipped','pending') or v_task.status in ('done','cancelled') then
    raise exception 'invalid status' using errcode = '22023';
  end if;
  update public.rotation_tasks set status = p_status, note = coalesce(nullif(btrim(coalesce(p_note, '')), ''), note),
    completed_at = case when p_status = 'skipped' then now() end,
    completed_by = case when p_status = 'skipped' then v_actor end
    where id = p_task_id;
  perform private.append_audit_event(v_task.tenant_id, v_actor, 'rotation_task.' || p_status, 'rotation_tasks', p_task_id,
    jsonb_build_object('campaign', v_task.campaign_id));
end
$$;

create or replace function private.close_rotation_campaign(p_campaign_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_tenant uuid;
begin
  select tenant_id into v_tenant from public.rotation_campaigns where id = p_campaign_id and status = 'open' for update;
  if v_tenant is null or not private.can_admin_workspace_access(v_tenant) then
    raise exception 'campaign not found' using errcode = '42501';
  end if;
  update public.rotation_campaigns set status = 'closed', closed_at = now(), closed_by = v_actor where id = p_campaign_id;
  perform private.append_audit_event(v_tenant, v_actor, 'rotation_campaign.closed', 'rotation_campaigns', p_campaign_id, '{}'::jsonb);
end
$$;

create or replace function private.rotation_campaign_summary(p_tenant_id uuid)
returns table (id uuid, title text, reason text, due_at timestamptz, status text, created_at timestamptz,
  total integer, done integer, skipped integer, pending integer, cancelled integer, overdue boolean)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  return query
  select c.id, c.title, c.reason, c.due_at, c.status, c.created_at,
    count(t.id)::integer, count(t.id) filter (where t.status = 'done')::integer,
    count(t.id) filter (where t.status = 'skipped')::integer, count(t.id) filter (where t.status = 'pending')::integer,
    count(t.id) filter (where t.status = 'cancelled')::integer,
    c.status = 'open' and c.due_at < now() and count(t.id) filter (where t.status = 'pending') > 0
  from public.rotation_campaigns c left join public.rotation_tasks t on t.campaign_id = c.id
  where c.tenant_id = p_tenant_id
  group by c.id
  order by c.status, c.due_at;
end
$$;

create or replace function private.check_rotation_overdue()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_row record; v_count integer := 0;
begin
  for v_row in
    select c.id, c.tenant_id, count(t.id) as pending from public.rotation_campaigns c
    join public.rotation_tasks t on t.campaign_id = c.id and t.status = 'pending'
    where c.status = 'open' and c.due_at < now()
    group by c.id
  loop
    perform private.raise_security_alert(v_row.tenant_id, 'low', 'rotation.overdue', 'A password rotation campaign is overdue',
      jsonb_build_object('pending', v_row.pending, 'campaign', v_row.id), null, null,
      'rotation-overdue:' || v_row.id || ':' || to_char(now(), 'YYYYMMDD'));
    v_count := v_count + 1;
  end loop;
  return v_count;
end
$$;
revoke all on function private.check_rotation_overdue() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 8. Weekly security reports
-- ---------------------------------------------------------------------------
create table if not exists public.weekly_security_reports (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  week_start date not null,
  report jsonb not null,
  ai_summary text check (ai_summary is null or char_length(ai_summary) <= 4000),
  ai_generated_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (tenant_id, week_start)
);
alter table public.weekly_security_reports enable row level security;
revoke all on public.weekly_security_reports from anon, authenticated;
grant select on public.weekly_security_reports to authenticated;
drop policy if exists weekly_security_reports_read on public.weekly_security_reports;
create policy weekly_security_reports_read on public.weekly_security_reports for select to authenticated
  using ((select private.can_view_security_posture(tenant_id)));

-- Aggregate posture for one organization. Counts only.
create or replace function private.build_security_report(p_tenant_id uuid)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare
  v jsonb;
  v_members integer; v_reporting integer; v_score integer; v_score_prev integer;
  v_weak integer; v_reused integer; v_breached integer; v_exposed integer; v_old integer; v_lookalikes integer;
  v_two_step integer; v_passkeys integer;
  v_alerts jsonb; v_alerts_new integer; v_breach_members integer; v_breach_new integer;
  v_rotation_pending integer; v_rotation_overdue integer; v_unfamiliar integer; v_policies integer;
  v_risks jsonb := '[]'::jsonb;
begin
  select count(*) into v_members from public.tenant_memberships tm
    join public.identities i on i.id = tm.identity_id and i.kind = 'human'
    where tm.tenant_id = p_tenant_id and tm.status = 'active';
  select count(h.identity_id), round(avg(h.score)), coalesce(sum(h.weak_count),0), coalesce(sum(h.reused_count),0),
      coalesce(sum(h.breached_count),0), coalesce(sum(h.exposed_secret_count),0), coalesce(sum(h.old_count),0),
      coalesce(sum(h.lookalike_count),0)
    into v_reporting, v_score, v_weak, v_reused, v_breached, v_exposed, v_old, v_lookalikes
    from public.security_health_reports h
    join public.tenant_memberships tm on tm.tenant_id = h.tenant_id and tm.identity_id = h.identity_id and tm.status = 'active'
    where h.tenant_id = p_tenant_id;
  select round(avg(x.score)) into v_score_prev from (
    select distinct on (y.identity_id) y.score from public.security_health_history y
    where y.tenant_id = p_tenant_id and y.day <= (now() at time zone 'UTC')::date - 7 and y.day > (now() at time zone 'UTC')::date - 37
    order by y.identity_id, y.day desc) x;
  select count(*) filter (where exists (select 1 from auth.mfa_factors f where f.user_id = i.auth_user_id and f.status = 'verified')
        or exists (select 1 from auth.webauthn_credentials w where w.user_id = i.auth_user_id)),
      count(*) filter (where exists (select 1 from auth.webauthn_credentials w where w.user_id = i.auth_user_id))
    into v_two_step, v_passkeys
    from public.tenant_memberships tm join public.identities i on i.id = tm.identity_id and i.kind = 'human'
    where tm.tenant_id = p_tenant_id and tm.status = 'active';
  select jsonb_build_object(
      'critical', count(*) filter (where a.severity = 'critical'), 'high', count(*) filter (where a.severity = 'high'),
      'medium', count(*) filter (where a.severity = 'medium'), 'low', count(*) filter (where a.severity = 'low'))
    into v_alerts from public.security_alerts a where a.tenant_id = p_tenant_id and a.status = 'open';
  select count(*) into v_alerts_new from public.security_alerts a where a.tenant_id = p_tenant_id and a.created_at > now() - interval '7 days';
  select count(distinct e.identity_id) filter (where e.includes_passwords and e.acknowledged_at is null),
      count(*) filter (where e.first_seen_at > now() - interval '7 days')
    into v_breach_members, v_breach_new from public.member_breach_exposures e where e.tenant_id = p_tenant_id;
  select count(*) filter (where t.status = 'pending'), count(*) filter (where t.status = 'pending' and c.due_at < now())
    into v_rotation_pending, v_rotation_overdue
    from public.rotation_tasks t join public.rotation_campaigns c on c.id = t.campaign_id and c.status = 'open'
    where t.tenant_id = p_tenant_id;
  select count(*) into v_unfamiliar from public.security_alerts a where a.tenant_id = p_tenant_id
    and a.kind in ('sign_in.unfamiliar','sign_in.new_country','sign_in.many_networks') and a.created_at > now() - interval '7 days';
  select count(*) into v_policies from public.organization_policies p where p.tenant_id = p_tenant_id and p.enforced and p.scope_type = 'tenant';

  -- Top risks, most serious first.
  if coalesce((v_alerts ->> 'critical')::integer, 0) > 0 then v_risks := v_risks || jsonb_build_object('key','critical_alerts','count',(v_alerts ->> 'critical')::integer); end if;
  if v_breached > 0 then v_risks := v_risks || jsonb_build_object('key','breached_passwords','count',v_breached); end if;
  if v_breach_members > 0 then v_risks := v_risks || jsonb_build_object('key','members_in_breaches','count',v_breach_members); end if;
  if v_exposed > 0 then v_risks := v_risks || jsonb_build_object('key','exposed_secrets','count',v_exposed); end if;
  if v_members - v_two_step > 0 then v_risks := v_risks || jsonb_build_object('key','members_without_two_step','count',v_members - v_two_step); end if;
  if v_reused > 0 then v_risks := v_risks || jsonb_build_object('key','reused_passwords','count',v_reused); end if;
  if coalesce((v_alerts ->> 'high')::integer, 0) > 0 then v_risks := v_risks || jsonb_build_object('key','high_alerts','count',(v_alerts ->> 'high')::integer); end if;
  if v_lookalikes > 0 then v_risks := v_risks || jsonb_build_object('key','lookalike_sites','count',v_lookalikes); end if;
  if v_weak > 0 then v_risks := v_risks || jsonb_build_object('key','weak_passwords','count',v_weak); end if;
  if v_rotation_overdue > 0 then v_risks := v_risks || jsonb_build_object('key','rotation_overdue','count',v_rotation_overdue); end if;
  if v_members - v_reporting > 0 then v_risks := v_risks || jsonb_build_object('key','members_not_reporting','count',v_members - v_reporting); end if;

  v := jsonb_build_object(
    'generated_at', now(), 'members', v_members, 'members_reporting', v_reporting,
    'score', v_score, 'score_week_ago', v_score_prev,
    'weak', v_weak, 'reused', v_reused, 'breached', v_breached, 'exposed_secrets', v_exposed, 'old', v_old,
    'lookalike_sites', v_lookalikes,
    'two_step_pct', case when v_members > 0 then round(100.0 * v_two_step / v_members) else 0 end,
    'passkey_pct', case when v_members > 0 then round(100.0 * v_passkeys / v_members) else 0 end,
    'alerts_open', v_alerts, 'alerts_new_7d', v_alerts_new,
    'members_in_breaches', v_breach_members, 'breach_exposures_new_7d', v_breach_new,
    'rotation_pending', v_rotation_pending, 'rotation_overdue', v_rotation_overdue,
    'unfamiliar_sign_ins_7d', v_unfamiliar, 'policies_enforced', v_policies,
    'top_risks', coalesce((select jsonb_agg(r) from (select r from jsonb_array_elements(v_risks) r limit 3) s), '[]'::jsonb),
    'all_risks', v_risks);
  return v;
end
$$;
revoke all on function private.build_security_report(uuid) from public, anon, authenticated;

create or replace function private.store_weekly_security_reports()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_tenant record; v_report jsonb; v_week date := date_trunc('week', now() at time zone 'UTC')::date; v_admin uuid; v_count integer := 0;
begin
  for v_tenant in select t.id from public.tenants t where t.kind = 'organization' loop
    continue when not private.has_business_entitlement(v_tenant.id);
    v_report := private.build_security_report(v_tenant.id);
    insert into public.weekly_security_reports (tenant_id, week_start, report) values (v_tenant.id, v_week, v_report)
    on conflict (tenant_id, week_start) do update set report = excluded.report, created_at = now();
    for v_admin in select * from private.security_contacts(v_tenant.id) loop
      continue when not coalesce((select p.weekly_report_email from public.account_notification_preferences p where p.identity_id = v_admin), true);
      perform private.enqueue_notification(v_tenant.id, v_admin, 'weekly_report', 'weekly_report',
        jsonb_build_object('week', v_week, 'score', v_report -> 'score', 'score_week_ago', v_report -> 'score_week_ago',
          'members', v_report -> 'members', 'alerts_new_7d', v_report -> 'alerts_new_7d', 'top_risks', v_report -> 'top_risks'),
        'weekly:' || v_tenant.id || ':' || v_week);
    end loop;
    v_count := v_count + 1;
  end loop;
  return v_count;
end
$$;
revoke all on function private.store_weekly_security_reports() from public, anon, authenticated;

create or replace function private.generate_security_report_now(p_tenant_id uuid)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare v_report jsonb; v_week date := date_trunc('week', now() at time zone 'UTC')::date;
begin
  if not private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin']) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  v_report := private.build_security_report(p_tenant_id);
  insert into public.weekly_security_reports (tenant_id, week_start, report) values (p_tenant_id, v_week, v_report)
  on conflict (tenant_id, week_start) do update set report = excluded.report;
  return v_report;
end
$$;

create or replace function private.save_security_report_summary(p_tenant_id uuid, p_week_start date, p_summary text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  -- Only owners/admins/security admins, and only right after their own completed AI summary request.
  if not private.can_manage_organization(p_tenant_id, array['organization_admin','security_admin'])
     or not exists (select 1 from public.ai_assistant_requests r
       where r.tenant_id = p_tenant_id and r.requested_by = private.current_identity_id()
         and r.use_case = 'weekly_summary' and r.status = 'completed' and r.completed_at > now() - interval '10 minutes') then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  if p_summary is null or char_length(btrim(p_summary)) not between 20 and 4000 then
    raise exception 'invalid summary' using errcode = '22023';
  end if;
  update public.weekly_security_reports set ai_summary = btrim(p_summary), ai_generated_at = now()
    where tenant_id = p_tenant_id and week_start = p_week_start;
end
$$;

-- ---------------------------------------------------------------------------
-- 9. AI context (counts only) and new AI use cases
-- ---------------------------------------------------------------------------
alter table public.ai_assistant_requests drop constraint if exists ai_assistant_requests_use_case_check;
alter table public.ai_assistant_requests add constraint ai_assistant_requests_use_case_check
  check (use_case in ('security_posture','access_review','spend_review','incident_summary','vault_health',
    'alert_triage','policy_advisor','weekly_summary'));

create or replace function private.ai_security_context(p_tenant_id uuid, p_use_case text)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare v_alerts jsonb; v_policies jsonb; v_report jsonb;
begin
  if not private.can_view_security_posture(p_tenant_id) then
    raise exception 'security posture access denied' using errcode = '42501';
  end if;
  select coalesce(jsonb_agg(g order by g.rank, g.count desc), '[]'::jsonb) into v_alerts from (
    select a.kind, a.severity, count(*)::integer as count,
      round(extract(epoch from now() - min(a.created_at)) / 3600)::integer as oldest_hours,
      round(extract(epoch from now() - max(a.created_at)) / 3600)::integer as newest_hours,
      count(distinct a.actor_identity_id)::integer as members_involved,
      case a.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end as rank
    from public.security_alerts a where a.tenant_id = p_tenant_id and a.status = 'open'
    group by a.kind, a.severity
    limit 40) g;
  if p_use_case = 'alert_triage' then
    return jsonb_build_object('open_alert_groups', v_alerts);
  end if;
  v_report := private.build_security_report(p_tenant_id);
  if p_use_case = 'weekly_summary' then
    return v_report - 'all_risks';
  end if;
  if p_use_case = 'policy_advisor' then
    select coalesce(jsonb_agg(jsonb_build_object('type', p.policy_type, 'configuration', p.configuration) order by p.policy_type), '[]'::jsonb)
      into v_policies from public.organization_policies p
      where p.tenant_id = p_tenant_id and p.enforced and p.scope_type = 'tenant';
    return jsonb_build_object('posture', v_report - 'all_risks' - 'top_risks', 'enforced_policies', v_policies,
      'open_alert_groups', v_alerts);
  end if;
  raise exception 'invalid AI request' using errcode = '22023';
end
$$;

create or replace function private.begin_ai_assistant_request(
  p_tenant_id uuid,p_use_case text,p_prompt_sha256 bytea,p_context_categories text[]
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_id uuid;
  v_recent integer;
  v_credits integer;
begin
  if v_actor is null then raise exception 'tenant access required' using errcode = '42501'; end if;
  if p_use_case = 'vault_health' then
    if not private.has_tenant_role(p_tenant_id,array['owner','admin','member','auditor']) then
      raise exception 'tenant access required' using errcode = '42501';
    end if;
    if octet_length(p_prompt_sha256) <> 32 or p_context_categories is distinct from array['vault_health_counts']::text[] then
      raise exception 'invalid AI request' using errcode = '22023';
    end if;
  elsif p_use_case in ('alert_triage','policy_advisor','weekly_summary') then
    if not private.can_view_security_posture(p_tenant_id) or not private.has_business_entitlement(p_tenant_id) then
      raise exception 'tenant access required' using errcode = '42501';
    end if;
    if octet_length(p_prompt_sha256) <> 32 or p_context_categories is distinct from array['security_counts']::text[] then
      raise exception 'invalid AI request' using errcode = '22023';
    end if;
  else
    if not private.can_view_runtime_tenant(p_tenant_id) or not private.has_business_entitlement(p_tenant_id) then
      raise exception 'tenant access required' using errcode = '42501';
    end if;
    if p_use_case not in ('security_posture','access_review','spend_review','incident_summary')
      or octet_length(p_prompt_sha256) <> 32
      or not (p_context_categories <@ array['tenant_counts','security_counts','spend_totals','access_risk_counts']::text[]) then
      raise exception 'invalid AI request' using errcode = '22023';
    end if;
  end if;
  select count(*) into v_recent from public.ai_assistant_requests request
    where request.requested_by = v_actor and request.created_at >= now() - interval '1 hour';
  if v_recent >= 20 then raise exception 'AI request limit reached' using errcode = '54000'; end if;

  select entitlement.ai_credits_remaining into v_credits
    from public.tenant_entitlements entitlement
    where entitlement.tenant_id = p_tenant_id for update;
  if not found or v_credits < 1 then
    raise exception 'AI credit limit reached' using errcode = '54000';
  end if;

  insert into public.ai_assistant_requests(
    tenant_id,requested_by,use_case,prompt_sha256,context_categories
  ) values (p_tenant_id,v_actor,p_use_case,p_prompt_sha256,p_context_categories)
  returning id into v_id;
  update public.tenant_entitlements
    set ai_credits_remaining = ai_credits_remaining - 1,updated_at = now()
    where tenant_id = p_tenant_id;
  return v_id;
end
$$;

-- ---------------------------------------------------------------------------
-- Public API (security invoker wrappers) and grants
-- ---------------------------------------------------------------------------
create or replace function public.set_my_notification_preferences(p_new_sign_in boolean, p_breach boolean, p_weekly_report boolean)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_my_notification_preferences(p_new_sign_in, p_breach, p_weekly_report) $$;
create or replace function public.my_sessions()
returns table (session_id uuid, created_at timestamptz, last_active_at timestamptz, device_label text,
  network_label text, country text, two_step boolean, is_current boolean)
language sql stable security invoker set search_path = ''
as $$ select * from private.my_sessions() $$;
create or replace function public.revoke_my_session(p_session_id uuid)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.revoke_my_session(p_session_id) $$;
create or replace function public.attest_sign_in_country(p_country text, p_issued_at bigint, p_signature text)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.attest_sign_in_country(p_country, p_issued_at, p_signature) $$;
create or replace function public.report_security_health_v2(p_tenant_id uuid, p_metrics jsonb, p_client_kind text default 'web')
returns void language sql volatile security invoker set search_path = ''
as $$ select private.report_security_health_v2(p_tenant_id, p_metrics, p_client_kind) $$;
create or replace function public.organization_health_trend(p_tenant_id uuid, p_days integer default 30)
returns table (day date, average_score integer, members_reporting integer, weak integer, reused integer, breached integer, exposed_secrets integer)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_health_trend(p_tenant_id, p_days) $$;
create or replace function public.organization_health_by_team(p_tenant_id uuid)
returns table (department_id uuid, department_name text, members integer, members_reporting integer,
  average_score integer, weak integer, reused integer, breached integer, exposed_secrets integer)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_health_by_team(p_tenant_id) $$;
create or replace function public.set_breach_watch(p_tenant_id uuid, p_enabled boolean)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_breach_watch(p_tenant_id, p_enabled) $$;
create or replace function public.organization_breach_watch(p_tenant_id uuid)
returns table (identity_id uuid, email text, display_name text, exposures integer, password_exposures integer,
  unacknowledged integer, latest_breach_date date, last_checked_at timestamptz)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_breach_watch(p_tenant_id) $$;
create or replace function public.acknowledge_breach_exposure(p_tenant_id uuid, p_identity_id uuid, p_breach_name text)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.acknowledge_breach_exposure(p_tenant_id, p_identity_id, p_breach_name) $$;
create or replace function public.organization_passkey_adoption(p_tenant_id uuid)
returns table (identity_id uuid, email text, display_name text, account_passkeys integer, two_step_methods integer,
  vault_passkeys integer, passkey_ready_sites integer, last_nudged_at timestamptz)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_passkey_adoption(p_tenant_id) $$;
create or replace function public.send_passkey_nudges(p_tenant_id uuid, p_identity_ids uuid[])
returns integer language sql volatile security invoker set search_path = ''
as $$ select private.send_passkey_nudges(p_tenant_id, p_identity_ids) $$;
create or replace function public.create_rotation_campaign(p_tenant_id uuid, p_title text, p_reason text, p_due_at timestamptz, p_tasks jsonb)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_rotation_campaign(p_tenant_id, p_title, p_reason, p_due_at, p_tasks) $$;
create or replace function public.update_rotation_task(p_task_id uuid, p_status text, p_note text default null)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.update_rotation_task(p_task_id, p_status, p_note) $$;
create or replace function public.close_rotation_campaign(p_campaign_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.close_rotation_campaign(p_campaign_id) $$;
create or replace function public.rotation_campaign_summary(p_tenant_id uuid)
returns table (id uuid, title text, reason text, due_at timestamptz, status text, created_at timestamptz,
  total integer, done integer, skipped integer, pending integer, cancelled integer, overdue boolean)
language sql stable security invoker set search_path = ''
as $$ select * from private.rotation_campaign_summary(p_tenant_id) $$;
create or replace function public.generate_security_report_now(p_tenant_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.generate_security_report_now(p_tenant_id) $$;
create or replace function public.save_security_report_summary(p_tenant_id uuid, p_week_start date, p_summary text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.save_security_report_summary(p_tenant_id, p_week_start, p_summary) $$;
create or replace function public.ai_security_context(p_tenant_id uuid, p_use_case text)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select private.ai_security_context(p_tenant_id, p_use_case) $$;

-- Worker endpoints (service role only).
create or replace function public.claim_notification_batch(p_token text, p_limit integer default 50)
returns table (id bigint, tenant_id uuid, recipient_identity_id uuid, email text, event_type text, template text, params jsonb, attempts smallint)
language sql volatile security invoker set search_path = ''
as $$ select * from private.claim_notification_batch(p_token, p_limit) $$;
create or replace function public.complete_notification(p_id bigint, p_status text, p_error text default null)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.complete_notification(p_id, p_status, p_error) $$;
create or replace function public.claim_breach_watch_batch(p_token text, p_limit integer default 8)
returns table (tenant_id uuid, identity_id uuid, email text)
language sql volatile security invoker set search_path = ''
as $$ select * from private.claim_breach_watch_batch(p_token, p_limit) $$;
create or replace function public.record_breach_watch_result(p_tenant_id uuid, p_identity_id uuid, p_status text, p_breaches jsonb)
returns integer language sql volatile security invoker set search_path = ''
as $$ select private.record_breach_watch_result(p_tenant_id, p_identity_id, p_status, p_breaches) $$;

do $$
declare v_sig text;
begin
  foreach v_sig in array array[
    'set_my_notification_preferences(boolean,boolean,boolean)',
    'my_sessions()',
    'revoke_my_session(uuid)',
    'attest_sign_in_country(text,bigint,text)',
    'report_security_health_v2(uuid,jsonb,text)',
    'organization_health_trend(uuid,integer)',
    'organization_health_by_team(uuid)',
    'set_breach_watch(uuid,boolean)',
    'organization_breach_watch(uuid)',
    'acknowledge_breach_exposure(uuid,uuid,text)',
    'organization_passkey_adoption(uuid)',
    'send_passkey_nudges(uuid,uuid[])',
    'create_rotation_campaign(uuid,text,text,timestamptz,jsonb)',
    'update_rotation_task(uuid,text,text)',
    'close_rotation_campaign(uuid)',
    'rotation_campaign_summary(uuid)',
    'generate_security_report_now(uuid)',
    'save_security_report_summary(uuid,date,text)',
    'ai_security_context(uuid,text)'
  ] loop
    execute format('revoke all on function private.%s from public, anon', v_sig);
    execute format('grant execute on function private.%s to authenticated', v_sig);
    execute format('revoke all on function public.%s from public, anon', v_sig);
    execute format('grant execute on function public.%s to authenticated', v_sig);
  end loop;
  foreach v_sig in array array[
    'claim_notification_batch(text,integer)',
    'complete_notification(bigint,text,text)',
    'claim_breach_watch_batch(text,integer)',
    'record_breach_watch_result(uuid,uuid,text,jsonb)'
  ] loop
    execute format('revoke all on function public.%s from public, anon, authenticated', v_sig);
    execute format('grant execute on function public.%s to service_role', v_sig);
  end loop;
end
$$;
revoke all on function private.can_view_security_posture(uuid) from public, anon;
grant execute on function private.can_view_security_posture(uuid) to authenticated;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('px-notify-dispatch', '* * * * *', $cron$select private.kick_notification_dispatch()$cron$);
    perform cron.schedule('px-breach-watch', '*/10 * * * *', $cron$select private.kick_breach_watch()$cron$);
    perform cron.schedule('px-weekly-security-reports', '15 6 * * 1', $cron$select private.store_weekly_security_reports()$cron$);
    perform cron.schedule('px-rotation-overdue', '30 6 * * *', $cron$select private.check_rotation_overdue()$cron$);
  end if;
end
$$;

comment on table public.account_sign_ins is 'Sign-in history: coarse device label and network prefix only (never the full IP).';
comment on table public.member_breach_exposures is 'Organization breach watch results from Have I Been Pwned (breach metadata only).';
comment on table public.rotation_tasks is 'Password rotation tasks. Item ids only; titles stay encrypted in the vault.';
comment on table public.weekly_security_reports is 'Weekly aggregate security posture per organization (counts only).';

commit;
