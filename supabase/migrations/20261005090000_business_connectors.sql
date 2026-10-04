-- Passkey-X business connectors and migration.
--
--  1. Outbound relay: every customer-facing HTTP delivery (audit streaming, chat alerts) is
--     queued with its format and credential and delivered by the SSRF-safe audit-relay edge
--     function, which also shapes vendor payloads.
--  2. Native SIEM destinations for audit streaming: Splunk HEC, Datadog Logs, Microsoft
--     Sentinel (Logs Ingestion API) and Elastic, next to the signed generic webhook.
--     Destination credentials are write-only.
--  3. Slack and Microsoft Teams alerts: security alerts, breach watch, rotation and the weekly
--     report posted to channels through incoming webhooks (webhook URLs are write-only).
--  4. Organization API keys (scoped, hashed, expiring, rate limited) for the org-api edge
--     function: audit events, alerts, members, security summary and weekly reports.
--  5. Member sharing keys and sealed workspace key grants: an administrator's device can give a
--     member a workspace key without links, encrypted to the member's public key (P-256 ECDH).
--     The server stores public keys and ciphertext only.
--  6. SCIM groups mapped to workspaces: group membership adds and removes workspace access;
--     keys are delivered by the grants above.
--  7. Organization workspaces created by administrators (team migration).
--  8. Self-serve SAML activation state for SSO connections.
--
-- Zero knowledge is unchanged: no vault content, workspace key or private key reaches the server.

begin;

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------
insert into private.app_settings (key, value) values ('app_url', 'https://passkey-x.com')
on conflict (key) do nothing;

-- Owners, admins and organization/security admins of a Business organization.
create or replace function private.require_business_admin(p_tenant_id uuid)
returns uuid language plpgsql stable security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not private.can_admin_workspace_access(p_tenant_id) then
    raise exception 'organization administrator role required' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = p_tenant_id) is distinct from 'organization' then
    raise exception 'this feature requires an organization' using errcode = '22023';
  end if;
  if not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement required' using errcode = '42501';
  end if;
  return v_actor;
end
$$;
revoke all on function private.require_business_admin(uuid) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 1. Outbound relay with formats
-- ---------------------------------------------------------------------------
alter table private.audit_webhook_outbox add column if not exists format text not null default 'raw';
alter table private.audit_webhook_outbox add column if not exists config jsonb not null default '{}';
alter table private.audit_webhook_outbox add column if not exists credential text;

-- Queues one delivery and wakes the relay. Returns the pg_net request id of the relay call,
-- whose status is the destination's status (or 421 when the destination is not allowed).
create or replace function private.relay_post(p_owner uuid, p_url text, p_headers jsonb, p_body text,
  p_format text default 'raw', p_config jsonb default '{}', p_credential text default null)
returns bigint language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_token text := encode(extensions.gen_random_bytes(32), 'hex');
  v_relay text := (select s.value from private.app_settings s where s.key = 'audit_relay_url');
  v_outbox bigint;
begin
  if v_relay is null then raise exception 'audit relay is not configured' using errcode = 'P0001'; end if;
  insert into private.audit_webhook_outbox (webhook_id, token_hash, url, headers, body, format, config, credential)
  values (p_owner, extensions.digest(v_token, 'sha256'), p_url, coalesce(p_headers, '{}'::jsonb), p_body,
    coalesce(p_format, 'raw'), coalesce(p_config, '{}'::jsonb), p_credential)
  returning id into v_outbox;
  return net.http_post(
    url := v_relay,
    body := jsonb_build_object('id', v_outbox, 'token', v_token),
    headers := jsonb_build_object('Content-Type', 'application/json'),
    timeout_milliseconds := 15000);
end
$$;
revoke all on function private.relay_post(uuid,text,jsonb,text,text,jsonb,text) from public, anon, authenticated;

-- The relay now also receives the format, its non-secret settings and the credential.
drop function if exists public.claim_audit_webhook_delivery(bigint, text);
drop function if exists private.claim_audit_webhook_delivery(bigint, text);
create function private.claim_audit_webhook_delivery(p_id bigint, p_token text)
returns table (url text, headers jsonb, body text, format text, config jsonb, credential text)
language sql volatile security definer set search_path = ''
as $$
  delete from private.audit_webhook_outbox o
  where o.id = p_id and o.token_hash = extensions.digest(p_token, 'sha256')
    and o.created_at > now() - interval '10 minutes'
  returning o.url, o.headers, o.body, o.format, o.config, o.credential
$$;
revoke all on function private.claim_audit_webhook_delivery(bigint, text) from public, anon, authenticated;
grant execute on function private.claim_audit_webhook_delivery(bigint, text) to service_role;
create function public.claim_audit_webhook_delivery(p_id bigint, p_token text)
returns table (url text, headers jsonb, body text, format text, config jsonb, credential text)
language sql volatile security invoker set search_path = ''
as $$ select * from private.claim_audit_webhook_delivery(p_id, p_token) $$;
revoke all on function public.claim_audit_webhook_delivery(bigint, text) from public, anon, authenticated;
grant execute on function public.claim_audit_webhook_delivery(bigint, text) to service_role;

-- ---------------------------------------------------------------------------
-- 2. Native SIEM destinations
-- ---------------------------------------------------------------------------
alter table public.audit_webhooks add column if not exists format text not null default 'generic';
alter table public.audit_webhooks drop constraint if exists audit_webhooks_format_check;
alter table public.audit_webhooks add constraint audit_webhooks_format_check
  check (format in ('generic','splunk_hec','datadog','sentinel','elastic'));
alter table public.audit_webhooks add column if not exists destination jsonb not null default '{}';
grant select (format, destination) on public.audit_webhooks to authenticated;

create table if not exists private.audit_webhook_credentials (
  webhook_id uuid primary key references public.audit_webhooks(id) on delete cascade,
  credential text not null check (char_length(credential) between 8 and 400),
  updated_at timestamptz not null default now()
);
revoke all on private.audit_webhook_credentials from public, anon, authenticated;

create or replace function private.datadog_sites()
returns text[] language sql immutable set search_path = ''
as $$ select array['datadoghq.com','us3.datadoghq.com','us5.datadoghq.com','datadoghq.eu','ap1.datadoghq.com','ap2.datadoghq.com','ddog-gov.com'] $$;

-- Validates a destination and returns {url, destination} for the stored row.
create or replace function private.normalize_siem_destination(p_format text, p_url text, p_destination jsonb, p_credential text)
returns jsonb language plpgsql immutable set search_path = ''
as $$
declare
  d jsonb := coalesce(p_destination, '{}'::jsonb);
  v_url text;
  v_dest jsonb;
begin
  if p_format = 'generic' then
    if not private.valid_webhook_url(p_url) then raise exception 'webhook url must be a public https address' using errcode = '22023'; end if;
    return jsonb_build_object('url', p_url, 'destination', '{}'::jsonb);
  end if;
  if p_credential is null or char_length(btrim(p_credential)) < 8 or char_length(p_credential) > 400 or p_credential ~ '[[:space:]]' then
    raise exception 'a valid destination credential is required' using errcode = '22023';
  end if;
  if p_format = 'splunk_hec' then
    if not private.valid_webhook_url(p_url) then raise exception 'Splunk HEC url must be a public https address' using errcode = '22023'; end if;
    if coalesce(d ->> 'index', '') !~ '^([A-Za-z0-9_-]{1,80})?$' or coalesce(d ->> 'sourcetype', '') !~ '^([A-Za-z0-9_:.-]{1,80})?$' then
      raise exception 'invalid Splunk index or sourcetype' using errcode = '22023';
    end if;
    v_url := regexp_replace(p_url, '/+$', '');
    if v_url !~ '/services/collector(/event)?$' then v_url := v_url || '/services/collector/event'; end if;
    v_dest := jsonb_strip_nulls(jsonb_build_object('index', nullif(d ->> 'index', ''), 'sourcetype', coalesce(nullif(d ->> 'sourcetype', ''), 'passkeyx:audit')));
  elsif p_format = 'datadog' then
    if not (coalesce(d ->> 'site', '') = any(private.datadog_sites())) then raise exception 'unknown Datadog site' using errcode = '22023'; end if;
    if coalesce(d ->> 'service', '') !~ '^([a-z0-9_.-]{1,60})?$' or coalesce(d ->> 'tags', '') !~ '^([A-Za-z0-9_.:/,-]{1,200})?$' then
      raise exception 'invalid Datadog service or tags' using errcode = '22023';
    end if;
    v_url := 'https://http-intake.logs.' || (d ->> 'site') || '/api/v2/logs';
    v_dest := jsonb_strip_nulls(jsonb_build_object('site', d ->> 'site', 'service', coalesce(nullif(d ->> 'service', ''), 'passkey-x'), 'tags', nullif(d ->> 'tags', '')));
  elsif p_format = 'sentinel' then
    if coalesce(d ->> 'tenant_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or coalesce(d ->> 'client_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      raise exception 'Sentinel needs the Entra tenant ID and application (client) ID' using errcode = '22023';
    end if;
    if coalesce(d ->> 'endpoint', '') !~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)*\.ingest\.monitor\.azure\.(com|us|cn)$' then
      raise exception 'Sentinel endpoint must be a data collection endpoint (https://….ingest.monitor.azure.com)' using errcode = '22023';
    end if;
    if coalesce(d ->> 'dcr_id', '') !~ '^dcr-[0-9a-f]{32}$' or coalesce(d ->> 'stream', '') !~ '^Custom-[A-Za-z0-9_]{1,60}$' then
      raise exception 'invalid data collection rule ID or stream name' using errcode = '22023';
    end if;
    v_url := (d ->> 'endpoint') || '/dataCollectionRules/' || (d ->> 'dcr_id') || '/streams/' || (d ->> 'stream') || '?api-version=2023-01-01';
    v_dest := jsonb_build_object('tenant_id', lower(d ->> 'tenant_id'), 'client_id', lower(d ->> 'client_id'),
      'endpoint', d ->> 'endpoint', 'dcr_id', d ->> 'dcr_id', 'stream', d ->> 'stream');
  elsif p_format = 'elastic' then
    if not private.valid_webhook_url(p_url) then raise exception 'Elasticsearch url must be a public https address' using errcode = '22023'; end if;
    if coalesce(d ->> 'index', 'passkey-x-audit') !~ '^[a-z0-9][a-z0-9._-]{0,99}$' then raise exception 'invalid Elasticsearch index' using errcode = '22023'; end if;
    v_url := regexp_replace(p_url, '/+$', '') || '/_bulk';
    v_dest := jsonb_build_object('index', coalesce(nullif(d ->> 'index', ''), 'passkey-x-audit'));
  else
    raise exception 'unsupported destination format' using errcode = '22023';
  end if;
  return jsonb_build_object('url', v_url, 'destination', v_dest);
end
$$;
revoke all on function private.normalize_siem_destination(text,text,jsonb,text) from public, anon, authenticated;

create or replace function private.create_audit_destination(p_tenant_id uuid, p_name text, p_format text, p_url text,
  p_destination jsonb, p_credential text, p_event_prefixes text[])
returns table (id uuid, secret text)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_secret text := 'pxwh_' || encode(extensions.gen_random_bytes(32), 'hex');
  v_id uuid;
  v_prefixes text[] := coalesce(p_event_prefixes, '{}');
  v_normal jsonb;
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then
    raise exception 'audit streaming management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = p_tenant_id) is distinct from 'organization' then
    raise exception 'audit streaming requires an organization' using errcode = '22023';
  end if;
  if not private.has_business_entitlement(p_tenant_id) then
    raise exception 'business organization entitlement required' using errcode = '42501';
  end if;
  if char_length(btrim(coalesce(p_name, ''))) not between 2 and 80 then raise exception 'name must be 2 to 80 characters' using errcode = '22023'; end if;
  if exists (select 1 from unnest(v_prefixes) prefix where prefix !~ '^[a-z_]{1,40}\.?[a-z_]{0,40}$') or cardinality(v_prefixes) > 20 then
    raise exception 'invalid event filter' using errcode = '22023';
  end if;
  if (select count(*) from public.audit_webhooks w where w.tenant_id = p_tenant_id) >= 5 then
    raise exception 'an organization can have at most 5 audit webhooks' using errcode = 'P0001';
  end if;
  v_normal := private.normalize_siem_destination(p_format, p_url, p_destination, p_credential);
  insert into public.audit_webhooks (tenant_id, name, url, secret, event_prefixes, created_by, delivered_through, format, destination)
  values (p_tenant_id, btrim(p_name), v_normal ->> 'url', v_secret, v_prefixes, private.current_identity_id(),
    coalesce((select max(e.sequence) from public.audit_events e where e.tenant_id = p_tenant_id), 0),
    p_format, v_normal -> 'destination')
  returning audit_webhooks.id into v_id;
  if p_format <> 'generic' then
    insert into private.audit_webhook_credentials (webhook_id, credential) values (v_id, btrim(p_credential));
  end if;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'audit_webhook.created', 'audit_webhooks', v_id,
    jsonb_build_object('name', btrim(p_name), 'format', p_format, 'host', substring(v_normal ->> 'url' from '^https://([^/:]+)')));
  return query select v_id, case when p_format = 'generic' then v_secret else null end;
end
$$;

create or replace function private.set_audit_destination_credential(p_id uuid, p_credential text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_hook public.audit_webhooks%rowtype;
begin
  select * into v_hook from public.audit_webhooks w where w.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_hook.tenant_id) then
    raise exception 'audit webhook not found' using errcode = '42501';
  end if;
  if v_hook.format = 'generic' then raise exception 'generic webhooks use a signing secret; rotate it instead' using errcode = '22023'; end if;
  perform private.normalize_siem_destination(v_hook.format, v_hook.url, v_hook.destination, p_credential);
  insert into private.audit_webhook_credentials (webhook_id, credential) values (p_id, btrim(p_credential))
    on conflict (webhook_id) do update set credential = excluded.credential, updated_at = now();
  update public.audit_webhooks set failure_count = 0 where id = p_id;
  perform private.append_audit_event(v_hook.tenant_id, private.current_identity_id(), 'audit_webhook.credential_replaced', 'audit_webhooks', p_id, '{}'::jsonb);
end
$$;

-- Generic webhooks are signed here; vendor formats are shaped and authenticated by the relay.
create or replace function private.post_audit_webhook(p_hook public.audit_webhooks, p_payload jsonb)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_ts text := extract(epoch from now())::bigint::text;
  v_body text := p_payload::text;
  v_credential text;
begin
  if coalesce(p_hook.format, 'generic') = 'generic' then
    return private.relay_post(p_hook.id, p_hook.url, jsonb_build_object(
        'Content-Type', 'application/json',
        'User-Agent', 'Passkey-X-Webhooks/1',
        'X-PasskeyX-Webhook', p_hook.id::text,
        'X-PasskeyX-Timestamp', v_ts,
        'X-PasskeyX-Signature', 'v1=' || encode(extensions.hmac(v_ts || '.' || v_body, p_hook.secret, 'sha256'), 'hex')),
      v_body, 'raw', '{}'::jsonb, null);
  end if;
  select c.credential into v_credential from private.audit_webhook_credentials c where c.webhook_id = p_hook.id;
  return private.relay_post(p_hook.id, p_hook.url, jsonb_build_object('User-Agent', 'Passkey-X-Webhooks/1'),
    v_body, p_hook.format, p_hook.destination, v_credential);
end
$$;
revoke all on function private.post_audit_webhook(public.audit_webhooks, jsonb) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 3. Slack and Microsoft Teams alerts
-- ---------------------------------------------------------------------------
create table if not exists public.chat_channels (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  kind text not null check (kind in ('slack','teams')),
  name text not null check (char_length(name) between 2 and 80),
  url_host text not null,
  events text[] not null default array['alerts','breach_watch','rotation','weekly_report']
    check (cardinality(events) between 1 and 4 and events <@ array['alerts','breach_watch','rotation','weekly_report']),
  min_severity text not null default 'high' check (min_severity in ('critical','high','medium','low')),
  enabled boolean not null default true,
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  failure_count integer not null default 0,
  last_status integer,
  last_error text,
  last_attempt_at timestamptz,
  last_success_at timestamptz
);
create index if not exists chat_channels_tenant_idx on public.chat_channels (tenant_id);
alter table public.chat_channels enable row level security;
revoke all on public.chat_channels from anon, authenticated;
grant select on public.chat_channels to authenticated;
drop policy if exists chat_channels_read on public.chat_channels;
create policy chat_channels_read on public.chat_channels for select to authenticated
  using ((select private.can_manage_audit_webhooks(tenant_id)));

create table if not exists private.chat_channel_secrets (
  channel_id uuid primary key references public.chat_channels(id) on delete cascade,
  webhook_url text not null
);
revoke all on private.chat_channel_secrets from public, anon, authenticated;

create table if not exists private.chat_queue (
  id bigint generated always as identity primary key,
  channel_id uuid not null references public.chat_channels(id) on delete cascade,
  event text not null,
  payload jsonb not null,
  attempts integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  request_id bigint,
  sent_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists chat_queue_due_idx on private.chat_queue (next_attempt_at) where request_id is null;
revoke all on private.chat_queue from public, anon, authenticated;

-- Slack incoming webhooks / workflow triggers; Teams Workflows (Power Automate) webhooks and
-- legacy Office 365 connectors. Nothing else, so a channel cannot be pointed at other hosts.
create or replace function private.valid_chat_webhook(p_kind text, p_url text)
returns boolean language sql immutable set search_path = ''
as $$
  select p_url is not null and char_length(p_url) <= 700 and p_url !~ '[[:space:]]' and case p_kind
    when 'slack' then p_url ~ '^https://hooks\.slack\.com/(services|triggers|workflows)/[A-Za-z0-9/_-]{10,}$'
    when 'teams' then p_url ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)*\.(logic\.azure\.com|webhook\.office\.com|powerplatform\.com|powerautomate\.com)(:443)?/[A-Za-z0-9/_.%?&=:-]{10,}$'
    else false end
$$;

create or replace function private.create_chat_channel(p_tenant_id uuid, p_kind text, p_name text, p_url text,
  p_events text[], p_min_severity text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.require_business_admin(p_tenant_id); v_id uuid;
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then raise exception 'channel management denied' using errcode = '42501'; end if;
  if not private.valid_chat_webhook(p_kind, p_url) then
    raise exception 'paste the incoming webhook URL from Slack or the Teams Workflows app' using errcode = '22023';
  end if;
  if (select count(*) from public.chat_channels c where c.tenant_id = p_tenant_id) >= 10 then
    raise exception 'an organization can have at most 10 chat channels' using errcode = 'P0001';
  end if;
  insert into public.chat_channels (tenant_id, kind, name, url_host, events, min_severity, created_by)
  values (p_tenant_id, p_kind, btrim(p_name), substring(p_url from '^https://([^/:]+)'),
    coalesce(p_events, array['alerts','breach_watch','rotation','weekly_report']), coalesce(p_min_severity, 'high'), v_actor)
  returning id into v_id;
  insert into private.chat_channel_secrets (channel_id, webhook_url) values (v_id, p_url);
  perform private.append_audit_event(p_tenant_id, v_actor, 'chat_channel.created', 'chat_channels', v_id,
    jsonb_build_object('kind', p_kind, 'name', btrim(p_name)));
  return v_id;
end
$$;

create or replace function private.update_chat_channel(p_id uuid, p_name text, p_events text[], p_min_severity text,
  p_enabled boolean, p_url text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.chat_channels%rowtype; v_actor uuid;
begin
  select * into v_row from public.chat_channels c where c.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_row.tenant_id) then raise exception 'channel not found' using errcode = '42501'; end if;
  v_actor := private.require_business_admin(v_row.tenant_id);
  if p_url is not null then
    if not private.valid_chat_webhook(v_row.kind, p_url) then raise exception 'invalid webhook url' using errcode = '22023'; end if;
    update private.chat_channel_secrets set webhook_url = p_url where channel_id = p_id;
  end if;
  update public.chat_channels set
    name = coalesce(nullif(btrim(coalesce(p_name, '')), ''), name),
    events = coalesce(p_events, events),
    min_severity = coalesce(p_min_severity, min_severity),
    enabled = coalesce(p_enabled, enabled),
    url_host = case when p_url is null then url_host else substring(p_url from '^https://([^/:]+)') end,
    failure_count = case when p_enabled or p_url is not null then 0 else failure_count end
    where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, v_actor, 'chat_channel.updated', 'chat_channels', p_id,
    jsonb_build_object('enabled', coalesce(p_enabled, v_row.enabled), 'url_replaced', p_url is not null));
end
$$;

create or replace function private.delete_chat_channel(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.chat_channels%rowtype;
begin
  select * into v_row from public.chat_channels c where c.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_row.tenant_id) then raise exception 'channel not found' using errcode = '42501'; end if;
  delete from public.chat_channels where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, private.current_identity_id(), 'chat_channel.deleted', 'chat_channels', p_id,
    jsonb_build_object('name', v_row.name));
end
$$;

create or replace function private.severity_rank(p_severity text)
returns integer language sql immutable set search_path = ''
as $$ select case p_severity when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end $$;

-- Queues a message for every enabled channel of the organization that subscribed to the event.
create or replace function private.enqueue_chat(p_tenant_id uuid, p_event text, p_severity text, p_payload jsonb)
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_count integer;
begin
  insert into private.chat_queue (channel_id, event, payload)
  select c.id, p_event, p_payload from public.chat_channels c
  where c.tenant_id = p_tenant_id and c.enabled and p_event = any(c.events)
    and (p_severity is null or private.severity_rank(p_severity) >= private.severity_rank(c.min_severity));
  get diagnostics v_count = row_count;
  return v_count;
end
$$;

create or replace function private.test_chat_channel(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.chat_channels%rowtype;
begin
  select * into v_row from public.chat_channels c where c.id = p_id;
  if not found or not private.can_manage_audit_webhooks(v_row.tenant_id) then raise exception 'channel not found' using errcode = '42501'; end if;
  if exists (select 1 from private.chat_queue q where q.channel_id = p_id and q.event = 'test' and q.created_at > now() - interval '15 seconds') then
    raise exception 'wait a few seconds before sending another test' using errcode = 'P0001';
  end if;
  insert into private.chat_queue (channel_id, event, payload)
  values (p_id, 'test', jsonb_build_object('title', 'Passkey-X is connected', 'channel', v_row.name));
end
$$;

create or replace function private.chat_on_alert()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform private.enqueue_chat(new.tenant_id,
    case when new.kind like 'member.breach%' then 'breach_watch' when new.kind like 'rotation.%' then 'rotation' else 'alerts' end,
    new.severity,
    jsonb_build_object('title', new.title, 'severity', new.severity, 'kind', new.kind, 'alert_id', new.id, 'created_at', new.created_at));
  return new;
exception when others then
  return new; -- a chat problem must never block an alert
end
$$;
drop trigger if exists security_alerts_chat on public.security_alerts;
create trigger security_alerts_chat after insert on public.security_alerts
  for each row execute function private.chat_on_alert();

create or replace function private.chat_on_weekly_report()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  perform private.enqueue_chat(new.tenant_id, 'weekly_report', null, jsonb_build_object(
    'week_start', new.week_start, 'score', new.report -> 'score', 'score_week_ago', new.report -> 'score_week_ago',
    'members', new.report -> 'members', 'two_step_pct', new.report -> 'two_step_pct', 'passkey_pct', new.report -> 'passkey_pct',
    'alerts_new_7d', new.report -> 'alerts_new_7d', 'top_risks', new.report -> 'top_risks'));
  return new;
exception when others then
  return new;
end
$$;
drop trigger if exists weekly_security_reports_chat on public.weekly_security_reports;
create trigger weekly_security_reports_chat after insert on public.weekly_security_reports
  for each row execute function private.chat_on_weekly_report();

-- Every minute: settle sent messages, then send due ones (at most 100 per run).
create or replace function private.deliver_chat_notifications()
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_row record;
  v_response record;
  v_sent integer := 0;
  v_app text := coalesce((select s.value from private.app_settings s where s.key = 'app_url'), 'https://passkey-x.com');
begin
  for v_row in select q.* from private.chat_queue q where q.request_id is not null for update skip locked loop
    select r.status_code, r.error_msg, r.timed_out into v_response from net._http_response r where r.id = v_row.request_id;
    continue when not found and v_row.sent_at > now() - interval '3 minutes';
    if found and v_response.status_code between 200 and 299 then
      delete from private.chat_queue where id = v_row.id;
      update public.chat_channels set failure_count = 0, last_status = v_response.status_code, last_error = null, last_success_at = now()
        where id = v_row.channel_id;
    else
      if v_row.attempts + 1 >= 5 or v_row.event = 'test' then
        delete from private.chat_queue where id = v_row.id;
        update public.chat_channels set failure_count = failure_count + 1, enabled = failure_count + 1 < 25,
          last_status = case when found then v_response.status_code else null end,
          last_error = left(case when not found then 'no response' when v_response.timed_out then 'timed out'
            when v_response.status_code = 421 then 'destination not allowed'
            else coalesce(v_response.error_msg, 'HTTP ' || v_response.status_code) end, 300)
          where id = v_row.channel_id;
      else
        update private.chat_queue set request_id = null, sent_at = null, attempts = attempts + 1,
          next_attempt_at = now() + interval '1 minute' * power(2, attempts + 1)
          where id = v_row.id;
      end if;
    end if;
  end loop;

  for v_row in
    select q.id, q.event, q.payload, c.id as channel_id, c.kind, c.name, c.tenant_id, s.webhook_url
    from private.chat_queue q
    join public.chat_channels c on c.id = q.channel_id and (c.enabled or q.event = 'test')
    join private.chat_channel_secrets s on s.channel_id = c.id
    where q.request_id is null and q.next_attempt_at <= now()
    order by q.id limit 100
    for update of q skip locked
  loop
    update private.chat_queue set request_id = private.relay_post(v_row.channel_id, v_row.webhook_url,
        jsonb_build_object('Content-Type', 'application/json', 'User-Agent', 'Passkey-X-Alerts/1'),
        (v_row.payload || jsonb_build_object('event', v_row.event, 'app_url', v_app))::text,
        v_row.kind, jsonb_build_object('channel', v_row.name), null),
      sent_at = now()
      where id = v_row.id;
    update public.chat_channels set last_attempt_at = now() where id = v_row.channel_id;
    v_sent := v_sent + 1;
  end loop;
  delete from private.chat_queue where created_at < now() - interval '2 days';
  return v_sent;
end
$$;
revoke all on function private.deliver_chat_notifications() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. Organization API keys
-- ---------------------------------------------------------------------------
create or replace function private.api_scopes()
returns text[] language sql immutable set search_path = ''
as $$ select array['audit:read','alerts:read','alerts:write','members:read','reports:read'] $$;

create table if not exists public.org_api_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 80),
  prefix text not null,
  scopes text[] not null check (cardinality(scopes) between 1 and 5),
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index if not exists org_api_keys_tenant_idx on public.org_api_keys (tenant_id);
alter table public.org_api_keys enable row level security;
revoke all on public.org_api_keys from anon, authenticated;
grant select on public.org_api_keys to authenticated;
drop policy if exists org_api_keys_read on public.org_api_keys;
create policy org_api_keys_read on public.org_api_keys for select to authenticated
  using ((select private.can_admin_workspace_access(tenant_id)));

create table if not exists private.org_api_key_hashes (
  key_id uuid primary key references public.org_api_keys(id) on delete cascade,
  token_hash bytea not null unique
);
revoke all on private.org_api_key_hashes from public, anon, authenticated;

create table if not exists private.org_api_usage (
  key_id uuid not null references public.org_api_keys(id) on delete cascade,
  window_start timestamptz not null,
  requests integer not null default 0,
  primary key (key_id, window_start)
);
revoke all on private.org_api_usage from public, anon, authenticated;

-- Returns the key once. Only a SHA-256 hash is stored.
create or replace function private.create_org_api_key(p_tenant_id uuid, p_name text, p_scopes text[], p_expires_in_days integer)
returns table (id uuid, token text)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.require_business_admin(p_tenant_id);
  v_secret text := encode(extensions.gen_random_bytes(32), 'hex');
  v_token text := 'pxk_' || v_secret;
  v_id uuid;
  v_days integer := coalesce(p_expires_in_days, 90);
  v_scopes text[] := (select array_agg(distinct s order by s) from unnest(coalesce(p_scopes, '{}')) s);
begin
  if v_scopes is null or not (v_scopes <@ private.api_scopes()) then raise exception 'unknown API scope' using errcode = '22023'; end if;
  if v_days not between 1 and 365 then raise exception 'keys expire after 1 to 365 days' using errcode = '22023'; end if;
  if char_length(btrim(coalesce(p_name, ''))) not between 2 and 80 then raise exception 'name must be 2 to 80 characters' using errcode = '22023'; end if;
  if (select count(*) from public.org_api_keys k where k.tenant_id = p_tenant_id and k.revoked_at is null and k.expires_at > now()) >= 20 then
    raise exception 'an organization can have at most 20 active API keys' using errcode = 'P0001';
  end if;
  insert into public.org_api_keys (tenant_id, name, prefix, scopes, created_by, expires_at)
  values (p_tenant_id, btrim(p_name), 'pxk_' || left(v_secret, 8), v_scopes, v_actor, now() + make_interval(days => v_days))
  returning org_api_keys.id into v_id;
  insert into private.org_api_key_hashes (key_id, token_hash) values (v_id, extensions.digest(v_token, 'sha256'));
  perform private.append_audit_event(p_tenant_id, v_actor, 'api_key.created', 'org_api_keys', v_id,
    jsonb_build_object('name', btrim(p_name), 'scopes', to_jsonb(v_scopes), 'expires_in_days', v_days));
  return query select v_id, v_token;
end
$$;

create or replace function private.revoke_org_api_key(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.org_api_keys%rowtype;
begin
  select * into v_row from public.org_api_keys k where k.id = p_id for update;
  if not found or not private.can_admin_workspace_access(v_row.tenant_id) then raise exception 'API key not found' using errcode = '42501'; end if;
  if v_row.revoked_at is not null then return; end if;
  update public.org_api_keys set revoked_at = now() where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, private.current_identity_id(), 'api_key.revoked', 'org_api_keys', p_id,
    jsonb_build_object('name', v_row.name));
end
$$;

-- Service role only (org-api edge function). Rate limit: 300 requests per key per minute.
create or replace function private.authenticate_org_api_key(p_token text)
returns table (key_id uuid, tenant_id uuid, scopes text[], rate_limited boolean)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_key public.org_api_keys%rowtype;
  v_window timestamptz := date_trunc('minute', now());
  v_count integer;
begin
  if p_token is null or p_token !~ '^pxk_[0-9a-f]{64}$' then return; end if;
  select k.* into v_key from private.org_api_key_hashes h join public.org_api_keys k on k.id = h.key_id
    where h.token_hash = extensions.digest(p_token, 'sha256');
  if not found or v_key.revoked_at is not null or v_key.expires_at <= now()
     or not private.has_business_entitlement(v_key.tenant_id) then
    return;
  end if;
  insert into private.org_api_usage (key_id, window_start, requests) values (v_key.id, v_window, 1)
    on conflict on constraint org_api_usage_pkey do update set requests = private.org_api_usage.requests + 1
    returning requests into v_count;
  if v_key.last_used_at is null or v_key.last_used_at < now() - interval '1 minute' then
    update public.org_api_keys set last_used_at = now() where id = v_key.id;
    delete from private.org_api_usage u where u.window_start < now() - interval '10 minutes';
  end if;
  return query select v_key.id, v_key.tenant_id, v_key.scopes, v_count > 300;
end
$$;

create or replace function private.api_key_tenant(p_key_id uuid, p_scope text)
returns uuid language plpgsql stable security definer set search_path = ''
as $$
declare v_key public.org_api_keys%rowtype;
begin
  select * into v_key from public.org_api_keys k where k.id = p_key_id;
  if not found or v_key.revoked_at is not null or v_key.expires_at <= now() or not (p_scope = any(v_key.scopes)) then
    raise exception 'API key lacks scope %', p_scope using errcode = '42501';
  end if;
  return v_key.tenant_id;
end
$$;

create or replace function private.api_audit_events(p_key_id uuid, p_after bigint, p_limit integer)
returns setof jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('sequence', e.sequence, 'occurred_at', e.occurred_at, 'action', e.action,
      'target_type', e.target_type, 'target_id', e.target_id, 'actor_identity_id', e.actor_identity_id,
      'metadata', e.metadata, 'event_hash', encode(e.event_hash, 'hex'))
  from public.audit_events e
  where e.tenant_id = private.api_key_tenant(p_key_id, 'audit:read') and e.sequence > coalesce(p_after, 0)
  order by e.sequence limit least(greatest(coalesce(p_limit, 100), 1), 500)
$$;

create or replace function private.api_alerts(p_key_id uuid, p_status text, p_limit integer)
returns setof jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('id', a.id, 'severity', a.severity, 'kind', a.kind, 'title', a.title, 'status', a.status,
      'created_at', a.created_at, 'acknowledged_at', a.acknowledged_at, 'actor_identity_id', a.actor_identity_id)
  from public.security_alerts a
  where a.tenant_id = private.api_key_tenant(p_key_id, 'alerts:read') and (p_status is null or a.status = p_status)
  order by a.created_at desc limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;

create or replace function private.api_update_alert(p_key_id uuid, p_alert_id uuid, p_status text, p_note text)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare v_tenant uuid := private.api_key_tenant(p_key_id, 'alerts:write'); v_row public.security_alerts%rowtype;
begin
  if p_status not in ('open','acknowledged','resolved') then raise exception 'invalid status' using errcode = '22023'; end if;
  update public.security_alerts set status = p_status,
      acknowledged_at = case when p_status = 'open' then null else coalesce(acknowledged_at, now()) end,
      note = coalesce(left(p_note, 500), note)
    where id = p_alert_id and tenant_id = v_tenant returning * into v_row;
  if not found then raise exception 'alert not found' using errcode = 'P0002'; end if;
  perform private.append_audit_event(v_tenant, null, 'security_alert.' || p_status, 'security_alerts', p_alert_id,
    jsonb_build_object('via', 'api', 'api_key_id', p_key_id));
  return jsonb_build_object('id', v_row.id, 'status', v_row.status);
end
$$;

create or replace function private.api_members(p_key_id uuid, p_offset integer, p_limit integer)
returns setof jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('identity_id', tm.identity_id, 'role', tm.role, 'status', tm.status,
      'display_name', op.display_name, 'job_title', op.job_title, 'email', u.email,
      'two_step', exists (select 1 from auth.mfa_factors f where f.user_id = i.auth_user_id and f.status = 'verified'),
      'passkey', exists (select 1 from auth.webauthn_credentials w where w.user_id = i.auth_user_id),
      'security_score', h.score, 'joined_at', tm.created_at)
  from public.tenant_memberships tm
  join public.identities i on i.id = tm.identity_id and i.kind = 'human'
  left join auth.users u on u.id = i.auth_user_id
  left join public.organization_profiles op on op.tenant_id = tm.tenant_id and op.identity_id = tm.identity_id
  left join public.security_health_reports h on h.tenant_id = tm.tenant_id and h.identity_id = tm.identity_id
  where tm.tenant_id = private.api_key_tenant(p_key_id, 'members:read')
  order by tm.created_at, tm.identity_id offset greatest(coalesce(p_offset, 0), 0) limit least(greatest(coalesce(p_limit, 100), 1), 500)
$$;

create or replace function private.api_security_summary(p_key_id uuid)
returns jsonb language sql stable security definer set search_path = ''
as $$ select private.build_security_report(private.api_key_tenant(p_key_id, 'reports:read')) $$;

create or replace function private.api_weekly_reports(p_key_id uuid, p_limit integer)
returns setof jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('week_start', r.week_start, 'report', r.report, 'ai_summary', r.ai_summary)
  from public.weekly_security_reports r
  where r.tenant_id = private.api_key_tenant(p_key_id, 'reports:read')
  order by r.week_start desc limit least(greatest(coalesce(p_limit, 4), 1), 52)
$$;

-- ---------------------------------------------------------------------------
-- 5. Member sharing keys and sealed workspace key grants
-- ---------------------------------------------------------------------------
-- Public half: readable by people who share an organization with the owner.
create table if not exists public.identity_sharing_keys (
  identity_id uuid primary key references public.identities(id) on delete cascade,
  public_key bytea not null check (octet_length(public_key) = 65 and get_byte(public_key, 0) = 4),
  fingerprint text not null check (fingerprint ~ '^[0-9a-f]{4}(:[0-9a-f]{4}){5}$'),
  created_at timestamptz not null default now()
);
-- Private half, encrypted under the owner's account root key: readable by the owner only.
create table if not exists public.identity_sharing_key_secrets (
  identity_id uuid primary key references public.identity_sharing_keys(identity_id) on delete cascade,
  nonce bytea not null check (octet_length(nonce) = 12),
  wrapped_private_key bytea not null check (octet_length(wrapped_private_key) between 64 and 512)
);
alter table public.identity_sharing_keys enable row level security;
alter table public.identity_sharing_key_secrets enable row level security;
revoke all on public.identity_sharing_keys, public.identity_sharing_key_secrets from anon, authenticated;
grant select on public.identity_sharing_keys, public.identity_sharing_key_secrets to authenticated;

create or replace function private.shares_tenant_with(p_identity uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select p_identity = private.current_identity_id() or exists (
    select 1 from public.tenant_memberships mine
    join public.tenant_memberships theirs on theirs.tenant_id = mine.tenant_id and theirs.identity_id = p_identity and theirs.status = 'active'
    where mine.identity_id = private.current_identity_id() and mine.status = 'active')
$$;
revoke all on function private.shares_tenant_with(uuid) from public, anon;
grant execute on function private.shares_tenant_with(uuid) to authenticated;

drop policy if exists identity_sharing_keys_read on public.identity_sharing_keys;
create policy identity_sharing_keys_read on public.identity_sharing_keys for select to authenticated
  using ((select private.shares_tenant_with(identity_id)));
drop policy if exists identity_sharing_key_secrets_read on public.identity_sharing_key_secrets;
create policy identity_sharing_key_secrets_read on public.identity_sharing_key_secrets for select to authenticated
  using (identity_id = (select private.current_identity_id()));

-- Publishing a new key (p_replace) invalidates grants sealed to the old one.
create or replace function private.publish_sharing_key(p_public_key bytea, p_fingerprint text, p_nonce bytea, p_wrapped_private_key bytea, p_replace boolean)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null then raise exception 'authentication required' using errcode = '42501'; end if;
  if exists (select 1 from public.identity_sharing_keys k where k.identity_id = v_actor) then
    if not coalesce(p_replace, false) then return; end if;
    update public.workspace_key_grants set status = 'stale', ephemeral_public_key = null, nonce = null, ciphertext = null
      where recipient_identity_id = v_actor and status = 'sealed';
    update public.workspace_key_grants set status = 'pending' where recipient_identity_id = v_actor and status = 'stale';
    delete from public.identity_sharing_keys where identity_id = v_actor;
  end if;
  insert into public.identity_sharing_keys (identity_id, public_key, fingerprint) values (v_actor, p_public_key, p_fingerprint);
  insert into public.identity_sharing_key_secrets (identity_id, nonce, wrapped_private_key) values (v_actor, p_nonce, p_wrapped_private_key);
end
$$;

create table if not exists public.workspace_key_grants (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  workspace_id uuid not null,
  recipient_identity_id uuid not null references public.identities(id) on delete cascade,
  role text not null check (role in ('manager','editor','viewer')),
  source text not null check (source in ('scim_group','admin','migration')),
  status text not null default 'pending' check (status in ('pending','sealed','accepted','cancelled','stale')),
  key_version integer,
  recipient_fingerprint text,
  ephemeral_public_key bytea check (ephemeral_public_key is null or octet_length(ephemeral_public_key) = 65),
  nonce bytea check (nonce is null or octet_length(nonce) = 12),
  ciphertext bytea check (ciphertext is null or octet_length(ciphertext) between 32 and 128),
  requested_by uuid references public.identities(id) on delete set null,
  sealed_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  sealed_at timestamptz,
  decided_at timestamptz,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  check (status <> 'sealed' or (ephemeral_public_key is not null and nonce is not null and ciphertext is not null and key_version is not null))
);
create unique index if not exists workspace_key_grants_open_idx on public.workspace_key_grants (workspace_id, recipient_identity_id)
  where status in ('pending','sealed');
create index if not exists workspace_key_grants_recipient_idx on public.workspace_key_grants (recipient_identity_id) where status = 'sealed';
alter table public.workspace_key_grants enable row level security;
revoke all on public.workspace_key_grants from anon, authenticated;
grant select on public.workspace_key_grants to authenticated;
drop policy if exists workspace_key_grants_read on public.workspace_key_grants;
create policy workspace_key_grants_read on public.workspace_key_grants for select to authenticated
  using (recipient_identity_id = (select private.current_identity_id())
    or (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager']))
    or (select private.can_admin_workspace_access(tenant_id)));

-- Gives (or changes) a member's access and opens a grant that a key holder's device seals.
create or replace function private.request_workspace_access(p_tenant_id uuid, p_workspace_id uuid, p_identity_id uuid,
  p_role text, p_source text, p_requested_by uuid)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_existing public.workspace_memberships%rowtype;
  v_grant uuid;
  v_version integer;
begin
  if p_role not in ('manager','editor','viewer') then raise exception 'invalid role' using errcode = '22023'; end if;
  if not exists (select 1 from public.tenant_memberships tm where tm.tenant_id = p_tenant_id and tm.identity_id = p_identity_id and tm.status = 'active') then
    raise exception 'person is not an active member of this organization' using errcode = '22023';
  end if;
  select w.current_key_version into v_version from public.workspaces w where w.id = p_workspace_id and w.tenant_id = p_tenant_id and w.status = 'active';
  if not found then raise exception 'workspace not found' using errcode = 'P0002'; end if;
  select * into v_existing from public.workspace_memberships wm where wm.workspace_id = p_workspace_id and wm.identity_id = p_identity_id for update;
  if found and v_existing.role = 'owner' then return null; end if;
  insert into public.workspace_memberships (tenant_id, workspace_id, identity_id, role, status)
    values (p_tenant_id, p_workspace_id, p_identity_id, p_role, 'active')
    on conflict (workspace_id, identity_id) do update set role = excluded.role, status = 'active', updated_at = now();
  if exists (select 1 from public.key_envelopes e where e.workspace_id = p_workspace_id and e.recipient_identity_id = p_identity_id
      and e.key_kind = 'workspace' and e.key_version = v_version and e.revoked_at is null) then
    return null; -- already holds the key
  end if;
  select g.id into v_grant from public.workspace_key_grants g
    where g.workspace_id = p_workspace_id and g.recipient_identity_id = p_identity_id and g.status in ('pending','sealed');
  if v_grant is not null then
    update public.workspace_key_grants set role = p_role where id = v_grant;
    return v_grant;
  end if;
  insert into public.workspace_key_grants (tenant_id, workspace_id, recipient_identity_id, role, source, requested_by)
    values (p_tenant_id, p_workspace_id, p_identity_id, p_role, p_source, p_requested_by)
    returning id into v_grant;
  return v_grant;
end
$$;
revoke all on function private.request_workspace_access(uuid,uuid,uuid,text,text,uuid) from public, anon, authenticated;

-- Removes access that was given by a group or grant: membership revoked, key envelopes revoked,
-- open grants cancelled and the workspace flagged for key rotation.
create or replace function private.remove_workspace_access(p_tenant_id uuid, p_workspace_id uuid, p_identity_id uuid, p_reason text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  if exists (select 1 from public.workspace_memberships wm where wm.workspace_id = p_workspace_id and wm.identity_id = p_identity_id and wm.role = 'owner') then
    return;
  end if;
  update public.workspace_key_grants set status = 'cancelled', decided_at = now(), ephemeral_public_key = null, nonce = null, ciphertext = null
    where workspace_id = p_workspace_id and recipient_identity_id = p_identity_id and status in ('pending','sealed','stale');
  if exists (select 1 from public.key_envelopes e where e.workspace_id = p_workspace_id and e.recipient_identity_id = p_identity_id and e.revoked_at is null) then
    update public.workspaces set key_rotation_required = true, updated_at = now() where id = p_workspace_id;
  end if;
  update public.key_envelopes set revoked_at = now()
    where workspace_id = p_workspace_id and recipient_identity_id = p_identity_id and revoked_at is null;
  update public.workspace_memberships set status = 'revoked', updated_at = now()
    where workspace_id = p_workspace_id and identity_id = p_identity_id and status <> 'revoked';
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'workspace.access_removed', 'workspaces', p_workspace_id,
    jsonb_build_object('identity_id', p_identity_id, 'reason', p_reason));
end
$$;
revoke all on function private.remove_workspace_access(uuid,uuid,uuid,text) from public, anon, authenticated;

-- Key holder seals a pending grant to the recipient's current sharing key.
create or replace function private.seal_workspace_key_grant(p_grant_id uuid, p_key_version integer, p_recipient_fingerprint text,
  p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_grant public.workspace_key_grants%rowtype; v_version integer;
begin
  select * into v_grant from public.workspace_key_grants g where g.id = p_grant_id and g.status in ('pending','sealed') for update;
  if not found or not private.has_workspace_role(v_grant.tenant_id, v_grant.workspace_id, array['owner','manager']) then
    raise exception 'grant not found' using errcode = '42501';
  end if;
  select w.current_key_version into v_version from public.workspaces w where w.id = v_grant.workspace_id;
  if p_key_version is distinct from v_version then raise exception 'workspace key changed; reload and try again' using errcode = '40001'; end if;
  if not exists (select 1 from public.identity_sharing_keys k where k.identity_id = v_grant.recipient_identity_id and k.fingerprint = p_recipient_fingerprint) then
    raise exception 'recipient key changed; reload and try again' using errcode = '40001';
  end if;
  update public.workspace_key_grants set status = 'sealed', key_version = p_key_version, recipient_fingerprint = p_recipient_fingerprint,
      ephemeral_public_key = p_ephemeral_public_key, nonce = p_nonce, ciphertext = p_ciphertext,
      sealed_by = private.current_identity_id(), sealed_at = now()
    where id = p_grant_id;
  perform private.append_audit_event(v_grant.tenant_id, private.current_identity_id(), 'workspace.key_shared', 'workspaces', v_grant.workspace_id,
    jsonb_build_object('identity_id', v_grant.recipient_identity_id, 'source', v_grant.source, 'role', v_grant.role));
end
$$;

-- Workspace managers may share as viewer/editor with active members. Granting or changing
-- the manager role, and restoring access that was removed, needs a workspace owner or an
-- organization administrator. Manually given access is no longer managed by group sync.
create or replace function private.check_direct_grant(p_tenant uuid, p_workspace_id uuid, p_identity_id uuid, p_role text)
returns void language plpgsql stable security definer set search_path = ''
as $$
declare v_admin boolean; v_existing public.workspace_memberships%rowtype;
begin
  v_admin := private.has_workspace_role(p_tenant, p_workspace_id, array['owner']) or private.can_admin_workspace_access(p_tenant);
  if v_admin then return; end if;
  if p_role = 'manager' then raise exception 'only the workspace owner or an administrator can add managers' using errcode = '42501'; end if;
  select * into v_existing from public.workspace_memberships wm where wm.workspace_id = p_workspace_id and wm.identity_id = p_identity_id;
  if found and v_existing.role in ('owner','manager') then
    raise exception 'only the workspace owner or an administrator can change a manager' using errcode = '42501';
  end if;
  if found and v_existing.status in ('revoked','suspended') then
    raise exception 'only the workspace owner or an administrator can restore removed access' using errcode = '42501';
  end if;
end
$$;
revoke all on function private.check_direct_grant(uuid,uuid,uuid,text) from public, anon, authenticated;

-- Administrator gives a member access directly (team migration, workspace sharing): one call
-- opens and seals the grant.
create or replace function private.grant_workspace_access(p_workspace_id uuid, p_identity_id uuid, p_role text,
  p_key_version integer, p_recipient_fingerprint text, p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea, p_source text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_tenant uuid; v_grant uuid; v_actor uuid := private.current_identity_id();
begin
  select w.tenant_id into v_tenant from public.workspaces w where w.id = p_workspace_id;
  if v_tenant is null or not private.has_workspace_role(v_tenant, p_workspace_id, array['owner','manager']) then
    raise exception 'workspace management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = v_tenant) <> 'organization' then
    raise exception 'direct sharing is available in organizations; use an invitation link' using errcode = '22023';
  end if;
  perform private.check_direct_grant(v_tenant, p_workspace_id, p_identity_id, p_role);
  v_grant := private.request_workspace_access(v_tenant, p_workspace_id, p_identity_id, p_role,
    case when p_source = 'migration' then 'migration' else 'admin' end, v_actor);
  delete from private.group_managed_access a where a.workspace_id = p_workspace_id and a.identity_id = p_identity_id;
  if v_grant is null then return null; end if;
  perform private.seal_workspace_key_grant(v_grant, p_key_version, p_recipient_fingerprint, p_ephemeral_public_key, p_nonce, p_ciphertext);
  return v_grant;
end
$$;

-- Administrator gives access to someone who cannot receive keys yet (has not unlocked Passkey-X
-- since sharing keys were introduced): the grant waits and is sealed automatically later.
create or replace function private.request_member_access(p_workspace_id uuid, p_identity_id uuid, p_role text, p_source text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_tenant uuid; v_grant uuid;
begin
  select w.tenant_id into v_tenant from public.workspaces w where w.id = p_workspace_id;
  if v_tenant is null or not private.has_workspace_role(v_tenant, p_workspace_id, array['owner','manager']) then
    raise exception 'workspace management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = v_tenant) <> 'organization' then
    raise exception 'direct sharing is available in organizations; use an invitation link' using errcode = '22023';
  end if;
  perform private.check_direct_grant(v_tenant, p_workspace_id, p_identity_id, p_role);
  v_grant := private.request_workspace_access(v_tenant, p_workspace_id, p_identity_id, p_role,
    case when p_source = 'migration' then 'migration' else 'admin' end, private.current_identity_id());
  delete from private.group_managed_access a where a.workspace_id = p_workspace_id and a.identity_id = p_identity_id;
  return v_grant;
end
$$;

-- Recipient stores the workspace key under their account root key; the grant is consumed.
create or replace function private.accept_workspace_key_grant(p_grant_id uuid, p_root_nonce bytea, p_root_wrapped_key bytea)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_grant public.workspace_key_grants%rowtype; v_actor uuid := private.current_identity_id(); v_version integer;
begin
  select * into v_grant from public.workspace_key_grants g
    where g.id = p_grant_id and g.recipient_identity_id = v_actor and g.status = 'sealed' for update;
  if not found then raise exception 'grant not available' using errcode = '42501'; end if;
  if not exists (select 1 from public.workspace_memberships wm where wm.workspace_id = v_grant.workspace_id and wm.identity_id = v_actor
      and wm.status = 'active' and (wm.expires_at is null or wm.expires_at > now())) then
    update public.workspace_key_grants set status = 'cancelled', decided_at = now(), ciphertext = null, nonce = null, ephemeral_public_key = null where id = p_grant_id;
    raise exception 'access was removed' using errcode = '42501';
  end if;
  select w.current_key_version into v_version from public.workspaces w where w.id = v_grant.workspace_id;
  if v_version is distinct from v_grant.key_version then
    update public.workspace_key_grants set status = 'pending', ciphertext = null, nonce = null, ephemeral_public_key = null where id = p_grant_id;
    raise exception 'workspace key changed; access will be re-shared' using errcode = '40001';
  end if;
  if octet_length(p_root_nonce) <> 12 or octet_length(p_root_wrapped_key) < 48 then raise exception 'invalid envelope' using errcode = '22023'; end if;
  update public.key_envelopes set revoked_at = now()
    where workspace_id = v_grant.workspace_id and recipient_identity_id = v_actor and key_kind = 'workspace' and key_version = v_grant.key_version and revoked_at is null;
  insert into public.key_envelopes (tenant_id, workspace_id, key_kind, key_version, recipient_identity_id, algorithm, nonce, wrapped_key)
    values (v_grant.tenant_id, v_grant.workspace_id, 'workspace', v_grant.key_version, v_actor, 'AES-256-GCM', p_root_nonce, p_root_wrapped_key);
  update public.workspace_key_grants set status = 'accepted', decided_at = now(), ciphertext = null, nonce = null, ephemeral_public_key = null
    where id = p_grant_id;
  perform private.append_audit_event(v_grant.tenant_id, v_actor, 'workspace.key_received', 'workspaces', v_grant.workspace_id,
    jsonb_build_object('source', v_grant.source));
  return v_grant.workspace_id;
end
$$;

-- Pending grants a key holder can seal now (workspaces where the caller is owner/manager).
create or replace function private.grants_to_seal(p_tenant_id uuid)
returns table (grant_id uuid, workspace_id uuid, recipient_identity_id uuid, role text, source text, display_name text,
  public_key bytea, fingerprint text, key_version integer, created_at timestamptz, requested_by uuid)
language sql stable security definer set search_path = ''
as $$
  select g.id, g.workspace_id, g.recipient_identity_id, g.role, g.source,
    coalesce(op.display_name, 'Member'), k.public_key, k.fingerprint, w.current_key_version, g.created_at, g.requested_by
  from public.workspace_key_grants g
  join public.workspaces w on w.id = g.workspace_id
  left join public.identity_sharing_keys k on k.identity_id = g.recipient_identity_id
  left join public.organization_profiles op on op.tenant_id = g.tenant_id and op.identity_id = g.recipient_identity_id
  where g.tenant_id = p_tenant_id and g.status = 'pending'
    and private.has_workspace_role(g.tenant_id, g.workspace_id, array['owner','manager'])
  order by g.created_at
  limit 500
$$;

-- ---------------------------------------------------------------------------
-- 6. SCIM groups mapped to workspaces
-- ---------------------------------------------------------------------------
create table if not exists public.scim_groups (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  external_id text check (external_id is null or char_length(external_id) <= 200),
  display_name text not null check (char_length(display_name) between 1 and 200),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, display_name)
);
create table if not exists public.scim_group_members (
  group_id uuid not null references public.scim_groups(id) on delete cascade,
  user_id uuid not null references public.scim_provisioned_users(id) on delete cascade,
  primary key (group_id, user_id)
);
create table if not exists public.group_workspace_mappings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  group_id uuid not null references public.scim_groups(id) on delete cascade,
  workspace_id uuid not null,
  role text not null check (role in ('manager','editor','viewer')),
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (group_id, workspace_id),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);
-- Which memberships were created by group sync (only these are removed by it).
create table if not exists private.group_managed_access (
  workspace_id uuid not null,
  identity_id uuid not null,
  tenant_id uuid not null,
  primary key (workspace_id, identity_id)
);
revoke all on private.group_managed_access from public, anon, authenticated;
alter table public.scim_groups enable row level security;
alter table public.scim_group_members enable row level security;
alter table public.group_workspace_mappings enable row level security;
revoke all on public.scim_groups, public.scim_group_members, public.group_workspace_mappings from anon, authenticated;
grant select on public.scim_groups, public.scim_group_members, public.group_workspace_mappings to authenticated;
drop policy if exists scim_groups_read on public.scim_groups;
create policy scim_groups_read on public.scim_groups for select to authenticated using ((select private.can_admin_workspace_access(tenant_id)));
drop policy if exists scim_group_members_read on public.scim_group_members;
create policy scim_group_members_read on public.scim_group_members for select to authenticated
  using (exists (select 1 from public.scim_groups g where g.id = group_id and (select private.can_admin_workspace_access(g.tenant_id))));
drop policy if exists group_workspace_mappings_read on public.group_workspace_mappings;
create policy group_workspace_mappings_read on public.group_workspace_mappings for select to authenticated
  using ((select private.can_admin_workspace_access(tenant_id)));

-- Recomputes group-derived access for one organization (optionally one person).
create or replace function private.sync_group_access(p_tenant_id uuid, p_identity_id uuid default null)
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_row record; v_changes integer := 0;
begin
  -- Desired: highest mapped role per (workspace, person) for active, joined people.
  create temporary table if not exists pg_temp.px_desired (workspace_id uuid, identity_id uuid, role text) on commit drop;
  truncate pg_temp.px_desired;
  insert into pg_temp.px_desired
  select m.workspace_id, u.identity_id,
    (array['viewer','editor','manager'])[max(case m.role when 'manager' then 3 when 'editor' then 2 else 1 end)]
  from public.group_workspace_mappings m
  join public.scim_group_members gm on gm.group_id = m.group_id
  join public.scim_provisioned_users u on u.id = gm.user_id and u.active and u.identity_id is not null
  join public.tenant_memberships tm on tm.tenant_id = m.tenant_id and tm.identity_id = u.identity_id and tm.status = 'active'
  join public.workspaces w on w.id = m.workspace_id and w.status = 'active'
  where m.tenant_id = p_tenant_id and (p_identity_id is null or u.identity_id = p_identity_id)
  group by m.workspace_id, u.identity_id;

  for v_row in
    select d.* from pg_temp.px_desired d
    where not exists (select 1 from public.workspace_memberships wm where wm.workspace_id = d.workspace_id and wm.identity_id = d.identity_id
      and wm.status = 'active' and (wm.role = d.role or wm.role = 'owner'
        or not exists (select 1 from private.group_managed_access a where a.workspace_id = d.workspace_id and a.identity_id = d.identity_id)))
  loop
    perform private.request_workspace_access(p_tenant_id, v_row.workspace_id, v_row.identity_id, v_row.role, 'scim_group', null);
    insert into private.group_managed_access (workspace_id, identity_id, tenant_id) values (v_row.workspace_id, v_row.identity_id, p_tenant_id)
      on conflict do nothing;
    v_changes := v_changes + 1;
  end loop;

  for v_row in
    select a.* from private.group_managed_access a
    where a.tenant_id = p_tenant_id and (p_identity_id is null or a.identity_id = p_identity_id)
      and not exists (select 1 from pg_temp.px_desired d where d.workspace_id = a.workspace_id and d.identity_id = a.identity_id)
  loop
    perform private.remove_workspace_access(p_tenant_id, v_row.workspace_id, v_row.identity_id, 'group_removed');
    delete from private.group_managed_access where workspace_id = v_row.workspace_id and identity_id = v_row.identity_id;
    v_changes := v_changes + 1;
  end loop;
  return v_changes;
end
$$;
revoke all on function private.sync_group_access(uuid, uuid) from public, anon, authenticated;

-- Joining, deactivation and reactivation of provisioned users re-run the sync for that person.
create or replace function private.scim_user_group_sync()
returns trigger language plpgsql volatile security definer set search_path = ''
as $$
begin
  if new.identity_id is not null and (old.identity_id is distinct from new.identity_id or old.active is distinct from new.active) then
    perform private.sync_group_access(new.tenant_id, new.identity_id);
  end if;
  return new;
end
$$;
drop trigger if exists scim_provisioned_users_group_sync on public.scim_provisioned_users;
create trigger scim_provisioned_users_group_sync after update of identity_id, active on public.scim_provisioned_users
  for each row execute function private.scim_user_group_sync();

-- SCIM /Groups (service role, called by the scim edge function).
create or replace function private.scim_group_json(p_group public.scim_groups)
returns jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('id', p_group.id, 'external_id', p_group.external_id, 'display_name', p_group.display_name,
    'created_at', p_group.created_at, 'updated_at', p_group.updated_at,
    'members', coalesce((select jsonb_agg(jsonb_build_object('value', u.id, 'display', u.display_name) order by u.display_name)
      from public.scim_group_members gm join public.scim_provisioned_users u on u.id = gm.user_id where gm.group_id = p_group.id), '[]'::jsonb))
$$;

create or replace function private.scim_list_groups(p_tenant_id uuid, p_display_name text, p_external_id text, p_offset integer, p_limit integer)
returns table (total bigint, groups jsonb)
language sql stable security definer set search_path = ''
as $$
  with matched as (
    select g.* from public.scim_groups g
    where g.tenant_id = p_tenant_id and (p_display_name is null or g.display_name = p_display_name)
      and (p_external_id is null or g.external_id = p_external_id))
  select (select count(*) from matched),
    coalesce((select jsonb_agg(private.scim_group_json(page) order by page.created_at) from (
      select * from matched m order by m.created_at offset greatest(p_offset, 0) limit least(greatest(p_limit, 0), 200)) page), '[]'::jsonb)
$$;

create or replace function private.scim_get_group(p_tenant_id uuid, p_id uuid)
returns jsonb language sql stable security definer set search_path = ''
as $$ select private.scim_group_json(g) from public.scim_groups g where g.id = p_id and g.tenant_id = p_tenant_id $$;

-- p_members: null keeps members; otherwise the full replacement list of SCIM user ids.
create or replace function private.scim_upsert_group(p_tenant_id uuid, p_id uuid, p_external_id text, p_display_name text, p_members uuid[])
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare v_group public.scim_groups%rowtype;
begin
  if p_id is null then
    insert into public.scim_groups (tenant_id, external_id, display_name) values (p_tenant_id, p_external_id, btrim(p_display_name))
      returning * into v_group;
    perform private.append_audit_event(p_tenant_id, null, 'scim.group_created', 'scim_groups', v_group.id, jsonb_build_object('name', v_group.display_name));
  else
    update public.scim_groups set external_id = coalesce(p_external_id, external_id),
        display_name = coalesce(nullif(btrim(coalesce(p_display_name, '')), ''), display_name), updated_at = now()
      where id = p_id and tenant_id = p_tenant_id returning * into v_group;
    if not found then raise exception 'group not found' using errcode = 'P0002'; end if;
  end if;
  if p_members is not null then
    delete from public.scim_group_members gm where gm.group_id = v_group.id and not (gm.user_id = any(p_members));
    insert into public.scim_group_members (group_id, user_id)
      select v_group.id, u.id from public.scim_provisioned_users u where u.tenant_id = p_tenant_id and u.id = any(p_members)
      on conflict do nothing;
    perform private.sync_group_access(p_tenant_id, null);
  end if;
  return private.scim_group_json(v_group);
end
$$;

create or replace function private.scim_patch_group_members(p_tenant_id uuid, p_id uuid, p_add uuid[], p_remove uuid[])
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare v_group public.scim_groups%rowtype;
begin
  select * into v_group from public.scim_groups g where g.id = p_id and g.tenant_id = p_tenant_id for update;
  if not found then raise exception 'group not found' using errcode = 'P0002'; end if;
  if cardinality(coalesce(p_remove, '{}')) > 0 then
    delete from public.scim_group_members gm where gm.group_id = p_id and gm.user_id = any(p_remove);
  end if;
  if cardinality(coalesce(p_add, '{}')) > 0 then
    insert into public.scim_group_members (group_id, user_id)
      select p_id, u.id from public.scim_provisioned_users u where u.tenant_id = p_tenant_id and u.id = any(p_add)
      on conflict do nothing;
  end if;
  update public.scim_groups set updated_at = now() where id = p_id returning * into v_group;
  perform private.sync_group_access(p_tenant_id, null);
  return private.scim_group_json(v_group);
end
$$;

create or replace function private.scim_delete_group(p_tenant_id uuid, p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare v_name text;
begin
  delete from public.scim_groups g where g.id = p_id and g.tenant_id = p_tenant_id returning display_name into v_name;
  if not found then return false; end if;
  perform private.sync_group_access(p_tenant_id, null);
  perform private.append_audit_event(p_tenant_id, null, 'scim.group_deleted', 'scim_groups', p_id, jsonb_build_object('name', v_name));
  return true;
end
$$;

-- Administrators map groups to workspaces they manage (they must hold the key to deliver it).
create or replace function private.set_group_mapping(p_group_id uuid, p_workspace_id uuid, p_role text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_group public.scim_groups%rowtype; v_actor uuid; v_id uuid;
begin
  select * into v_group from public.scim_groups g where g.id = p_group_id;
  if not found then raise exception 'group not found' using errcode = 'P0002'; end if;
  v_actor := private.require_business_admin(v_group.tenant_id);
  if not private.has_workspace_role(v_group.tenant_id, p_workspace_id, array['owner','manager']) then
    raise exception 'you must manage the workspace to map a group to it' using errcode = '42501';
  end if;
  if p_role not in ('manager','editor','viewer') then raise exception 'invalid role' using errcode = '22023'; end if;
  insert into public.group_workspace_mappings (tenant_id, group_id, workspace_id, role, created_by)
    values (v_group.tenant_id, p_group_id, p_workspace_id, p_role, v_actor)
    on conflict (group_id, workspace_id) do update set role = excluded.role
    returning id into v_id;
  perform private.append_audit_event(v_group.tenant_id, v_actor, 'scim.group_mapped', 'workspaces', p_workspace_id,
    jsonb_build_object('group', v_group.display_name, 'role', p_role));
  perform private.sync_group_access(v_group.tenant_id, null);
  return v_id;
end
$$;

create or replace function private.delete_group_mapping(p_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_row public.group_workspace_mappings%rowtype; v_actor uuid;
begin
  select * into v_row from public.group_workspace_mappings m where m.id = p_id;
  if not found then raise exception 'mapping not found' using errcode = 'P0002'; end if;
  v_actor := private.require_business_admin(v_row.tenant_id);
  if not private.has_workspace_role(v_row.tenant_id, v_row.workspace_id, array['owner','manager']) then
    raise exception 'you must manage the workspace to change its group mappings' using errcode = '42501';
  end if;
  delete from public.group_workspace_mappings where id = p_id;
  perform private.append_audit_event(v_row.tenant_id, v_actor, 'scim.group_unmapped', 'workspaces', v_row.workspace_id, '{}'::jsonb);
  perform private.sync_group_access(v_row.tenant_id, null);
end
$$;

-- ---------------------------------------------------------------------------
-- 7. Organization workspaces created by administrators (team migration)
-- ---------------------------------------------------------------------------
create or replace function private.create_organization_workspace(p_tenant_id uuid, p_workspace_id uuid,
  p_encrypted_name bytea, p_name_nonce bytea, p_name_aad_hash bytea, p_key_nonce bytea, p_wrapped_workspace_key bytea, p_source text)
returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.require_business_admin(p_tenant_id);
begin
  if octet_length(p_name_nonce) <> 12 or octet_length(p_name_aad_hash) <> 32 or octet_length(p_key_nonce) <> 12
     or octet_length(p_wrapped_workspace_key) < 48 or octet_length(p_encrypted_name) < 16 then
    raise exception 'invalid encrypted workspace envelope' using errcode = '22023';
  end if;
  insert into public.workspaces (id, tenant_id, kind, encrypted_name, created_by, suite, name_nonce, name_aad_hash,
      current_key_version, key_rotation_required, status)
    values (p_workspace_id, p_tenant_id, 'shared', p_encrypted_name, v_actor, 'business', p_name_nonce, p_name_aad_hash, 1, false, 'active');
  insert into public.workspace_memberships (tenant_id, workspace_id, identity_id, role, status)
    values (p_tenant_id, p_workspace_id, v_actor, 'owner', 'active');
  insert into public.key_envelopes (tenant_id, workspace_id, key_kind, key_version, recipient_identity_id, algorithm, nonce, wrapped_key)
    values (p_tenant_id, p_workspace_id, 'workspace', 1, v_actor, 'AES-256-GCM', p_key_nonce, p_wrapped_workspace_key);
  perform private.append_audit_event(p_tenant_id, v_actor, 'workspace.created', 'workspaces', p_workspace_id,
    jsonb_build_object('source', case when p_source = 'migration' then 'migration' else 'admin' end));
  return p_workspace_id;
end
$$;

-- ---------------------------------------------------------------------------
-- 8. Self-serve SAML activation
-- ---------------------------------------------------------------------------
-- provider_id (text) already exists on sso_connections.
alter table public.sso_connections add column if not exists activation_error text;
grant select (provider_id, activation_error) on public.sso_connections to authenticated;

-- Service role only (identity-admin edge function after it registered the provider).
create or replace function private.set_sso_provider(p_tenant_id uuid, p_provider_id uuid, p_error text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  update public.sso_connections set
      provider_id = coalesce(p_provider_id::text, provider_id),
      status = case when p_provider_id is not null then 'active' when p_error is not null and status <> 'active' then 'requested' else status end,
      activation_error = case when p_provider_id is not null then null else left(p_error, 200) end,
      updated_at = now()
    where tenant_id = p_tenant_id;
  perform private.append_audit_event(p_tenant_id, null,
    case when p_provider_id is not null then 'sso.activated' else 'sso.activation_failed' end, 'sso_connections', null,
    jsonb_build_object('error', p_error));
end
$$;

create or replace function private.sso_activation_allowed(p_tenant_id uuid)
returns boolean language sql stable security definer set search_path = ''
as $$ select coalesce((select t.kind = 'organization' from public.tenants t where t.id = p_tenant_id), false)
  and private.has_business_entitlement(p_tenant_id) $$;

create or replace function private.clear_sso_provider(p_tenant_id uuid)
returns void language plpgsql volatile security definer set search_path = ''
as $$
begin
  update public.sso_connections set provider_id = null, status = 'draft', enforce_sso = false, activation_error = null, updated_at = now()
    where tenant_id = p_tenant_id;
  perform private.append_audit_event(p_tenant_id, null, 'sso.deactivated', 'sso_connections', null, '{}'::jsonb);
end
$$;

-- An identity provider can only vouch for email addresses on its own domains. Accounts created
-- through SAML whose email is outside their provider's domains are not treated as verified, so
-- they cannot claim provisioned seats or accept invitations addressed to someone else.
create or replace function private.sso_email_domain_ok(p_user_id uuid, p_email text)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from auth.identities i
    join auth.sso_domains d on i.provider = 'sso:' || d.sso_provider_id::text
    where i.user_id = p_user_id and lower(d.domain) = lower(split_part(p_email, '@', 2)))
$$;
revoke all on function private.sso_email_domain_ok(uuid, text) from public, anon, authenticated;

create or replace function private.current_verified_email_hash()
returns bytea language sql stable security definer set search_path = ''
as $$
  select extensions.digest(convert_to(lower(trim(u.email)), 'UTF8'), 'sha256')
  from auth.users u
  where u.id = auth.uid()
    and u.email is not null
    and u.email_confirmed_at is not null
    and (not coalesce(u.is_sso_user, false) or private.sso_email_domain_ok(u.id, u.email))
  limit 1
$$;
revoke all on function private.current_verified_email_hash() from public, anon;
grant execute on function private.current_verified_email_hash() to authenticated;

-- A connected identity provider stays bound to its verified domain: turn SSO off before moving
-- to another domain (that removes the provider from Supabase Auth).
create or replace function private.sso_domain_change_guard()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if old.domain is distinct from new.domain and old.provider_id is not null and new.provider_id is not null then
    raise exception 'turn off single sign-on before changing the domain' using errcode = '22023';
  end if;
  return new;
end
$$;
revoke all on function private.sso_domain_change_guard() from public, anon, authenticated;
drop trigger if exists sso_connections_domain_guard on public.sso_connections;
create trigger sso_connections_domain_guard before update of domain on public.sso_connections
  for each row execute function private.sso_domain_change_guard();

-- ---------------------------------------------------------------------------
-- Public wrappers and grants
-- ---------------------------------------------------------------------------
create or replace function public.create_audit_destination(p_tenant_id uuid, p_name text, p_format text, p_url text default null,
  p_destination jsonb default '{}', p_credential text default null, p_event_prefixes text[] default '{}')
returns table (id uuid, secret text) language sql volatile security invoker set search_path = ''
as $$ select * from private.create_audit_destination(p_tenant_id, p_name, p_format, p_url, p_destination, p_credential, p_event_prefixes) $$;
create or replace function public.set_audit_destination_credential(p_id uuid, p_credential text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_audit_destination_credential(p_id, p_credential) $$;
create or replace function public.create_chat_channel(p_tenant_id uuid, p_kind text, p_name text, p_url text,
  p_events text[] default null, p_min_severity text default 'high')
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_chat_channel(p_tenant_id, p_kind, p_name, p_url, p_events, p_min_severity) $$;
create or replace function public.update_chat_channel(p_id uuid, p_name text default null, p_events text[] default null,
  p_min_severity text default null, p_enabled boolean default null, p_url text default null)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.update_chat_channel(p_id, p_name, p_events, p_min_severity, p_enabled, p_url) $$;
create or replace function public.delete_chat_channel(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.delete_chat_channel(p_id) $$;
create or replace function public.test_chat_channel(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.test_chat_channel(p_id) $$;
create or replace function public.create_org_api_key(p_tenant_id uuid, p_name text, p_scopes text[], p_expires_in_days integer default 90)
returns table (id uuid, token text) language sql volatile security invoker set search_path = ''
as $$ select * from private.create_org_api_key(p_tenant_id, p_name, p_scopes, p_expires_in_days) $$;
create or replace function public.revoke_org_api_key(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.revoke_org_api_key(p_id) $$;
create or replace function public.publish_sharing_key(p_public_key bytea, p_fingerprint text, p_nonce bytea, p_wrapped_private_key bytea, p_replace boolean default false)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.publish_sharing_key(p_public_key, p_fingerprint, p_nonce, p_wrapped_private_key, p_replace) $$;
create or replace function public.seal_workspace_key_grant(p_grant_id uuid, p_key_version integer, p_recipient_fingerprint text,
  p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.seal_workspace_key_grant(p_grant_id, p_key_version, p_recipient_fingerprint, p_ephemeral_public_key, p_nonce, p_ciphertext) $$;
create or replace function public.grant_workspace_access(p_workspace_id uuid, p_identity_id uuid, p_role text, p_key_version integer,
  p_recipient_fingerprint text, p_ephemeral_public_key bytea, p_nonce bytea, p_ciphertext bytea, p_source text default 'admin')
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.grant_workspace_access(p_workspace_id, p_identity_id, p_role, p_key_version, p_recipient_fingerprint,
  p_ephemeral_public_key, p_nonce, p_ciphertext, p_source) $$;
create or replace function public.request_member_access(p_workspace_id uuid, p_identity_id uuid, p_role text, p_source text default 'admin')
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.request_member_access(p_workspace_id, p_identity_id, p_role, p_source) $$;
create or replace function public.accept_workspace_key_grant(p_grant_id uuid, p_root_nonce bytea, p_root_wrapped_key bytea)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.accept_workspace_key_grant(p_grant_id, p_root_nonce, p_root_wrapped_key) $$;
create or replace function public.grants_to_seal(p_tenant_id uuid)
returns table (grant_id uuid, workspace_id uuid, recipient_identity_id uuid, role text, source text, display_name text,
  public_key bytea, fingerprint text, key_version integer, created_at timestamptz, requested_by uuid)
language sql stable security invoker set search_path = ''
as $$ select * from private.grants_to_seal(p_tenant_id) $$;
create or replace function public.set_group_mapping(p_group_id uuid, p_workspace_id uuid, p_role text)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.set_group_mapping(p_group_id, p_workspace_id, p_role) $$;
create or replace function public.delete_group_mapping(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.delete_group_mapping(p_id) $$;
create or replace function public.create_organization_workspace(p_tenant_id uuid, p_workspace_id uuid, p_encrypted_name bytea,
  p_name_nonce bytea, p_name_aad_hash bytea, p_key_nonce bytea, p_wrapped_workspace_key bytea, p_source text default 'admin')
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_organization_workspace(p_tenant_id, p_workspace_id, p_encrypted_name, p_name_nonce, p_name_aad_hash,
  p_key_nonce, p_wrapped_workspace_key, p_source) $$;

-- Service-role wrappers (edge functions).
create or replace function public.authenticate_org_api_key(p_token text)
returns table (key_id uuid, tenant_id uuid, scopes text[], rate_limited boolean)
language sql volatile security invoker set search_path = ''
as $$ select * from private.authenticate_org_api_key(p_token) $$;
create or replace function public.api_audit_events(p_key_id uuid, p_after bigint default 0, p_limit integer default 100)
returns setof jsonb language sql stable security invoker set search_path = '' as $$ select private.api_audit_events(p_key_id, p_after, p_limit) $$;
create or replace function public.api_alerts(p_key_id uuid, p_status text default null, p_limit integer default 50)
returns setof jsonb language sql stable security invoker set search_path = '' as $$ select private.api_alerts(p_key_id, p_status, p_limit) $$;
create or replace function public.api_update_alert(p_key_id uuid, p_alert_id uuid, p_status text, p_note text default null)
returns jsonb language sql volatile security invoker set search_path = '' as $$ select private.api_update_alert(p_key_id, p_alert_id, p_status, p_note) $$;
create or replace function public.api_members(p_key_id uuid, p_offset integer default 0, p_limit integer default 100)
returns setof jsonb language sql stable security invoker set search_path = '' as $$ select private.api_members(p_key_id, p_offset, p_limit) $$;
create or replace function public.api_security_summary(p_key_id uuid)
returns jsonb language sql stable security invoker set search_path = '' as $$ select private.api_security_summary(p_key_id) $$;
create or replace function public.api_weekly_reports(p_key_id uuid, p_limit integer default 4)
returns setof jsonb language sql stable security invoker set search_path = '' as $$ select private.api_weekly_reports(p_key_id, p_limit) $$;
create or replace function public.scim_list_groups(p_tenant_id uuid, p_display_name text default null, p_external_id text default null,
  p_offset integer default 0, p_limit integer default 100)
returns table (total bigint, groups jsonb) language sql stable security invoker set search_path = ''
as $$ select * from private.scim_list_groups(p_tenant_id, p_display_name, p_external_id, p_offset, p_limit) $$;
create or replace function public.scim_get_group(p_tenant_id uuid, p_id uuid)
returns jsonb language sql stable security invoker set search_path = '' as $$ select private.scim_get_group(p_tenant_id, p_id) $$;
create or replace function public.scim_upsert_group(p_tenant_id uuid, p_id uuid, p_external_id text, p_display_name text, p_members uuid[])
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.scim_upsert_group(p_tenant_id, p_id, p_external_id, p_display_name, p_members) $$;
create or replace function public.scim_patch_group_members(p_tenant_id uuid, p_id uuid, p_add uuid[], p_remove uuid[])
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.scim_patch_group_members(p_tenant_id, p_id, p_add, p_remove) $$;
create or replace function public.scim_delete_group(p_tenant_id uuid, p_id uuid)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.scim_delete_group(p_tenant_id, p_id) $$;
create or replace function public.set_sso_provider(p_tenant_id uuid, p_provider_id uuid, p_error text default null)
returns void language sql volatile security invoker set search_path = '' as $$ select private.set_sso_provider(p_tenant_id, p_provider_id, p_error) $$;
create or replace function public.sso_activation_allowed(p_tenant_id uuid)
returns boolean language sql stable security invoker set search_path = '' as $$ select private.sso_activation_allowed(p_tenant_id) $$;
create or replace function public.clear_sso_provider(p_tenant_id uuid)
returns void language sql volatile security invoker set search_path = '' as $$ select private.clear_sso_provider(p_tenant_id) $$;

do $$
declare
  v_fn text;
  v_user text[] := array[
    'create_audit_destination(uuid,text,text,text,jsonb,text,text[])', 'set_audit_destination_credential(uuid,text)',
    'create_chat_channel(uuid,text,text,text,text[],text)', 'update_chat_channel(uuid,text,text[],text,boolean,text)',
    'delete_chat_channel(uuid)', 'test_chat_channel(uuid)',
    'create_org_api_key(uuid,text,text[],integer)', 'revoke_org_api_key(uuid)',
    'publish_sharing_key(bytea,text,bytea,bytea,boolean)', 'seal_workspace_key_grant(uuid,integer,text,bytea,bytea,bytea)',
    'grant_workspace_access(uuid,uuid,text,integer,text,bytea,bytea,bytea,text)', 'accept_workspace_key_grant(uuid,bytea,bytea)', 'request_member_access(uuid,uuid,text,text)',
    'grants_to_seal(uuid)', 'set_group_mapping(uuid,uuid,text)', 'delete_group_mapping(uuid)',
    'create_organization_workspace(uuid,uuid,bytea,bytea,bytea,bytea,bytea,text)'];
  v_service text[] := array[
    'authenticate_org_api_key(text)', 'api_audit_events(uuid,bigint,integer)', 'api_alerts(uuid,text,integer)',
    'api_update_alert(uuid,uuid,text,text)', 'api_members(uuid,integer,integer)', 'api_security_summary(uuid)',
    'api_weekly_reports(uuid,integer)', 'scim_list_groups(uuid,text,text,integer,integer)',
    'scim_get_group(uuid,uuid)', 'scim_upsert_group(uuid,uuid,text,text,uuid[])', 'scim_patch_group_members(uuid,uuid,uuid[],uuid[])',
    'scim_delete_group(uuid,uuid)', 'set_sso_provider(uuid,uuid,text)', 'clear_sso_provider(uuid)', 'sso_activation_allowed(uuid)'];
begin
  foreach v_fn in array v_user loop
    execute format('revoke all on function private.%s from public, anon', v_fn);
    execute format('grant execute on function private.%s to authenticated', v_fn);
    execute format('revoke all on function public.%s from public, anon', v_fn);
    execute format('grant execute on function public.%s to authenticated', v_fn);
  end loop;
  foreach v_fn in array v_service loop
    execute format('revoke all on function private.%s from public, anon, authenticated', v_fn);
    execute format('grant execute on function private.%s to service_role', v_fn);
    execute format('revoke all on function public.%s from public, anon, authenticated', v_fn);
    execute format('grant execute on function public.%s to service_role', v_fn);
  end loop;
end $$;
revoke all on function private.api_key_tenant(uuid, text) from public, anon, authenticated;
revoke all on function private.enqueue_chat(uuid,text,text,jsonb) from public, anon, authenticated;
revoke all on function private.scim_group_json(public.scim_groups) from public, anon, authenticated;
revoke all on function private.valid_chat_webhook(text,text) from public, anon, authenticated;
revoke all on function private.datadog_sites() from public, anon, authenticated;
revoke all on function private.api_scopes() from public, anon, authenticated;
revoke all on function private.severity_rank(text) from public, anon, authenticated;
revoke all on function private.chat_on_alert() from public, anon, authenticated;
revoke all on function private.chat_on_weekly_report() from public, anon, authenticated;
revoke all on function private.scim_user_group_sync() from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('px-chat-notifications', '* * * * *', $cron$select private.deliver_chat_notifications()$cron$);
  end if;
end $$;

comment on table public.chat_channels is 'Slack / Teams alert channels. Webhook URLs live in private.chat_channel_secrets (write-only).';
comment on table public.org_api_keys is 'Organization API keys. Only SHA-256 hashes of the tokens are stored.';
comment on table public.identity_sharing_keys is 'Members'' P-256 public keys for receiving workspace keys. Private halves stay encrypted under each account root key.';
comment on table public.workspace_key_grants is 'Workspace keys encrypted to a member''s public key (ECDH P-256 + HKDF + AES-GCM). Ciphertext only.';
comment on table public.group_workspace_mappings is 'SCIM groups mapped to workspaces; membership is synchronised by private.sync_group_access.';

commit;
