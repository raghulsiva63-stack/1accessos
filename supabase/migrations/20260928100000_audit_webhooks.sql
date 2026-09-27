-- Audit streaming: signed HTTPS webhooks for SIEM and automation.
-- Events are metadata only (no vault content). Delivery is at-least-once and in order:
-- a batch is re-sent until the endpoint answers 2xx, then the cursor advances.

create extension if not exists pg_net;

create table if not exists public.audit_webhooks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 80),
  url text not null check (char_length(url) <= 500),
  secret text not null,
  event_prefixes text[] not null default '{}' check (cardinality(event_prefixes) <= 20),
  enabled boolean not null default true,
  created_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  delivered_through bigint not null default 0,
  pending_request_id bigint,
  pending_through bigint,
  pending_since timestamptz,
  test_request_id bigint,
  failure_count integer not null default 0,
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_status integer,
  last_error text,
  last_test_status integer,
  last_test_at timestamptz
);
create index if not exists audit_webhooks_tenant_idx on public.audit_webhooks (tenant_id);

alter table public.audit_webhooks enable row level security;
revoke all on public.audit_webhooks from anon, authenticated;
-- The signing secret is never readable through the API.
grant select (id, tenant_id, name, url, event_prefixes, enabled, created_by, created_at, delivered_through,
  failure_count, last_attempt_at, last_success_at, last_status, last_error, last_test_status, last_test_at)
  on public.audit_webhooks to authenticated;

create or replace function private.can_manage_audit_webhooks(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant, array['owner','admin'])
    or private.can_manage_organization(target_tenant, array['organization_admin','security_admin'])
$$;
revoke all on function private.can_manage_audit_webhooks(uuid) from public, anon;
grant execute on function private.can_manage_audit_webhooks(uuid) to authenticated;

drop policy if exists audit_webhooks_read on public.audit_webhooks;
create policy audit_webhooks_read on public.audit_webhooks for select to authenticated
  using (private.can_read_organization_audit(tenant_id));

-- Only public HTTPS hostnames: no IP literals, localhost or internal suffixes.
create or replace function private.valid_webhook_url(p_url text)
returns boolean language plpgsql immutable set search_path = ''
as $$
declare v_host text;
begin
  if p_url is null or char_length(p_url) > 500 or p_url !~ '^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?(/[^[:space:]]*)?$' then
    return false;
  end if;
  v_host := lower(substring(p_url from '^https://([A-Za-z0-9.-]+)'));
  if v_host ~ '^[0-9.]+$' or v_host !~ '\.[a-z]{2,}$' or v_host in ('localhost')
     or v_host ~ '(\.local|\.localhost|\.internal|\.lan|\.home|\.corp|\.intranet|\.supabase\.co|\.supabase\.in)$' then
    return false;
  end if;
  return true;
end
$$;

create or replace function private.create_audit_webhook(p_tenant_id uuid, p_name text, p_url text, p_event_prefixes text[])
returns table (id uuid, secret text)
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_secret text := 'pxwh_' || encode(extensions.gen_random_bytes(32), 'hex');
  v_id uuid;
  v_prefixes text[] := coalesce(p_event_prefixes, '{}');
begin
  if not private.can_manage_audit_webhooks(p_tenant_id) then
    raise exception 'audit streaming management denied' using errcode = '42501';
  end if;
  if (select t.kind from public.tenants t where t.id = p_tenant_id) is distinct from 'organization' then
    raise exception 'audit streaming requires an organization' using errcode = '22023';
  end if;
  if not private.valid_webhook_url(p_url) then
    raise exception 'webhook url must be a public https address' using errcode = '22023';
  end if;
  if exists (select 1 from unnest(v_prefixes) prefix where prefix !~ '^[a-z_]{1,40}\.?[a-z_]{0,40}$') then
    raise exception 'invalid event filter' using errcode = '22023';
  end if;
  if (select count(*) from public.audit_webhooks w where w.tenant_id = p_tenant_id) >= 5 then
    raise exception 'an organization can have at most 5 audit webhooks' using errcode = 'P0001';
  end if;
  insert into public.audit_webhooks (tenant_id, name, url, secret, event_prefixes, created_by, delivered_through)
  values (p_tenant_id, btrim(p_name), p_url, v_secret, v_prefixes, private.current_identity_id(),
    coalesce((select max(e.sequence) from public.audit_events e where e.tenant_id = p_tenant_id), 0))
  returning audit_webhooks.id into v_id;
  perform private.append_audit_event(p_tenant_id, private.current_identity_id(), 'audit_webhook.created', 'audit_webhooks', v_id,
    jsonb_build_object('name', btrim(p_name), 'host', substring(p_url from '^https://([^/:]+)')));
  return query select v_id, v_secret;
end
$$;

create or replace function private.update_audit_webhook(p_id uuid, p_enabled boolean, p_rotate_secret boolean)
returns text
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_hook public.audit_webhooks%rowtype;
  v_secret text;
begin
  select * into v_hook from public.audit_webhooks w where w.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_hook.tenant_id) then
    raise exception 'audit webhook not found' using errcode = '42501';
  end if;
  if p_rotate_secret then
    v_secret := 'pxwh_' || encode(extensions.gen_random_bytes(32), 'hex');
    update public.audit_webhooks set secret = v_secret where id = p_id;
    perform private.append_audit_event(v_hook.tenant_id, private.current_identity_id(), 'audit_webhook.secret_rotated', 'audit_webhooks', p_id, '{}'::jsonb);
  end if;
  if p_enabled is not null and p_enabled is distinct from v_hook.enabled then
    update public.audit_webhooks set enabled = p_enabled,
      failure_count = case when p_enabled then 0 else failure_count end
      where id = p_id;
    perform private.append_audit_event(v_hook.tenant_id, private.current_identity_id(),
      case when p_enabled then 'audit_webhook.enabled' else 'audit_webhook.disabled' end, 'audit_webhooks', p_id, '{}'::jsonb);
  end if;
  return v_secret;
end
$$;

create or replace function private.delete_audit_webhook(p_id uuid)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare v_hook public.audit_webhooks%rowtype;
begin
  select * into v_hook from public.audit_webhooks w where w.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_hook.tenant_id) then
    raise exception 'audit webhook not found' using errcode = '42501';
  end if;
  delete from public.audit_webhooks where id = p_id;
  perform private.append_audit_event(v_hook.tenant_id, private.current_identity_id(), 'audit_webhook.deleted', 'audit_webhooks', p_id,
    jsonb_build_object('name', v_hook.name));
end
$$;

-- Builds, signs and posts one request. Signature: HMAC-SHA256(secret, "<timestamp>.<body>").
create or replace function private.post_audit_webhook(p_hook public.audit_webhooks, p_payload jsonb)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_ts text := extract(epoch from now())::bigint::text;
  v_signature text := encode(extensions.hmac(v_ts || '.' || p_payload::text, p_hook.secret, 'sha256'), 'hex');
begin
  return net.http_post(
    url := p_hook.url,
    body := p_payload,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'User-Agent', 'Passkey-X-Webhooks/1',
      'X-PasskeyX-Webhook', p_hook.id::text,
      'X-PasskeyX-Timestamp', v_ts,
      'X-PasskeyX-Signature', 'v1=' || v_signature),
    timeout_milliseconds := 8000);
end
$$;
revoke all on function private.post_audit_webhook(public.audit_webhooks, jsonb) from public, anon, authenticated;

create or replace function private.test_audit_webhook(p_id uuid)
returns void
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_hook public.audit_webhooks%rowtype;
  v_request bigint;
begin
  select * into v_hook from public.audit_webhooks w where w.id = p_id for update;
  if not found or not private.can_manage_audit_webhooks(v_hook.tenant_id) then
    raise exception 'audit webhook not found' using errcode = '42501';
  end if;
  if v_hook.last_test_at is not null and v_hook.last_test_at > now() - interval '10 seconds' then
    raise exception 'wait a few seconds before sending another test' using errcode = 'P0001';
  end if;
  v_request := private.post_audit_webhook(v_hook, jsonb_build_object(
    'source', 'passkey-x', 'type', 'test', 'webhook_id', v_hook.id, 'tenant_id', v_hook.tenant_id,
    'sent_at', now(), 'events', jsonb_build_array(jsonb_build_object(
      'sequence', 0, 'occurred_at', now(), 'action', 'audit_webhook.test', 'target_type', 'audit_webhooks',
      'target_id', v_hook.id, 'actor_identity_id', private.current_identity_id(), 'metadata', '{}'::jsonb))));
  update public.audit_webhooks set test_request_id = v_request, last_test_at = now(), last_test_status = null where id = p_id;
end
$$;

create or replace function private.deliver_audit_webhooks()
returns integer
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_hook public.audit_webhooks%rowtype;
  v_response record;
  v_through bigint;
  v_events jsonb;
  v_sent integer := 0;
begin
  for v_hook in select * from public.audit_webhooks w where w.enabled or w.test_request_id is not null for update skip locked loop
    if v_hook.test_request_id is not null then
      select r.status_code into v_response from net._http_response r where r.id = v_hook.test_request_id;
      if found then
        update public.audit_webhooks set last_test_status = coalesce(v_response.status_code, 0), test_request_id = null where id = v_hook.id;
      elsif v_hook.last_test_at < now() - interval '2 minutes' then
        update public.audit_webhooks set last_test_status = 0, test_request_id = null where id = v_hook.id;
      end if;
    end if;
    continue when not v_hook.enabled;

    if v_hook.pending_request_id is not null then
      select r.status_code, r.error_msg, r.timed_out into v_response from net._http_response r where r.id = v_hook.pending_request_id;
      if not found and v_hook.pending_since > now() - interval '3 minutes' then
        continue;
      end if;
      if found and v_response.status_code between 200 and 299 then
        update public.audit_webhooks set delivered_through = pending_through, pending_request_id = null, pending_through = null,
          pending_since = null, last_success_at = now(), last_status = v_response.status_code, last_error = null, failure_count = 0
          where id = v_hook.id;
        v_hook.delivered_through := v_hook.pending_through;
      else
        update public.audit_webhooks set pending_request_id = null, pending_through = null, pending_since = null,
          failure_count = failure_count + 1, enabled = failure_count + 1 < 100,
          last_status = case when found then v_response.status_code else null end,
          last_error = left(case when not found then 'no response' when v_response.timed_out then 'timed out'
            else coalesce(v_response.error_msg, 'HTTP ' || v_response.status_code) end, 300)
          where id = v_hook.id;
        continue;
      end if;
    end if;

    -- Exponential backoff after failures (1, 2, 4 … up to 60 minutes).
    continue when v_hook.failure_count > 0 and v_hook.last_attempt_at is not null
      and v_hook.last_attempt_at > now() - least(interval '60 minutes', interval '1 minute' * power(2, least(v_hook.failure_count, 6)));

    select max(e.sequence) into v_through from (
      select e.sequence from public.audit_events e
      where e.tenant_id = v_hook.tenant_id and e.sequence > v_hook.delivered_through
      order by e.sequence limit 200) e;
    continue when v_through is null;

    select coalesce(jsonb_agg(jsonb_build_object(
      'sequence', e.sequence, 'occurred_at', e.occurred_at, 'action', e.action, 'target_type', e.target_type,
      'target_id', e.target_id, 'actor_identity_id', e.actor_identity_id, 'metadata', e.metadata,
      'hash_version', e.hash_version, 'event_hash', encode(e.event_hash, 'hex')) order by e.sequence), '[]'::jsonb)
    into v_events
    from public.audit_events e
    where e.tenant_id = v_hook.tenant_id and e.sequence > v_hook.delivered_through and e.sequence <= v_through
      and (cardinality(v_hook.event_prefixes) = 0 or exists (select 1 from unnest(v_hook.event_prefixes) prefix where e.action like prefix || '%'));

    if jsonb_array_length(v_events) = 0 then
      update public.audit_webhooks set delivered_through = v_through where id = v_hook.id;
      continue;
    end if;

    update public.audit_webhooks set
      pending_request_id = private.post_audit_webhook(v_hook, jsonb_build_object(
        'source', 'passkey-x', 'type', 'audit_events', 'webhook_id', v_hook.id, 'tenant_id', v_hook.tenant_id,
        'sent_at', now(), 'first_sequence', v_hook.delivered_through + 1, 'last_sequence', v_through, 'events', v_events)),
      pending_through = v_through, pending_since = now(), last_attempt_at = now()
      where id = v_hook.id;
    v_sent := v_sent + 1;
  end loop;
  return v_sent;
end
$$;
revoke all on function private.deliver_audit_webhooks() from public, anon, authenticated;

-- Public invoker wrappers (project convention).
create or replace function public.create_audit_webhook(p_tenant_id uuid, p_name text, p_url text, p_event_prefixes text[] default '{}')
returns table (id uuid, secret text) language sql volatile security invoker set search_path = ''
as $$ select * from private.create_audit_webhook(p_tenant_id, p_name, p_url, p_event_prefixes) $$;
create or replace function public.update_audit_webhook(p_id uuid, p_enabled boolean default null, p_rotate_secret boolean default false)
returns text language sql volatile security invoker set search_path = ''
as $$ select private.update_audit_webhook(p_id, p_enabled, p_rotate_secret) $$;
create or replace function public.delete_audit_webhook(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.delete_audit_webhook(p_id) $$;
create or replace function public.test_audit_webhook(p_id uuid)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.test_audit_webhook(p_id) $$;

revoke all on function private.create_audit_webhook(uuid,text,text,text[]) from public, anon;
revoke all on function private.update_audit_webhook(uuid,boolean,boolean) from public, anon;
revoke all on function private.delete_audit_webhook(uuid) from public, anon;
revoke all on function private.test_audit_webhook(uuid) from public, anon;
grant execute on function private.create_audit_webhook(uuid,text,text,text[]) to authenticated;
grant execute on function private.update_audit_webhook(uuid,boolean,boolean) to authenticated;
grant execute on function private.delete_audit_webhook(uuid) to authenticated;
grant execute on function private.test_audit_webhook(uuid) to authenticated;
revoke all on function public.create_audit_webhook(uuid,text,text,text[]) from public, anon;
revoke all on function public.update_audit_webhook(uuid,boolean,boolean) from public, anon;
revoke all on function public.delete_audit_webhook(uuid) from public, anon;
revoke all on function public.test_audit_webhook(uuid) from public, anon;
grant execute on function public.create_audit_webhook(uuid,text,text,text[]) to authenticated;
grant execute on function public.update_audit_webhook(uuid,boolean,boolean) to authenticated;
grant execute on function public.delete_audit_webhook(uuid) to authenticated;
grant execute on function public.test_audit_webhook(uuid) to authenticated;

select cron.schedule('px-deliver-audit-webhooks', '* * * * *', $$select private.deliver_audit_webhooks()$$);
