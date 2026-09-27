-- Audit webhook delivery through an SSRF-safe relay.
-- The database no longer posts to customer URLs directly. It queues each signed
-- request in a private outbox and calls the audit-relay edge function with a
-- one-time token; the relay resolves DNS, blocks private/loopback/link-local
-- destinations and forwards the exact signed body. Event filters now match
-- literal prefixes.

create table if not exists private.app_settings (
  key text primary key,
  value text not null
);
revoke all on private.app_settings from public, anon, authenticated;
-- Project-specific: the relay endpoint of this Supabase project.
insert into private.app_settings (key, value)
values ('audit_relay_url', 'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/audit-relay')
on conflict (key) do nothing;

create table if not exists private.audit_webhook_outbox (
  id bigint generated always as identity primary key,
  webhook_id uuid not null,
  token_hash bytea not null,
  url text not null,
  headers jsonb not null,
  body text not null,
  created_at timestamptz not null default now()
);
create index if not exists audit_webhook_outbox_created_idx on private.audit_webhook_outbox (created_at);
revoke all on private.audit_webhook_outbox from public, anon, authenticated;

-- Builds and signs one request, queues it and asks the relay to deliver it.
-- Signature: HMAC-SHA256(secret, "<timestamp>.<body>") over the exact body text sent.
create or replace function private.post_audit_webhook(p_hook public.audit_webhooks, p_payload jsonb)
returns bigint
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_ts text := extract(epoch from now())::bigint::text;
  v_body text := p_payload::text;
  v_signature text := encode(extensions.hmac(v_ts || '.' || v_body, p_hook.secret, 'sha256'), 'hex');
  v_token text := encode(extensions.gen_random_bytes(32), 'hex');
  v_relay text := (select s.value from private.app_settings s where s.key = 'audit_relay_url');
  v_outbox bigint;
begin
  if v_relay is null then raise exception 'audit relay is not configured' using errcode = 'P0001'; end if;
  insert into private.audit_webhook_outbox (webhook_id, token_hash, url, headers, body)
  values (p_hook.id, extensions.digest(v_token, 'sha256'), p_hook.url, jsonb_build_object(
      'Content-Type', 'application/json',
      'User-Agent', 'Passkey-X-Webhooks/1',
      'X-PasskeyX-Webhook', p_hook.id::text,
      'X-PasskeyX-Timestamp', v_ts,
      'X-PasskeyX-Signature', 'v1=' || v_signature), v_body)
  returning id into v_outbox;
  return net.http_post(
    url := v_relay,
    body := jsonb_build_object('id', v_outbox, 'token', v_token),
    headers := jsonb_build_object('Content-Type', 'application/json'),
    timeout_milliseconds := 12000);
end
$$;
revoke all on function private.post_audit_webhook(public.audit_webhooks, jsonb) from public, anon, authenticated;

-- One-time claim used by the relay (service role only).
create or replace function private.claim_audit_webhook_delivery(p_id bigint, p_token text)
returns table (url text, headers jsonb, body text)
language sql volatile security definer set search_path = ''
as $$
  delete from private.audit_webhook_outbox o
  where o.id = p_id and o.token_hash = extensions.digest(p_token, 'sha256')
    and o.created_at > now() - interval '10 minutes'
  returning o.url, o.headers, o.body
$$;
revoke all on function private.claim_audit_webhook_delivery(bigint, text) from public, anon, authenticated;
grant execute on function private.claim_audit_webhook_delivery(bigint, text) to service_role;

create or replace function public.claim_audit_webhook_delivery(p_id bigint, p_token text)
returns table (url text, headers jsonb, body text)
language sql volatile security invoker set search_path = ''
as $$ select * from private.claim_audit_webhook_delivery(p_id, p_token) $$;
revoke all on function public.claim_audit_webhook_delivery(bigint, text) from public, anon, authenticated;
grant execute on function public.claim_audit_webhook_delivery(bigint, text) to service_role;
grant usage on schema private to service_role;

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
      and (cardinality(v_hook.event_prefixes) = 0 or exists (select 1 from unnest(v_hook.event_prefixes) prefix where left(e.action, char_length(prefix)) = prefix));

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
  delete from private.audit_webhook_outbox o where o.created_at < now() - interval '1 hour';
  return v_sent;
end
$$;
revoke all on function private.deliver_audit_webhooks() from public, anon, authenticated;
