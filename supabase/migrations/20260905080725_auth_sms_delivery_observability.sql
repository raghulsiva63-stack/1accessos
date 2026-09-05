-- Delivery evidence for Supabase Auth phone MFA messages sent through Sent.
-- OTPs, phone numbers, and message bodies are deliberately never persisted.

create table public.auth_sms_deliveries (
  id uuid primary key default gen_random_uuid(),
  auth_hook_id text not null unique check (char_length(auth_hook_id) between 8 and 255),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  payload_sha256 bytea not null check (octet_length(payload_sha256) = 32),
  provider text not null default 'sent' check (provider = 'sent'),
  provider_message_id text unique check (provider_message_id is null or char_length(provider_message_id) between 8 and 255),
  provider_request_id text check (provider_request_id is null or char_length(provider_request_id) <= 255),
  provider_status text not null default 'pending' check (char_length(provider_status) between 2 and 40),
  last_channel text check (last_channel is null or char_length(last_channel) <= 24),
  last_event_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index auth_sms_deliveries_user_idx on public.auth_sms_deliveries(auth_user_id, created_at desc);

create table public.auth_sms_delivery_events (
  id bigint generated always as identity primary key,
  delivery_id uuid not null references public.auth_sms_deliveries(id) on delete cascade,
  provider_message_id text not null check (char_length(provider_message_id) between 8 and 255),
  event_name text not null check (char_length(event_name) between 3 and 80),
  provider_status text not null check (char_length(provider_status) between 2 and 40),
  channel text check (channel is null or char_length(channel) <= 24),
  happened_at timestamptz not null,
  payload_sha256 bytea not null unique check (octet_length(payload_sha256) = 32),
  received_at timestamptz not null default now()
);

create index auth_sms_delivery_events_delivery_idx on public.auth_sms_delivery_events(delivery_id, happened_at desc);

alter table public.auth_sms_deliveries enable row level security;
alter table public.auth_sms_delivery_events enable row level security;

create policy auth_sms_deliveries_browser_deny
on public.auth_sms_deliveries for all to anon, authenticated
using (false) with check (false);

create policy auth_sms_delivery_events_browser_deny
on public.auth_sms_delivery_events for all to anon, authenticated
using (false) with check (false);

revoke all on table public.auth_sms_deliveries from public, anon, authenticated;
revoke all on table public.auth_sms_delivery_events from public, anon, authenticated;
revoke all on sequence public.auth_sms_delivery_events_id_seq from public, anon, authenticated;
grant all on table public.auth_sms_deliveries to service_role;
grant all on table public.auth_sms_delivery_events to service_role;
grant all on sequence public.auth_sms_delivery_events_id_seq to service_role;

create or replace function public.apply_sent_sms_delivery_event(
  p_provider_message_id text,
  p_event_name text,
  p_provider_status text,
  p_channel text,
  p_happened_at timestamptz,
  p_payload_sha256 bytea
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  target_id uuid;
  inserted_count integer;
begin
  if p_provider_message_id is null or char_length(p_provider_message_id) not between 8 and 255
     or p_event_name is null or char_length(p_event_name) not between 3 and 80
     or p_provider_status is null or char_length(p_provider_status) not between 2 and 40
     or p_happened_at is null or p_payload_sha256 is null
     or octet_length(p_payload_sha256) <> 32 then
    raise exception 'invalid Sent delivery event' using errcode = '22023';
  end if;

  select id into target_id
  from public.auth_sms_deliveries
  where provider_message_id = p_provider_message_id;

  -- A shared Sent account may emit unrelated messages. Acknowledge them without
  -- copying recipient or content data into the Passkey-X database.
  if target_id is null then return false; end if;

  insert into public.auth_sms_delivery_events(
    delivery_id, provider_message_id, event_name, provider_status,
    channel, happened_at, payload_sha256
  ) values (
    target_id, p_provider_message_id, p_event_name, p_provider_status,
    nullif(p_channel, ''), p_happened_at, p_payload_sha256
  ) on conflict (payload_sha256) do nothing;
  get diagnostics inserted_count = row_count;

  if inserted_count = 0 then return false; end if;

  update public.auth_sms_deliveries
  set provider_status = p_provider_status,
      last_channel = nullif(p_channel, ''),
      last_event_at = p_happened_at,
      updated_at = now()
  where id = target_id
    and (last_event_at is null or p_happened_at >= last_event_at);

  return true;
end
$$;

revoke all on function public.apply_sent_sms_delivery_event(text,text,text,text,timestamptz,bytea) from public, anon, authenticated;
grant execute on function public.apply_sent_sms_delivery_event(text,text,text,text,timestamptz,bytea) to service_role;

comment on table public.auth_sms_deliveries is
  'Backend-only mapping from a signed Supabase Auth SMS hook to Sent delivery evidence; contains no phone number, OTP, or message body.';
comment on table public.auth_sms_delivery_events is
  'Append-only, deduplicated Sent status evidence for Passkey-X authentication SMS messages; contains no recipient or content.';
comment on function public.apply_sent_sms_delivery_event(text,text,text,text,timestamptz,bytea) is
  'Service-role-only idempotent projection for verified Sent webhook events; ignores messages not mapped to a Passkey-X Auth hook.';
