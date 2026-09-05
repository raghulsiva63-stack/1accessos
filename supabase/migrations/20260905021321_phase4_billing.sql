begin;

-- Phase 4 commercial SaaS boundary. Billing metadata is tenant-scoped and
-- contains no vault ciphertext, decrypted fields, master keys, or recovery data.
create table public.tenant_entitlements (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  plan_code text not null default 'free'
    check (plan_code in ('free','personal','family','team')),
  subscription_status text not null default 'none'
    check (subscription_status in ('none','trialing','active','past_due','unpaid','canceled','incomplete','incomplete_expired','paused')),
  source text not null default 'free'
    check (source in ('free','stripe','manual')),
  max_members integer not null default 1 check (max_members > 0),
  max_workspaces integer not null default 1 check (max_workspaces > 0),
  max_devices integer check (max_devices is null or max_devices > 0),
  ai_credits_remaining integer not null default 20 check (ai_credits_remaining >= 0),
  automation_runs_remaining integer not null default 50 check (automation_runs_remaining >= 0),
  valid_until timestamptz,
  updated_at timestamptz not null default now()
);

create table public.billing_customers (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  provider text not null default 'stripe' check (provider = 'stripe'),
  stripe_customer_id text not null unique
    check (stripe_customer_id ~ '^cus_[A-Za-z0-9]+$'),
  livemode boolean not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.billing_subscriptions (
  tenant_id uuid primary key references public.billing_customers(tenant_id) on delete cascade,
  stripe_subscription_id text not null unique
    check (stripe_subscription_id ~ '^sub_[A-Za-z0-9]+$'),
  stripe_product_id text not null
    check (stripe_product_id ~ '^prod_[A-Za-z0-9]+$'),
  stripe_price_id text not null
    check (stripe_price_id ~ '^price_[A-Za-z0-9]+$'),
  livemode boolean not null,
  plan_code text not null check (plan_code in ('personal','family','team')),
  billing_interval text not null check (billing_interval in ('month','year')),
  currency text not null check (currency in ('inr','usd')),
  status text not null
    check (status in ('trialing','active','past_due','unpaid','canceled','incomplete','incomplete_expired','paused')),
  quantity integer not null default 1 check (quantity > 0),
  current_period_started_at timestamptz,
  current_period_ends_at timestamptz,
  cancel_at_period_end boolean not null default false,
  canceled_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (current_period_ends_at is null or current_period_started_at is null or current_period_ends_at > current_period_started_at)
);

create table public.billing_events (
  stripe_event_id text primary key check (stripe_event_id ~ '^evt_[A-Za-z0-9]+$'),
  event_type text not null check (length(event_type) between 3 and 120),
  stripe_api_version text,
  payload_sha256 bytea not null check (octet_length(payload_sha256) = 32),
  livemode boolean not null,
  tenant_id uuid references public.tenants(id) on delete set null,
  outcome text not null default 'received'
    check (outcome in ('received','processed','ignored')),
  delivery_count integer not null default 1 check (delivery_count > 0),
  received_at timestamptz not null default now(),
  processed_at timestamptz
);

create index billing_subscriptions_status_period_idx
  on public.billing_subscriptions(status, current_period_ends_at)
  where status in ('trialing','active','past_due');
create index billing_events_received_idx
  on public.billing_events(received_at desc);
create index billing_events_tenant_idx
  on public.billing_events(tenant_id, received_at desc)
  where tenant_id is not null;

alter table public.tenant_entitlements enable row level security;
alter table public.billing_customers enable row level security;
alter table public.billing_subscriptions enable row level security;
alter table public.billing_events enable row level security;

revoke all on public.tenant_entitlements from anon, authenticated;
revoke all on public.billing_customers from anon, authenticated;
revoke all on public.billing_subscriptions from anon, authenticated;
revoke all on public.billing_events from anon, authenticated;
grant select on public.tenant_entitlements to authenticated;
grant select, insert, update, delete on public.tenant_entitlements to service_role;
grant select, insert, update, delete on public.billing_customers to service_role;
grant select, insert, update, delete on public.billing_subscriptions to service_role;
grant select, insert, update, delete on public.billing_events to service_role;

create policy tenant_entitlements_read_member
on public.tenant_entitlements for select to authenticated
using (
  (select private.has_tenant_role(
    tenant_id,
    array['owner','admin','member','auditor']
  ))
);

create or replace function private.provision_free_tenant_entitlement()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.tenant_entitlements(tenant_id)
  values (new.id)
  on conflict (tenant_id) do nothing;
  return new;
end
$$;

create trigger tenant_provision_free_entitlement
after insert on public.tenants
for each row execute function private.provision_free_tenant_entitlement();

insert into public.tenant_entitlements(tenant_id)
select id from public.tenants
on conflict (tenant_id) do nothing;

revoke all on function private.provision_free_tenant_entitlement()
from public, anon, authenticated;

-- The webhook function calls this transaction boundary with a backend-only
-- Supabase secret key. It is SECURITY INVOKER and unavailable to browsers.
create or replace function public.apply_stripe_billing_event(
  p_event_id text,
  p_event_type text,
  p_api_version text,
  p_payload_sha256 bytea,
  p_livemode boolean,
  p_tenant_id uuid,
  p_customer_id text,
  p_subscription_id text default null,
  p_product_id text default null,
  p_price_id text default null,
  p_plan_code text default null,
  p_billing_interval text default null,
  p_currency text default null,
  p_status text default null,
  p_quantity integer default 1,
  p_period_started_at timestamptz default null,
  p_period_ends_at timestamptz default null,
  p_cancel_at_period_end boolean default false,
  p_canceled_at timestamptz default null
) returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_inserted integer;
  v_existing_customer text;
  v_effective_plan text := 'free';
  v_max_members integer := 1;
  v_max_workspaces integer := 1;
  v_max_devices integer := 2;
  v_ai_credits integer := 20;
  v_automation_runs integer := 50;
begin
  insert into public.billing_events(
    stripe_event_id, event_type, stripe_api_version, payload_sha256,
    livemode, tenant_id
  ) values (
    p_event_id, p_event_type, p_api_version, p_payload_sha256,
    p_livemode, p_tenant_id
  ) on conflict (stripe_event_id) do nothing;

  get diagnostics v_inserted = row_count;
  if v_inserted = 0 then
    update public.billing_events
      set delivery_count = delivery_count + 1
      where stripe_event_id = p_event_id;
    return false;
  end if;

  if p_tenant_id is null or p_customer_id is null then
    update public.billing_events
      set outcome = 'ignored', processed_at = now()
      where stripe_event_id = p_event_id;
    return true;
  end if;

  if p_customer_id !~ '^cus_[A-Za-z0-9]+$' then
    raise exception 'invalid billing customer identifier' using errcode = '22023';
  end if;

  select stripe_customer_id into v_existing_customer
  from public.billing_customers
  where tenant_id = p_tenant_id;

  if v_existing_customer is not null and v_existing_customer <> p_customer_id then
    raise exception 'tenant billing customer mismatch' using errcode = '23514';
  end if;

  if exists (
    select 1 from public.billing_customers
    where stripe_customer_id = p_customer_id and tenant_id <> p_tenant_id
  ) then
    raise exception 'billing customer already belongs to another tenant' using errcode = '23514';
  end if;

  insert into public.billing_customers(
    tenant_id, stripe_customer_id, livemode
  ) values (
    p_tenant_id, p_customer_id, p_livemode
  ) on conflict (tenant_id) do update
    set updated_at = now()
    where public.billing_customers.stripe_customer_id = excluded.stripe_customer_id
      and public.billing_customers.livemode = excluded.livemode;

  if p_subscription_id is not null then
    if p_subscription_id !~ '^sub_[A-Za-z0-9]+$'
      or p_product_id !~ '^prod_[A-Za-z0-9]+$'
      or p_price_id !~ '^price_[A-Za-z0-9]+$'
      or p_plan_code not in ('personal','family','team')
      or p_billing_interval not in ('month','year')
      or p_currency not in ('inr','usd')
      or p_status not in ('trialing','active','past_due','unpaid','canceled','incomplete','incomplete_expired','paused')
      or p_quantity < 1 then
      raise exception 'invalid subscription state' using errcode = '22023';
    end if;

    insert into public.billing_subscriptions(
      tenant_id, stripe_subscription_id, stripe_product_id, stripe_price_id,
      livemode, plan_code, billing_interval, currency, status, quantity,
      current_period_started_at, current_period_ends_at,
      cancel_at_period_end, canceled_at
    ) values (
      p_tenant_id, p_subscription_id, p_product_id, p_price_id,
      p_livemode, p_plan_code, p_billing_interval, p_currency, p_status, p_quantity,
      p_period_started_at, p_period_ends_at,
      p_cancel_at_period_end, p_canceled_at
    ) on conflict (tenant_id) do update set
      stripe_subscription_id = excluded.stripe_subscription_id,
      stripe_product_id = excluded.stripe_product_id,
      stripe_price_id = excluded.stripe_price_id,
      livemode = excluded.livemode,
      plan_code = excluded.plan_code,
      billing_interval = excluded.billing_interval,
      currency = excluded.currency,
      status = excluded.status,
      quantity = excluded.quantity,
      current_period_started_at = excluded.current_period_started_at,
      current_period_ends_at = excluded.current_period_ends_at,
      cancel_at_period_end = excluded.cancel_at_period_end,
      canceled_at = excluded.canceled_at,
      updated_at = now();

    if p_status in ('trialing','active','past_due') then
      v_effective_plan := p_plan_code;
      case p_plan_code
        when 'personal' then
          v_max_members := 1; v_max_workspaces := 5; v_max_devices := null;
          v_ai_credits := 200; v_automation_runs := 500;
        when 'family' then
          v_max_members := 6; v_max_workspaces := 20; v_max_devices := null;
          v_ai_credits := 500; v_automation_runs := 1500;
        when 'team' then
          v_max_members := 50; v_max_workspaces := 100; v_max_devices := null;
          v_ai_credits := 2000; v_automation_runs := 10000;
      end case;
    end if;

    insert into public.tenant_entitlements(
      tenant_id, plan_code, subscription_status, source,
      max_members, max_workspaces, max_devices,
      ai_credits_remaining, automation_runs_remaining,
      valid_until, updated_at
    ) values (
      p_tenant_id, v_effective_plan, p_status,
      case when v_effective_plan = 'free' then 'free' else 'stripe' end,
      v_max_members, v_max_workspaces, v_max_devices,
      v_ai_credits, v_automation_runs,
      p_period_ends_at, now()
    ) on conflict (tenant_id) do update set
      plan_code = excluded.plan_code,
      subscription_status = excluded.subscription_status,
      source = excluded.source,
      max_members = excluded.max_members,
      max_workspaces = excluded.max_workspaces,
      max_devices = excluded.max_devices,
      ai_credits_remaining = greatest(
        public.tenant_entitlements.ai_credits_remaining,
        excluded.ai_credits_remaining
      ),
      automation_runs_remaining = greatest(
        public.tenant_entitlements.automation_runs_remaining,
        excluded.automation_runs_remaining
      ),
      valid_until = excluded.valid_until,
      updated_at = now();
  end if;

  update public.billing_events
    set outcome = 'processed', processed_at = now()
    where stripe_event_id = p_event_id;
  return true;
end
$$;

revoke all on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) from public, anon, authenticated;
grant execute on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) to service_role;

commit;

