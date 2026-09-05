begin;

alter table public.billing_customers
  add constraint billing_customers_tenant_mode_key unique (tenant_id, livemode);

alter table public.billing_subscriptions
  add constraint billing_subscriptions_tenant_mode_fkey
  foreign key (tenant_id, livemode)
  references public.billing_customers(tenant_id, livemode)
  on delete cascade;

create or replace function private.enforce_billing_event_mode()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.tenant_id is not null and exists (
    select 1 from public.billing_customers bc
    where bc.tenant_id = new.tenant_id
      and bc.livemode <> new.livemode
  ) then
    raise exception 'billing event mode does not match tenant customer'
      using errcode = '23514';
  end if;
  return new;
end
$$;

create trigger billing_event_mode_guard
before insert on public.billing_events
for each row execute function private.enforce_billing_event_mode();

revoke all on function private.enforce_billing_event_mode()
from public, anon, authenticated;

-- Adds payload-integrity checking around the original atomic state transition.
-- The original function remains backend-only; browsers cannot call either RPC.
create or replace function public.apply_stripe_billing_event_checked(
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
  v_applied boolean;
begin
  v_applied := public.apply_stripe_billing_event(
    p_event_id, p_event_type, p_api_version, p_payload_sha256, p_livemode,
    p_tenant_id, p_customer_id, p_subscription_id, p_product_id, p_price_id,
    p_plan_code, p_billing_interval, p_currency, p_status, p_quantity,
    p_period_started_at, p_period_ends_at, p_cancel_at_period_end, p_canceled_at
  );

  if not v_applied and not exists (
    select 1 from public.billing_events be
    where be.stripe_event_id = p_event_id
      and be.event_type = p_event_type
      and be.payload_sha256 = p_payload_sha256
      and be.livemode = p_livemode
  ) then
    raise exception 'duplicate billing event integrity mismatch'
      using errcode = '23514';
  end if;
  return v_applied;
end
$$;

revoke all on function public.apply_stripe_billing_event_checked(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) from public, anon, authenticated;
grant execute on function public.apply_stripe_billing_event_checked(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) to service_role;

commit;
