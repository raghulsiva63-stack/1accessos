begin;

-- The v2.2 package catalog is the authority for the Stripe sandbox launch.
-- This backend-only policy table turns catalog packages into enforceable limits
-- without trusting price, trial, quantity, or entitlement values from a client.
create table private.billing_plan_policies (
  catalog_version text not null,
  plan_code text not null,
  active boolean not null default true,
  billing_model text not null check (billing_model in ('flat','per_seat')),
  min_quantity integer not null check (min_quantity > 0),
  max_quantity integer not null check (max_quantity >= min_quantity),
  fixed_max_members integer check (fixed_max_members is null or fixed_max_members > 0),
  max_workspaces integer not null check (max_workspaces > 0),
  max_devices integer check (max_devices is null or max_devices > 0),
  ai_credits_per_unit integer not null check (ai_credits_per_unit >= 0),
  automation_runs_per_unit integer not null check (automation_runs_per_unit >= 0),
  primary key (catalog_version, plan_code),
  foreign key (catalog_version, plan_code)
    references public.plan_catalog(catalog_version, plan_code) on delete restrict,
  check (
    (billing_model = 'flat' and min_quantity = 1 and max_quantity = 1 and fixed_max_members is not null)
    or (billing_model = 'per_seat' and fixed_max_members is null)
  )
);

create unique index billing_plan_policies_one_active_idx
  on private.billing_plan_policies(plan_code) where active;

revoke all on private.billing_plan_policies from public, anon, authenticated;
grant usage on schema private to service_role;
grant select on private.billing_plan_policies to service_role;

insert into private.billing_plan_policies(
  catalog_version, plan_code, billing_model, min_quantity, max_quantity,
  fixed_max_members, max_workspaces, max_devices, ai_credits_per_unit,
  automation_runs_per_unit
) values
  ('2026-09-v2.2','personal','flat',1,1,1,5,null,250,500),
  ('2026-09-v2.2','family','flat',1,1,6,20,null,800,1500),
  ('2026-09-v2.2','professional','flat',1,1,1,100,null,1000,3000),
  ('2026-09-v2.2','team','per_seat',3,50,null,100,null,600,2000),
  ('2026-09-v2.2','business','per_seat',5,500,null,500,null,2000,5000);

alter table public.tenant_entitlements
  drop constraint tenant_entitlements_plan_code_check;
alter table public.tenant_entitlements
  add constraint tenant_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','professional','team','business'));

alter table public.billing_subscriptions
  drop constraint billing_subscriptions_plan_code_check;
alter table public.billing_subscriptions
  add constraint billing_subscriptions_plan_code_check
  check (plan_code in ('personal','family','professional','team','business'));

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
  v_policy private.billing_plan_policies%rowtype;
begin
  insert into public.billing_events(
    stripe_event_id,event_type,stripe_api_version,payload_sha256,livemode,tenant_id
  ) values (
    p_event_id,p_event_type,p_api_version,p_payload_sha256,p_livemode,p_tenant_id
  ) on conflict (stripe_event_id) do nothing;

  get diagnostics v_inserted = row_count;
  if v_inserted = 0 then
    update public.billing_events set delivery_count = delivery_count + 1
    where stripe_event_id = p_event_id;
    return false;
  end if;

  if p_tenant_id is null or p_customer_id is null then
    update public.billing_events set outcome = 'ignored',processed_at = now()
    where stripe_event_id = p_event_id;
    return true;
  end if;

  if p_customer_id !~ '^cus_[A-Za-z0-9]+$' then
    raise exception 'invalid billing customer identifier' using errcode = '22023';
  end if;

  select stripe_customer_id into v_existing_customer
  from public.billing_customers where tenant_id = p_tenant_id;

  if v_existing_customer is not null and v_existing_customer <> p_customer_id then
    raise exception 'tenant billing customer mismatch' using errcode = '23514';
  end if;
  if exists (
    select 1 from public.billing_customers
    where stripe_customer_id = p_customer_id and tenant_id <> p_tenant_id
  ) then
    raise exception 'billing customer already belongs to another tenant' using errcode = '23514';
  end if;

  insert into public.billing_customers(tenant_id,stripe_customer_id,livemode)
  values (p_tenant_id,p_customer_id,p_livemode)
  on conflict (tenant_id) do update set updated_at = now()
  where public.billing_customers.stripe_customer_id = excluded.stripe_customer_id
    and public.billing_customers.livemode = excluded.livemode;

  if p_subscription_id is not null then
    if p_subscription_id !~ '^sub_[A-Za-z0-9]+$'
      or p_product_id !~ '^prod_[A-Za-z0-9]+$'
      or p_price_id !~ '^price_[A-Za-z0-9]+$'
      or p_billing_interval not in ('month','year')
      or p_currency not in ('inr','usd')
      or p_status not in ('trialing','active','past_due','unpaid','canceled','incomplete','incomplete_expired','paused')
      or p_quantity < 1 then
      raise exception 'invalid subscription state' using errcode = '22023';
    end if;

    select * into v_policy
    from private.billing_plan_policies
    where plan_code = p_plan_code and active;
    if not found
      or p_quantity < v_policy.min_quantity
      or p_quantity > v_policy.max_quantity then
      raise exception 'invalid subscription package or quantity' using errcode = '22023';
    end if;

    insert into public.billing_subscriptions(
      tenant_id,stripe_subscription_id,stripe_product_id,stripe_price_id,
      livemode,plan_code,billing_interval,currency,status,quantity,
      current_period_started_at,current_period_ends_at,cancel_at_period_end,canceled_at
    ) values (
      p_tenant_id,p_subscription_id,p_product_id,p_price_id,
      p_livemode,p_plan_code,p_billing_interval,p_currency,p_status,p_quantity,
      p_period_started_at,p_period_ends_at,p_cancel_at_period_end,p_canceled_at
    ) on conflict (tenant_id) do update set
      stripe_subscription_id=excluded.stripe_subscription_id,
      stripe_product_id=excluded.stripe_product_id,
      stripe_price_id=excluded.stripe_price_id,
      livemode=excluded.livemode,
      plan_code=excluded.plan_code,
      billing_interval=excluded.billing_interval,
      currency=excluded.currency,
      status=excluded.status,
      quantity=excluded.quantity,
      current_period_started_at=excluded.current_period_started_at,
      current_period_ends_at=excluded.current_period_ends_at,
      cancel_at_period_end=excluded.cancel_at_period_end,
      canceled_at=excluded.canceled_at,
      updated_at=now();

    if p_status in ('trialing','active','past_due') then
      v_effective_plan := p_plan_code;
      v_max_members := case
        when v_policy.billing_model = 'per_seat' then p_quantity
        else v_policy.fixed_max_members
      end;
      v_max_workspaces := v_policy.max_workspaces;
      v_max_devices := v_policy.max_devices;
      v_ai_credits := v_policy.ai_credits_per_unit * case
        when v_policy.billing_model = 'per_seat' then p_quantity else 1
      end;
      v_automation_runs := v_policy.automation_runs_per_unit * case
        when v_policy.billing_model = 'per_seat' then p_quantity else 1
      end;
    end if;

    insert into public.tenant_entitlements(
      tenant_id,plan_code,subscription_status,source,max_members,max_workspaces,
      max_devices,ai_credits_remaining,automation_runs_remaining,valid_until,updated_at
    ) values (
      p_tenant_id,v_effective_plan,p_status,
      case when v_effective_plan='free' then 'free' else 'stripe' end,
      v_max_members,v_max_workspaces,v_max_devices,v_ai_credits,v_automation_runs,
      p_period_ends_at,now()
    ) on conflict (tenant_id) do update set
      plan_code=excluded.plan_code,
      subscription_status=excluded.subscription_status,
      source=excluded.source,
      max_members=excluded.max_members,
      max_workspaces=excluded.max_workspaces,
      max_devices=excluded.max_devices,
      ai_credits_remaining=excluded.ai_credits_remaining,
      automation_runs_remaining=excluded.automation_runs_remaining,
      valid_until=excluded.valid_until,
      updated_at=now();
  end if;

  update public.billing_events set outcome='processed',processed_at=now()
  where stripe_event_id=p_event_id;
  return true;
end
$$;

revoke all on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) from public,anon,authenticated;
grant execute on function public.apply_stripe_billing_event(
  text,text,text,bytea,boolean,uuid,text,text,text,text,text,text,text,text,
  integer,timestamptz,timestamptz,boolean,timestamptz
) to service_role;

commit;
