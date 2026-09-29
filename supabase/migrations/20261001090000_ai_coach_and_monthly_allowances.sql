begin;

-- 1. AI Security Coach for every plan.
-- Plans below Business advertise monthly AI credits, but the only hosted AI feature was the
-- Business advisor. The new 'vault_health' use case lets any member of a workspace spend one
-- credit on advice built from on-device vault-health totals (counts only: no titles, sites,
-- usernames or passwords ever leave the device).
alter table public.ai_assistant_requests drop constraint if exists ai_assistant_requests_use_case_check;
alter table public.ai_assistant_requests add constraint ai_assistant_requests_use_case_check
  check (use_case in ('security_posture','access_review','spend_review','incident_summary','vault_health'));
alter table public.ai_assistant_requests drop constraint if exists ai_assistant_requests_context_categories_check;
alter table public.ai_assistant_requests add constraint ai_assistant_requests_context_categories_check
  check (context_categories <@ array['tenant_counts','security_counts','spend_totals','access_risk_counts','vault_health_counts']::text[]);

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
    -- Personal coaching: any active member of the workspace's tenant, on any plan with credits.
    if not private.has_tenant_role(p_tenant_id,array['owner','admin','member','auditor']) then
      raise exception 'tenant access required' using errcode = '42501';
    end if;
    if octet_length(p_prompt_sha256) <> 32 or p_context_categories is distinct from array['vault_health_counts']::text[] then
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

comment on function private.begin_ai_assistant_request(uuid,text,bytea,text[]) is
  'Hosted-AI admission: Business aggregate advisor, or the all-plans vault-health coach (on-device counts only). Hourly rate limit and atomic tenant credit consumption.';

-- A request that fails at the AI provider gives its credit back, so users are only charged for
-- advice they actually receive. Only the requester's own still-open request can be completed.
create or replace function private.complete_ai_assistant_request(
  p_request_id uuid,p_status text,p_input_tokens integer,p_output_tokens integer,p_failure_code text default null
) returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_tenant uuid;
begin
  if v_actor is null or p_status not in ('completed','blocked','failed')
    or coalesce(p_input_tokens,0) not between 0 and 1000000
    or coalesce(p_output_tokens,0) not between 0 and 1000000
    or (p_failure_code is not null and p_failure_code !~ '^[a-z0-9_]{2,64}$') then
    raise exception 'invalid AI completion' using errcode = '22023';
  end if;
  update public.ai_assistant_requests set status = p_status,input_tokens = p_input_tokens,
    output_tokens = p_output_tokens,failure_code = p_failure_code,completed_at = now()
    where id = p_request_id and requested_by = v_actor and status = 'accepted'
    returning tenant_id into v_tenant;
  if v_tenant is null then return false; end if;
  if p_status = 'failed' then
    update public.tenant_entitlements
      set ai_credits_remaining = ai_credits_remaining + 1,updated_at = now()
      where tenant_id = v_tenant;
  end if;
  return true;
end
$$;

-- 2. Monthly allowances.
-- The catalog promises AI credits and automation runs "each month", but credits were only
-- refilled by Stripe events (so never for Free, and only yearly for annual plans).
-- On the 1st of every month, refill every tenant to its plan allowance.
create or replace function private.refill_monthly_allowances()
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_count integer;
begin
  update public.tenant_entitlements entitlement set
    ai_credits_remaining = case
      when entitlement.plan_code = 'free' or policy.plan_code is null then 20
      else policy.ai_credits_per_unit * case when policy.billing_model = 'per_seat'
        then greatest(coalesce(subscription.quantity, policy.min_quantity), policy.min_quantity) else 1 end
    end,
    automation_runs_remaining = case
      when entitlement.plan_code = 'free' or policy.plan_code is null then 50
      else policy.automation_runs_per_unit * case when policy.billing_model = 'per_seat'
        then greatest(coalesce(subscription.quantity, policy.min_quantity), policy.min_quantity) else 1 end
    end,
    updated_at = now()
  from public.tenant_entitlements current_row
  left join private.billing_plan_policies policy
    on policy.plan_code = current_row.plan_code and policy.active
  left join public.billing_subscriptions subscription
    on subscription.tenant_id = current_row.tenant_id
  where entitlement.tenant_id = current_row.tenant_id
    and (
      entitlement.plan_code = 'free'
      or (entitlement.source = 'stripe' and entitlement.subscription_status in ('trialing','active','past_due'))
    );
  get diagnostics v_count = row_count;
  return v_count;
end
$$;

revoke all on function private.refill_monthly_allowances() from public,anon,authenticated;
grant execute on function private.refill_monthly_allowances() to service_role;

do $schedule$
declare v_job_id bigint;
begin
  select jobid into v_job_id from cron.job where jobname = 'px-refill-monthly-allowances';
  if v_job_id is not null then perform cron.unschedule(v_job_id); end if;
  perform cron.schedule('px-refill-monthly-allowances','5 0 1 * *','select private.refill_monthly_allowances();');
end
$schedule$;

-- The published 2026-09-v2.2 catalog is immutable, so its wording stays as sold: the "hosted AI
-- credits" it lists are now spent by the AI Security Coach on every plan, and are refilled monthly.

commit;
