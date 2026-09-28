-- Exported from production supabase_migrations.schema_migrations (20260907100653_hosted_ai_credit_metering).
begin;

-- A hosted AI request consumes exactly one tenant credit before provider work
-- starts. The row lock makes the quota check and decrement atomic; any later
-- statement failure rolls the transaction back.
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
  if v_actor is null or not private.can_view_runtime_tenant(p_tenant_id)
    or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'tenant access required' using errcode = '42501';
  end if;
  if p_use_case not in ('security_posture','access_review','spend_review','incident_summary')
    or octet_length(p_prompt_sha256) <> 32
    or not (p_context_categories <@ array['tenant_counts','security_counts','spend_totals','access_risk_counts']::text[]) then
    raise exception 'invalid AI request' using errcode = '22023';
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
  'Authenticated hosted-AI admission worker with aggregate-only input validation, hourly rate limit, and atomic tenant credit consumption.';

commit;
