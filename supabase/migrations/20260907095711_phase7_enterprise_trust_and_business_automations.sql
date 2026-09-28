-- Exported from production supabase_migrations.schema_migrations (20260907095711_phase7_enterprise_trust_and_business_automations).
begin;

-- Business automations and the Phase 7 enterprise trust control plane operate
-- only on tenant metadata. Vault plaintext, recovery material, connector
-- credentials, raw prompts, and provider response bodies are prohibited.

alter table public.tenant_entitlements
  drop constraint if exists tenant_entitlements_plan_code_check;
alter table public.tenant_entitlements
  add constraint tenant_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','professional','team','business','enterprise'));

create or replace function private.has_business_entitlement(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1
    from public.tenant_entitlements entitlement
    join public.tenants tenant on tenant.id = entitlement.tenant_id
    where entitlement.tenant_id = target_tenant
      and tenant.kind = 'organization'
      and entitlement.plan_code in ('business','enterprise')
      and (entitlement.valid_until is null or entitlement.valid_until > now())
      and (
        entitlement.source = 'manual'
        or (entitlement.source = 'stripe' and entitlement.subscription_status in ('trialing','active','past_due'))
      )
  )
$$;

create or replace function private.has_enterprise_entitlement(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1
    from public.tenant_entitlements entitlement
    join public.tenants tenant on tenant.id = entitlement.tenant_id
    where entitlement.tenant_id = target_tenant
      and tenant.kind = 'organization'
      and entitlement.plan_code = 'enterprise'
      and entitlement.source = 'manual'
      and entitlement.subscription_status in ('trialing','active')
      and (entitlement.valid_until is null or entitlement.valid_until > now())
  )
$$;

revoke all on function private.has_business_entitlement(uuid),
  private.has_enterprise_entitlement(uuid) from public,anon;
grant execute on function private.has_business_entitlement(uuid),
  private.has_enterprise_entitlement(uuid) to authenticated;

-- Existing lifecycle workflow rows become the durable Business automation
-- definition store. Only fixed templates may be created through browser RPCs.
alter table public.lifecycle_workflows
  drop constraint if exists lifecycle_workflows_trigger_type_check;
alter table public.lifecycle_workflows
  add constraint lifecycle_workflows_trigger_type_check
  check (trigger_type in (
    'joiner','mover','leaver','access_review','license_reclaim','renewal_notice',
    'budget_threshold','device_posture','security_signal','schedule'
  ));
alter table public.lifecycle_workflows
  add column template_key text
    check (template_key is null or template_key ~ '^[a-z][a-z0-9_]{2,63}$'),
  add column schedule_interval_minutes integer
    check (schedule_interval_minutes is null or schedule_interval_minutes between 15 and 525600),
  add column last_run_at timestamptz,
  add column next_run_at timestamptz,
  add column last_run_status text
    check (last_run_status is null or last_run_status in ('completed','awaiting_approval','approved','cancelled','failed'));

alter table public.lifecycle_workflow_runs
  add column requested_by uuid references public.identities(id) on delete set null,
  add column credits_charged integer not null default 1 check (credits_charged in (0,1)),
  add constraint lifecycle_workflow_runs_tenant_id_id_key unique (tenant_id,id);

create table public.automation_action_items (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workflow_id uuid not null,
  run_id uuid not null,
  action_kind text not null check (action_kind in ('notify','create_review','propose_reclaim','propose_deprovision','apply_tag','webhook')),
  title text not null check (length(title) between 3 and 180),
  status text not null default 'open' check (status in ('open','completed','dismissed')),
  requires_approval boolean not null default false,
  summary jsonb not null default '{}'::jsonb
    check (jsonb_typeof(summary) = 'object' and octet_length(convert_to(summary::text,'UTF8')) <= 16384),
  created_by uuid references public.identities(id) on delete set null,
  resolved_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  unique (tenant_id,run_id),
  foreign key (tenant_id,workflow_id) references public.lifecycle_workflows(tenant_id,id) on delete restrict,
  foreign key (tenant_id,run_id) references public.lifecycle_workflow_runs(tenant_id,id) on delete restrict,
  check ((status = 'open') = (resolved_at is null)),
  check (not lower(summary::text) ~ '"(password|secret|token|private_key|recovery_key|credential|vault_content|raw_prompt|command_output)"[[:space:]]*:')
);

create table public.business_automation_events (
  sequence bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  run_id uuid not null,
  actor_identity_id uuid references public.identities(id) on delete set null,
  event_type text not null check (event_type in ('created','approval_requested','approved','denied','completed','failed')),
  event_metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(event_metadata) = 'object' and octet_length(convert_to(event_metadata::text,'UTF8')) <= 16384),
  previous_hash bytea,
  event_hash bytea not null check (octet_length(event_hash) = 32),
  occurred_at timestamptz not null default now(),
  foreign key (tenant_id,run_id) references public.lifecycle_workflow_runs(tenant_id,id) on delete restrict,
  check (not lower(event_metadata::text) ~ '"(password|secret|token|private_key|recovery_key|credential|vault_content|raw_prompt|command_output)"[[:space:]]*:')
);

create index lifecycle_workflows_due_idx on public.lifecycle_workflows(next_run_at)
  where enabled and next_run_at is not null;
create index lifecycle_workflow_runs_requested_by_idx on public.lifecycle_workflow_runs(requested_by)
  where requested_by is not null;
create index automation_action_items_tenant_status_idx on public.automation_action_items(tenant_id,status,created_at desc);
create index automation_action_items_workflow_idx on public.automation_action_items(tenant_id,workflow_id);
create index automation_action_items_run_idx on public.automation_action_items(run_id);
create index automation_action_items_created_by_idx on public.automation_action_items(created_by)
  where created_by is not null;
create index automation_action_items_resolved_by_idx on public.automation_action_items(resolved_by)
  where resolved_by is not null;
create index business_automation_events_tenant_idx on public.business_automation_events(tenant_id,sequence desc);
create index business_automation_events_run_idx on public.business_automation_events(tenant_id,run_id,sequence);
create index business_automation_events_actor_idx on public.business_automation_events(actor_identity_id)
  where actor_identity_id is not null;

alter table public.automation_action_items enable row level security;
alter table public.business_automation_events enable row level security;

revoke all on public.automation_action_items,public.business_automation_events from public,anon,authenticated;
grant select on public.automation_action_items,public.business_automation_events to authenticated;
grant select,insert,update,delete on public.automation_action_items,public.business_automation_events to service_role;

create policy automation_action_items_read on public.automation_action_items for select to authenticated
  using ((select private.can_view_phase5_tenant(tenant_id)));
create policy business_automation_events_read on public.business_automation_events for select to authenticated
  using ((select private.can_view_phase5_tenant(tenant_id)));

-- Workflow definitions and run summaries are modified only by the guarded
-- RPCs below. This closes the former direct browser-write path.
revoke insert,update,delete on public.lifecycle_workflows,public.lifecycle_workflow_runs from authenticated;
drop policy if exists lifecycle_workflows_manage on public.lifecycle_workflows;
drop policy if exists lifecycle_workflows_insert on public.lifecycle_workflows;
drop policy if exists lifecycle_workflows_update on public.lifecycle_workflows;
drop policy if exists lifecycle_workflows_delete on public.lifecycle_workflows;
drop policy if exists lifecycle_workflow_runs_manage on public.lifecycle_workflow_runs;
drop policy if exists lifecycle_workflow_runs_insert on public.lifecycle_workflow_runs;
drop policy if exists lifecycle_workflow_runs_update on public.lifecycle_workflow_runs;
drop policy if exists lifecycle_workflow_runs_delete on public.lifecycle_workflow_runs;

create or replace function private.append_business_automation_event(
  p_tenant_id uuid,p_run_id uuid,p_actor_identity_id uuid,p_event_type text,p_metadata jsonb
) returns bigint language plpgsql security definer set search_path = ''
as $$
declare v_previous bytea; v_hash bytea; v_sequence bigint; v_occurred_at timestamptz := clock_timestamp();
begin
  if p_event_type not in ('created','approval_requested','approved','denied','completed','failed')
    or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb)) <> 'object'
    or octet_length(convert_to(coalesce(p_metadata,'{}'::jsonb)::text,'UTF8')) > 16384 then
    raise exception 'invalid automation event' using errcode = '22023';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('business-automation:' || p_tenant_id::text,17));
  select event_hash into v_previous from public.business_automation_events
    where tenant_id = p_tenant_id order by sequence desc limit 1;
  v_hash := extensions.digest(convert_to(concat_ws('|',p_tenant_id::text,p_run_id::text,
    coalesce(p_actor_identity_id::text,''),p_event_type,coalesce(p_metadata,'{}'::jsonb)::text,
    coalesce(encode(v_previous,'hex'),''),v_occurred_at::text),'UTF8'),'sha256');
  insert into public.business_automation_events(
    tenant_id,run_id,actor_identity_id,event_type,event_metadata,previous_hash,event_hash,occurred_at
  ) values (
    p_tenant_id,p_run_id,p_actor_identity_id,p_event_type,coalesce(p_metadata,'{}'::jsonb),v_previous,v_hash,v_occurred_at
  ) returning sequence into v_sequence;
  return v_sequence;
end
$$;

create or replace function private.execute_business_automation(
  p_workflow_id uuid,p_idempotency_key text,p_trigger_source text,p_actor_identity_id uuid
) returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_workflow public.lifecycle_workflows%rowtype;
  v_existing public.lifecycle_workflow_runs%rowtype;
  v_entitlement public.tenant_entitlements%rowtype;
  v_run_id uuid;
  v_action_id uuid;
  v_status text;
  v_result jsonb;
begin
  if p_idempotency_key !~ '^[A-Za-z0-9._:-]{8,200}$'
    or p_trigger_source not in ('manual','schedule','event') then
    raise exception 'invalid automation invocation' using errcode = '22023';
  end if;
  select * into v_workflow from public.lifecycle_workflows workflow
    where workflow.id = p_workflow_id for update;
  if not found or not v_workflow.enabled or not private.has_business_entitlement(v_workflow.tenant_id) then
    raise exception 'enabled Business automation required' using errcode = '42501';
  end if;
  select * into v_existing from public.lifecycle_workflow_runs run
    where run.tenant_id = v_workflow.tenant_id and run.idempotency_key = p_idempotency_key;
  if found then
    return jsonb_build_object('run_id',v_existing.id,'status',v_existing.status,'replayed',true,
      'credits_remaining',(select automation_runs_remaining from public.tenant_entitlements where tenant_id = v_workflow.tenant_id));
  end if;

  select * into v_entitlement from public.tenant_entitlements entitlement
    where entitlement.tenant_id = v_workflow.tenant_id for update;
  if not found or v_entitlement.automation_runs_remaining < 1 then
    raise exception 'automation credits exhausted' using errcode = '54000';
  end if;
  update public.tenant_entitlements set automation_runs_remaining = automation_runs_remaining - 1,
    updated_at = now() where tenant_id = v_workflow.tenant_id;

  v_status := case when v_workflow.approval_required or v_workflow.destructive_action
    then 'awaiting_approval' else 'completed' end;
  v_result := jsonb_build_object(
    'template_key',coalesce(v_workflow.template_key,'custom'),
    'action_type',v_workflow.action_type,
    'trigger_source',p_trigger_source,
    'external_side_effect',false,
    'outcome',case when v_status = 'awaiting_approval' then 'human_approval_required' else 'action_item_created' end
  );
  insert into public.lifecycle_workflow_runs(
    tenant_id,workflow_id,idempotency_key,trigger_ref_hash,status,result_summary,
    started_at,finished_at,requested_by,credits_charged
  ) values (
    v_workflow.tenant_id,v_workflow.id,p_idempotency_key,
    extensions.digest(convert_to(v_workflow.id::text || ':' || p_trigger_source || ':' || p_idempotency_key,'UTF8'),'sha256'),
    v_status,v_result,now(),case when v_status = 'completed' then now() else null end,p_actor_identity_id,1
  ) returning id into v_run_id;

  insert into public.automation_action_items(
    tenant_id,workflow_id,run_id,action_kind,title,requires_approval,summary,created_by
  ) values (
    v_workflow.tenant_id,v_workflow.id,v_run_id,v_workflow.action_type,v_workflow.display_name,
    v_status = 'awaiting_approval',
    jsonb_build_object('template_key',coalesce(v_workflow.template_key,'custom'),'source',p_trigger_source,
      'execution_boundary',case when v_status = 'awaiting_approval' then 'proposal_only' else 'in_app_action_item' end),
    p_actor_identity_id
  ) returning id into v_action_id;

  perform private.append_business_automation_event(v_workflow.tenant_id,v_run_id,p_actor_identity_id,'created',
    jsonb_build_object('workflow_id',v_workflow.id,'trigger_source',p_trigger_source));
  perform private.append_business_automation_event(v_workflow.tenant_id,v_run_id,p_actor_identity_id,
    case when v_status = 'awaiting_approval' then 'approval_requested' else 'completed' end,
    jsonb_build_object('action_item_id',v_action_id,'external_side_effect',false));
  update public.lifecycle_workflows set last_run_at = now(),last_run_status = v_status,
    next_run_at = case when schedule_interval_minutes is null then null
      else now() + schedule_interval_minutes * interval '1 minute' end,
    updated_at = now() where id = v_workflow.id;
  return jsonb_build_object('run_id',v_run_id,'action_item_id',v_action_id,'status',v_status,
    'replayed',false,'credits_remaining',v_entitlement.automation_runs_remaining - 1);
end
$$;

create or replace function public.create_business_automation(
  p_tenant_id uuid,p_template_key text,p_display_name text default null
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_id uuid;
  v_name text;
  v_trigger text;
  v_action text;
  v_mode text;
  v_destructive boolean;
  v_approval boolean;
  v_interval integer;
begin
  if v_actor is null or not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_phase5_tenant(p_tenant_id) then
    raise exception 'Business automation manager permission required' using errcode = '42501';
  end if;
  case p_template_key
    when 'weekly_security_review' then
      v_name := 'Weekly security review'; v_trigger := 'security_signal'; v_action := 'create_review';
      v_mode := 'automatic'; v_destructive := false; v_approval := false; v_interval := 10080;
    when 'monthly_device_review' then
      v_name := 'Monthly device posture review'; v_trigger := 'device_posture'; v_action := 'create_review';
      v_mode := 'automatic'; v_destructive := false; v_approval := false; v_interval := 43200;
    when 'renewal_watch' then
      v_name := 'Daily renewal watch'; v_trigger := 'renewal_notice'; v_action := 'notify';
      v_mode := 'automatic'; v_destructive := false; v_approval := false; v_interval := 1440;
    when 'joiner_review' then
      v_name := 'Joiner access review'; v_trigger := 'joiner'; v_action := 'create_review';
      v_mode := 'proposal'; v_destructive := false; v_approval := true; v_interval := null;
    when 'license_reclaim' then
      v_name := 'Unused license reclaim proposal'; v_trigger := 'license_reclaim'; v_action := 'propose_reclaim';
      v_mode := 'proposal'; v_destructive := true; v_approval := true; v_interval := 10080;
    when 'leaver_guardrail' then
      v_name := 'Leaver deprovision proposal'; v_trigger := 'leaver'; v_action := 'propose_deprovision';
      v_mode := 'proposal'; v_destructive := true; v_approval := true; v_interval := null;
    else raise exception 'unsupported automation template' using errcode = '22023';
  end case;
  if nullif(trim(coalesce(p_display_name,'')),'') is not null then v_name := trim(p_display_name); end if;
  if length(v_name) not between 3 and 160 then raise exception 'invalid automation name' using errcode = '22023'; end if;
  insert into public.lifecycle_workflows(
    tenant_id,display_name,trigger_type,action_type,execution_mode,destructive_action,
    approval_required,definition,enabled,created_by,template_key,schedule_interval_minutes
  ) values (
    p_tenant_id,v_name,v_trigger,v_action,v_mode,v_destructive,v_approval,
    jsonb_build_object('source','business_template','version',1,'privacy_boundary','tenant_metadata_only'),
    false,v_actor,p_template_key,v_interval
  ) returning id into v_id;
  return v_id;
end
$$;

create or replace function public.set_business_automation_enabled(p_workflow_id uuid,p_enabled boolean)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_workflow public.lifecycle_workflows%rowtype;
begin
  select * into v_workflow from public.lifecycle_workflows workflow where workflow.id = p_workflow_id for update;
  if not found or v_actor is null or not private.has_business_entitlement(v_workflow.tenant_id)
    or not private.can_manage_phase5_tenant(v_workflow.tenant_id) then
    raise exception 'Business automation manager permission required' using errcode = '42501';
  end if;
  update public.lifecycle_workflows set enabled = p_enabled,
    next_run_at = case when p_enabled and schedule_interval_minutes is not null
      then now() + schedule_interval_minutes * interval '1 minute' else null end,
    updated_at = now() where id = p_workflow_id;
  return true;
end
$$;

create or replace function public.run_business_automation(p_workflow_id uuid,p_idempotency_key text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_tenant uuid;
begin
  select tenant_id into v_tenant from public.lifecycle_workflows where id = p_workflow_id;
  if v_actor is null or v_tenant is null or not private.can_manage_phase5_tenant(v_tenant) then
    raise exception 'Business automation manager permission required' using errcode = '42501';
  end if;
  return private.execute_business_automation(p_workflow_id,p_idempotency_key,'manual',v_actor);
end
$$;

create or replace function public.decide_business_automation_run(p_run_id uuid,p_decision text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_run public.lifecycle_workflow_runs%rowtype; v_status text;
begin
  if p_decision not in ('approved','denied') then raise exception 'invalid automation decision' using errcode = '22023'; end if;
  select * into v_run from public.lifecycle_workflow_runs run where run.id = p_run_id for update;
  if not found or v_actor is null or not private.has_business_entitlement(v_run.tenant_id)
    or not private.can_manage_phase5_tenant(v_run.tenant_id) then
    raise exception 'Business automation manager permission required' using errcode = '42501';
  end if;
  if v_run.status <> 'awaiting_approval' then raise exception 'automation run is not awaiting approval' using errcode = '55000'; end if;
  v_status := case when p_decision = 'approved' then 'approved' else 'cancelled' end;
  update public.lifecycle_workflow_runs set status = v_status,finished_at = now(),
    result_summary = result_summary || jsonb_build_object(
      'decision',p_decision,'external_side_effect',false,
      'execution_gate',case when p_decision = 'approved' then 'certified_adapter_required' else 'closed' end
    ) where id = p_run_id;
  update public.automation_action_items set status = case when p_decision = 'approved' then 'open' else 'dismissed' end,
    resolved_by = case when p_decision = 'denied' then v_actor else null end,
    resolved_at = case when p_decision = 'denied' then now() else null end
    where run_id = p_run_id;
  perform private.append_business_automation_event(v_run.tenant_id,p_run_id,v_actor,
    case when p_decision = 'approved' then 'approved' else 'denied' end,
    jsonb_build_object('external_side_effect',false,'execution_gate',
      case when p_decision = 'approved' then 'certified_adapter_required' else 'closed' end));
  return jsonb_build_object('run_id',p_run_id,'status',v_status,'external_side_effect',false);
end
$$;

create or replace function public.resolve_automation_action_item(p_action_item_id uuid,p_resolution text)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_item public.automation_action_items%rowtype;
begin
  if p_resolution not in ('completed','dismissed') then raise exception 'invalid action resolution' using errcode = '22023'; end if;
  select * into v_item from public.automation_action_items item where item.id = p_action_item_id for update;
  if not found or v_actor is null or not private.can_manage_phase5_tenant(v_item.tenant_id) then
    raise exception 'Business automation manager permission required' using errcode = '42501';
  end if;
  if v_item.status <> 'open' then return false; end if;
  update public.automation_action_items set status = p_resolution,resolved_by = v_actor,resolved_at = now()
    where id = p_action_item_id;
  return true;
end
$$;

create or replace function public.business_automation_dashboard(p_tenant_id uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$
  select case when private.can_view_phase5_tenant(p_tenant_id) then jsonb_build_object(
    'eligible',private.has_business_entitlement(p_tenant_id),
    'credits_remaining',coalesce((select automation_runs_remaining from public.tenant_entitlements where tenant_id = p_tenant_id),0),
    'definitions',(select count(*) from public.lifecycle_workflows workflow where workflow.tenant_id = p_tenant_id),
    'enabled',(select count(*) from public.lifecycle_workflows workflow where workflow.tenant_id = p_tenant_id and workflow.enabled),
    'awaiting_approval',(select count(*) from public.lifecycle_workflow_runs run where run.tenant_id = p_tenant_id and run.status = 'awaiting_approval'),
    'open_actions',(select count(*) from public.automation_action_items item where item.tenant_id = p_tenant_id and item.status = 'open'),
    'scheduler','database_cron_15m'
  ) else null end
$$;

create or replace function private.run_due_business_automations(p_limit integer default 100)
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_workflow public.lifecycle_workflows%rowtype; v_count integer := 0; v_key text;
begin
  for v_workflow in
    select * from public.lifecycle_workflows workflow
    where workflow.enabled and workflow.next_run_at is not null and workflow.next_run_at <= now()
    order by workflow.next_run_at for update skip locked limit least(greatest(p_limit,1),500)
  loop
    begin
      v_key := 'schedule:' || v_workflow.id::text || ':' || extract(epoch from v_workflow.next_run_at)::bigint::text;
      perform private.execute_business_automation(v_workflow.id,v_key,'schedule',v_workflow.created_by);
      v_count := v_count + 1;
    exception when others then
      update public.lifecycle_workflows set last_run_at = now(),last_run_status = 'failed',
        next_run_at = now() + interval '15 minutes',updated_at = now() where id = v_workflow.id;
    end;
  end loop;
  return v_count;
end
$$;

revoke all on function private.append_business_automation_event(uuid,uuid,uuid,text,jsonb),
  private.execute_business_automation(uuid,text,text,uuid),
  private.run_due_business_automations(integer) from public,anon,authenticated;
revoke all on function public.create_business_automation(uuid,text,text),
  public.set_business_automation_enabled(uuid,boolean),
  public.run_business_automation(uuid,text),
  public.decide_business_automation_run(uuid,text),
  public.resolve_automation_action_item(uuid,text),
  public.business_automation_dashboard(uuid) from public,anon;
grant execute on function public.create_business_automation(uuid,text,text),
  public.set_business_automation_enabled(uuid,boolean),
  public.run_business_automation(uuid,text),
  public.decide_business_automation_run(uuid,text),
  public.resolve_automation_action_item(uuid,text),
  public.business_automation_dashboard(uuid) to authenticated;
grant execute on function private.append_business_automation_event(uuid,uuid,uuid,text,jsonb),
  private.execute_business_automation(uuid,text,text,uuid),
  private.run_due_business_automations(integer) to service_role;

-- Phase 7 requested policy and provider certification are deliberately
-- separate. Tenant administrators can request controls; only a reviewed
-- backend process can publish certification evidence or activate delivery.
create or replace function private.valid_enterprise_regions(p_regions text[])
returns boolean language sql immutable strict set search_path = ''
as $$
  select cardinality(p_regions) <= 12 and not exists (
    select 1 from unnest(p_regions) as region(value)
    where value !~ '^[a-z]{2}(?:-[a-z]+)+[0-9]?$'
  )
$$;

create or replace function private.valid_siem_event_types(p_types text[])
returns boolean language sql immutable strict set search_path = ''
as $$
  select cardinality(p_types) between 1 and 12 and p_types <@
    array['access','identity','runtime','policy','billing','automation','device','connector','account']::text[]
$$;

create table public.enterprise_trust_policies (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  device_trust_mode text not null default 'observe' check (device_trust_mode in ('observe','enforce')),
  posture_max_age_minutes integer not null default 1440 check (posture_max_age_minutes between 15 and 43200),
  private_ai_mode text not null default 'disabled' check (private_ai_mode in ('disabled','aggregate_only','private_region')),
  allowed_ai_regions text[] not null default '{}',
  siem_mode text not null default 'disabled' check (siem_mode in ('disabled','audit_export','continuous')),
  msp_mode text not null default 'disabled' check (msp_mode in ('disabled','metadata_view','metadata_manage')),
  procurement_mode text not null default 'direct' check (procurement_mode in ('direct','marketplace')),
  requested_status text not null default 'draft' check (requested_status in ('draft','requested','suspended')),
  created_by uuid not null references public.identities(id) on delete restrict,
  updated_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (private.valid_enterprise_regions(allowed_ai_regions)),
  check (private_ai_mode <> 'private_region' or cardinality(allowed_ai_regions) > 0)
);

create table public.enterprise_component_certifications (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  component text not null check (component in ('security_review','device_trust','private_ai','siem','msp','marketplace','connector_ecosystem','disaster_recovery')),
  certification_status text not null default 'not_configured'
    check (certification_status in ('not_configured','sandbox_verified','production_certified','suspended','expired')),
  deployment_region text,
  evidence_sha256 bytea,
  reviewer_ref_sha256 bytea,
  verified_at timestamptz,
  expires_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key (tenant_id,component),
  check (deployment_region is null or private.valid_enterprise_regions(array[deployment_region])),
  check (evidence_sha256 is null or octet_length(evidence_sha256) = 32),
  check (reviewer_ref_sha256 is null or octet_length(reviewer_ref_sha256) = 32),
  check (certification_status <> 'production_certified' or
    (evidence_sha256 is not null and reviewer_ref_sha256 is not null and verified_at is not null)),
  check (expires_at is null or verified_at is null or expires_at > verified_at)
);

create table public.enterprise_siem_destinations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  display_name text not null check (length(display_name) between 3 and 120),
  region text not null,
  endpoint_origin_sha256 bytea not null check (octet_length(endpoint_origin_sha256) = 32),
  schema_version text not null default '1.0' check (schema_version = '1.0'),
  event_types text[] not null,
  status text not null default 'draft' check (status in ('draft','requested','active','disabled','error')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,display_name),
  unique (tenant_id,id),
  check (private.valid_enterprise_regions(array[region])),
  check (private.valid_siem_event_types(event_types))
);

create table public.enterprise_siem_delivery_receipts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  destination_id uuid not null,
  event_id uuid not null,
  idempotency_key text not null check (idempotency_key ~ '^[A-Za-z0-9._:-]{8,200}$'),
  envelope_sha256 bytea not null check (octet_length(envelope_sha256) = 32),
  delivery_status text not null default 'pending'
    check (delivery_status in ('pending','in_flight','acknowledged','retryable','dead_letter')),
  attempt_count integer not null default 0 check (attempt_count between 0 and 100),
  response_code integer check (response_code is null or response_code between 100 and 599),
  next_attempt_at timestamptz,
  acknowledged_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,idempotency_key),
  foreign key (tenant_id,destination_id) references public.enterprise_siem_destinations(tenant_id,id) on delete restrict
);

create table public.enterprise_trust_events (
  sequence bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  actor_identity_id uuid references public.identities(id) on delete set null,
  event_type text not null check (event_type in ('policy_requested','siem_destination_registered','siem_activation_requested','certification_changed','control_blocked')),
  event_metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(event_metadata) = 'object' and octet_length(convert_to(event_metadata::text,'UTF8')) <= 16384),
  previous_hash bytea,
  event_hash bytea not null check (octet_length(event_hash) = 32),
  occurred_at timestamptz not null default now(),
  check (not lower(event_metadata::text) ~ '"(password|secret|token|private_key|recovery_key|credential|vault_content|raw_prompt|command_output|endpoint_url)"[[:space:]]*:')
);

create index enterprise_trust_policies_created_by_idx on public.enterprise_trust_policies(created_by);
create index enterprise_trust_policies_updated_by_idx on public.enterprise_trust_policies(updated_by);
create index enterprise_component_certifications_status_idx on public.enterprise_component_certifications(component,certification_status,expires_at);
create index enterprise_siem_destinations_tenant_status_idx on public.enterprise_siem_destinations(tenant_id,status,updated_at desc);
create index enterprise_siem_destinations_created_by_idx on public.enterprise_siem_destinations(created_by);
create index enterprise_siem_receipts_destination_idx on public.enterprise_siem_delivery_receipts(tenant_id,destination_id,created_at desc);
create index enterprise_siem_receipts_retry_idx on public.enterprise_siem_delivery_receipts(next_attempt_at)
  where delivery_status = 'retryable';
create index enterprise_trust_events_tenant_idx on public.enterprise_trust_events(tenant_id,sequence desc);
create index enterprise_trust_events_actor_idx on public.enterprise_trust_events(actor_identity_id)
  where actor_identity_id is not null;

alter table public.enterprise_trust_policies enable row level security;
alter table public.enterprise_component_certifications enable row level security;
alter table public.enterprise_siem_destinations enable row level security;
alter table public.enterprise_siem_delivery_receipts enable row level security;
alter table public.enterprise_trust_events enable row level security;

revoke all on public.enterprise_trust_policies,public.enterprise_component_certifications,
  public.enterprise_siem_destinations,public.enterprise_siem_delivery_receipts,
  public.enterprise_trust_events from public,anon,authenticated;
grant select on public.enterprise_trust_policies,public.enterprise_component_certifications,
  public.enterprise_siem_destinations,public.enterprise_siem_delivery_receipts,
  public.enterprise_trust_events to authenticated;
grant select,insert,update,delete on public.enterprise_trust_policies,public.enterprise_component_certifications,
  public.enterprise_siem_destinations,public.enterprise_siem_delivery_receipts,
  public.enterprise_trust_events to service_role;

create policy enterprise_trust_policies_read on public.enterprise_trust_policies for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy enterprise_component_certifications_read on public.enterprise_component_certifications for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy enterprise_siem_destinations_read on public.enterprise_siem_destinations for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy enterprise_siem_delivery_receipts_read on public.enterprise_siem_delivery_receipts for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));
create policy enterprise_trust_events_read on public.enterprise_trust_events for select to authenticated
  using ((select private.has_tenant_role(tenant_id,array['owner','admin','member','auditor'])));

create or replace function private.append_enterprise_trust_event(
  p_tenant_id uuid,p_actor_identity_id uuid,p_event_type text,p_metadata jsonb
) returns bigint language plpgsql security definer set search_path = ''
as $$
declare v_previous bytea; v_hash bytea; v_sequence bigint; v_occurred_at timestamptz := clock_timestamp();
begin
  if p_event_type not in ('policy_requested','siem_destination_registered','siem_activation_requested','certification_changed','control_blocked') then
    raise exception 'invalid enterprise trust event' using errcode = '22023';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('enterprise-trust:' || p_tenant_id::text,29));
  select event_hash into v_previous from public.enterprise_trust_events
    where tenant_id = p_tenant_id order by sequence desc limit 1;
  v_hash := extensions.digest(convert_to(concat_ws('|',p_tenant_id::text,coalesce(p_actor_identity_id::text,''),
    p_event_type,coalesce(p_metadata,'{}'::jsonb)::text,coalesce(encode(v_previous,'hex'),''),v_occurred_at::text),'UTF8'),'sha256');
  insert into public.enterprise_trust_events(
    tenant_id,actor_identity_id,event_type,event_metadata,previous_hash,event_hash,occurred_at
  ) values (p_tenant_id,p_actor_identity_id,p_event_type,coalesce(p_metadata,'{}'::jsonb),v_previous,v_hash,v_occurred_at)
  returning sequence into v_sequence;
  return v_sequence;
end
$$;

create or replace function public.enterprise_trust_dashboard(p_tenant_id uuid)
returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
declare
  v_policy public.enterprise_trust_policies%rowtype;
  v_eligible boolean;
  v_components jsonb;
  v_production_connectors integer;
  v_phase7_accepted boolean;
begin
  if not private.has_tenant_role(p_tenant_id,array['owner','admin','member','auditor']) then return null; end if;
  v_eligible := private.has_enterprise_entitlement(p_tenant_id);
  select * into v_policy from public.enterprise_trust_policies policy where policy.tenant_id = p_tenant_id;
  select coalesce(jsonb_object_agg(certification.component,jsonb_build_object(
    'status',case when certification.expires_at is not null and certification.expires_at <= now() then 'expired' else certification.certification_status end,
    'region',certification.deployment_region,'verified_at',certification.verified_at,'expires_at',certification.expires_at
  )),'{}'::jsonb) into v_components
  from public.enterprise_component_certifications certification where certification.tenant_id = p_tenant_id;
  select count(*) into v_production_connectors from public.connector_catalog connector
    where connector.published and connector.adapter_stage = 'production'
      and exists (select 1 from public.connector_certifications certification
        where certification.connector_key = connector.connector_key and certification.result = 'passed'
          and (certification.expires_at is null or certification.expires_at > now()));
  v_phase7_accepted := v_eligible and v_production_connectors >= 100 and not exists (
    select 1 from unnest(array['security_review','device_trust','private_ai','siem','msp','marketplace','connector_ecosystem','disaster_recovery']) component
    where not exists (
      select 1 from public.enterprise_component_certifications certification
      where certification.tenant_id = p_tenant_id and certification.component = component
        and certification.certification_status = 'production_certified'
        and (certification.expires_at is null or certification.expires_at > now())
    )
  );
  return jsonb_build_object(
    'eligible',v_eligible,
    'policy',case when v_policy.tenant_id is null then null else jsonb_build_object(
      'device_trust_mode',v_policy.device_trust_mode,'posture_max_age_minutes',v_policy.posture_max_age_minutes,
      'private_ai_mode',v_policy.private_ai_mode,'allowed_ai_regions',v_policy.allowed_ai_regions,
      'siem_mode',v_policy.siem_mode,'msp_mode',v_policy.msp_mode,
      'procurement_mode',v_policy.procurement_mode,'requested_status',v_policy.requested_status,'updated_at',v_policy.updated_at
    ) end,
    'components',v_components,
    'production_certified_connectors',v_production_connectors,
    'connector_milestone',100,
    'active_msp_relationships',(select count(*) from public.msp_tenant_access access
      where (access.provider_tenant_id = p_tenant_id or access.customer_tenant_id = p_tenant_id) and access.status = 'active'),
    'siem_destinations',(select count(*) from public.enterprise_siem_destinations destination where destination.tenant_id = p_tenant_id),
    'phase7_accepted',v_phase7_accepted,
    'acceptance_state',case when v_phase7_accepted then 'accepted' when v_eligible then 'external_evidence_required' else 'enterprise_contract_required' end
  );
end
$$;

create or replace function public.configure_enterprise_trust(
  p_tenant_id uuid,p_device_trust_mode text,p_posture_max_age_minutes integer,
  p_private_ai_mode text,p_allowed_ai_regions text[],p_siem_mode text,p_msp_mode text,p_procurement_mode text
) returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not private.has_enterprise_entitlement(p_tenant_id)
    or not private.can_manage_runtime_tenant(p_tenant_id) then
    raise exception 'Enterprise trust manager permission required' using errcode = '42501';
  end if;
  if p_device_trust_mode not in ('observe','enforce') or p_posture_max_age_minutes not between 15 and 43200
    or p_private_ai_mode not in ('disabled','aggregate_only','private_region')
    or not private.valid_enterprise_regions(p_allowed_ai_regions)
    or (p_private_ai_mode = 'private_region' and cardinality(p_allowed_ai_regions) = 0)
    or p_siem_mode not in ('disabled','audit_export','continuous')
    or p_msp_mode not in ('disabled','metadata_view','metadata_manage')
    or p_procurement_mode not in ('direct','marketplace') then
    raise exception 'invalid enterprise trust policy' using errcode = '22023';
  end if;
  insert into public.enterprise_trust_policies(
    tenant_id,device_trust_mode,posture_max_age_minutes,private_ai_mode,allowed_ai_regions,
    siem_mode,msp_mode,procurement_mode,requested_status,created_by,updated_by
  ) values (
    p_tenant_id,p_device_trust_mode,p_posture_max_age_minutes,p_private_ai_mode,p_allowed_ai_regions,
    p_siem_mode,p_msp_mode,p_procurement_mode,'requested',v_actor,v_actor
  ) on conflict (tenant_id) do update set
    device_trust_mode = excluded.device_trust_mode,posture_max_age_minutes = excluded.posture_max_age_minutes,
    private_ai_mode = excluded.private_ai_mode,allowed_ai_regions = excluded.allowed_ai_regions,
    siem_mode = excluded.siem_mode,msp_mode = excluded.msp_mode,procurement_mode = excluded.procurement_mode,
    requested_status = 'requested',updated_by = v_actor,updated_at = now();
  perform private.append_enterprise_trust_event(p_tenant_id,v_actor,'policy_requested',jsonb_build_object(
    'device_trust_mode',p_device_trust_mode,'private_ai_mode',p_private_ai_mode,
    'siem_mode',p_siem_mode,'msp_mode',p_msp_mode,'procurement_mode',p_procurement_mode));
  return public.enterprise_trust_dashboard(p_tenant_id);
end
$$;

create or replace function public.register_enterprise_siem_destination(
  p_tenant_id uuid,p_display_name text,p_region text,p_endpoint_origin_sha256 bytea,p_event_types text[]
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_id uuid;
begin
  if v_actor is null or not private.has_enterprise_entitlement(p_tenant_id)
    or not private.can_manage_runtime_tenant(p_tenant_id) then
    raise exception 'Enterprise SIEM manager permission required' using errcode = '42501';
  end if;
  if length(trim(p_display_name)) not between 3 and 120
    or not private.valid_enterprise_regions(array[p_region])
    or octet_length(p_endpoint_origin_sha256) <> 32
    or not private.valid_siem_event_types(p_event_types) then
    raise exception 'invalid SIEM destination' using errcode = '22023';
  end if;
  insert into public.enterprise_siem_destinations(
    tenant_id,display_name,region,endpoint_origin_sha256,event_types,created_by
  ) values (p_tenant_id,trim(p_display_name),p_region,p_endpoint_origin_sha256,p_event_types,v_actor)
  returning id into v_id;
  perform private.append_enterprise_trust_event(p_tenant_id,v_actor,'siem_destination_registered',
    jsonb_build_object('destination_id',v_id,'region',p_region,'schema_version','1.0'));
  return v_id;
end
$$;

create or replace function public.request_enterprise_siem_activation(p_destination_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_destination public.enterprise_siem_destinations%rowtype; v_policy public.enterprise_trust_policies%rowtype;
begin
  select * into v_destination from public.enterprise_siem_destinations destination where destination.id = p_destination_id for update;
  if not found or v_actor is null or not private.has_enterprise_entitlement(v_destination.tenant_id)
    or not private.can_manage_runtime_tenant(v_destination.tenant_id) then
    raise exception 'Enterprise SIEM manager permission required' using errcode = '42501';
  end if;
  select * into v_policy from public.enterprise_trust_policies policy where policy.tenant_id = v_destination.tenant_id;
  if not found or v_policy.siem_mode <> 'continuous' then
    raise exception 'continuous SIEM policy must be requested first' using errcode = '55000';
  end if;
  update public.enterprise_siem_destinations set status = 'requested',updated_at = now() where id = p_destination_id;
  perform private.append_enterprise_trust_event(v_destination.tenant_id,v_actor,'siem_activation_requested',
    jsonb_build_object('destination_id',p_destination_id,'effective_delivery',false,'certification_required',true));
  return true;
end
$$;

create or replace function public.evaluate_enterprise_ai_routing(
  p_tenant_id uuid,p_deployment_region text,p_deployment_mode text
) returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
declare v_policy public.enterprise_trust_policies%rowtype; v_certified boolean := false;
begin
  if not private.can_view_runtime_tenant(p_tenant_id) or not private.has_business_entitlement(p_tenant_id) then return null; end if;
  if not private.has_enterprise_entitlement(p_tenant_id) then
    return jsonb_build_object('allowed',true,'mode','aggregate_only','reason','business_aggregate_policy');
  end if;
  select * into v_policy from public.enterprise_trust_policies policy where policy.tenant_id = p_tenant_id;
  if not found or v_policy.private_ai_mode = 'disabled' then
    return jsonb_build_object('allowed',false,'mode','disabled','reason','enterprise_ai_policy_disabled');
  end if;
  if v_policy.private_ai_mode = 'aggregate_only' then
    return jsonb_build_object('allowed',true,'mode','aggregate_only','reason','enterprise_aggregate_policy');
  end if;
  select exists (
    select 1 from public.enterprise_component_certifications certification
    where certification.tenant_id = p_tenant_id and certification.component = 'private_ai'
      and certification.certification_status = 'production_certified'
      and certification.deployment_region = p_deployment_region
      and (certification.expires_at is null or certification.expires_at > now())
  ) into v_certified;
  return jsonb_build_object(
    'allowed',v_certified and p_deployment_mode = 'private' and p_deployment_region = any(v_policy.allowed_ai_regions),
    'mode','private_region','reason',case
      when p_deployment_mode <> 'private' then 'private_deployment_required'
      when not p_deployment_region = any(v_policy.allowed_ai_regions) then 'region_not_allowed'
      when not v_certified then 'regional_provider_not_certified'
      else 'regional_policy_satisfied' end
  );
end
$$;

create or replace function public.evaluate_enterprise_device_trust(
  p_tenant_id uuid,p_device_id uuid,p_identity_id uuid
) returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_policy public.enterprise_trust_policies%rowtype;
  v_report public.organization_device_posture_reports%rowtype;
  v_device_trusted boolean := false;
  v_certified boolean := false;
  v_allowed boolean := false;
  v_reason text;
begin
  if v_actor is null or (p_identity_id <> v_actor and not private.can_manage_organization_identity(
    p_tenant_id,array['organization_admin','security_admin','auditor'],p_identity_id)) then
    raise exception 'device trust access denied' using errcode = '42501';
  end if;
  if not private.has_enterprise_entitlement(p_tenant_id) then
    return public.evaluate_organization_device_readiness(p_tenant_id,p_device_id,p_identity_id)
      || jsonb_build_object('enterprise_enforced',false);
  end if;
  select * into v_policy from public.enterprise_trust_policies policy where policy.tenant_id = p_tenant_id;
  select exists (select 1 from public.devices device where device.id = p_device_id
    and device.identity_id = p_identity_id and device.status = 'trusted') into v_device_trusted;
  select * into v_report from public.organization_device_posture_reports report
    where report.tenant_id = p_tenant_id and report.device_id = p_device_id and report.identity_id = p_identity_id
    order by (report.verification_status = 'verified') desc,report.observed_at desc limit 1;
  select exists (
    select 1 from public.enterprise_component_certifications certification
    where certification.tenant_id = p_tenant_id and certification.component = 'device_trust'
      and certification.certification_status = 'production_certified'
      and (certification.expires_at is null or certification.expires_at > now())
  ) into v_certified;
  if v_policy.tenant_id is null or v_policy.device_trust_mode <> 'enforce' then
    v_allowed := v_device_trusted; v_reason := 'enterprise_observe_only';
  elsif not v_certified then v_reason := 'device_provider_not_certified';
  elsif not v_device_trusted then v_reason := 'device_not_trusted';
  elsif v_report.id is null then v_reason := 'attestation_missing';
  elsif v_report.source not in ('mdm','idp','attested') or v_report.verification_status <> 'verified' then v_reason := 'attestation_unverified';
  elsif v_report.evaluation <> 'compliant' then v_reason := 'posture_non_compliant';
  elsif v_report.valid_until <= now() or v_report.observed_at < now() - v_policy.posture_max_age_minutes * interval '1 minute' then v_reason := 'attestation_stale';
  else v_allowed := true; v_reason := 'enterprise_trust_satisfied'; end if;
  return jsonb_build_object('allowed',v_allowed,'enterprise_enforced',coalesce(v_policy.device_trust_mode = 'enforce',false),
    'provider_certified',v_certified,'verified',coalesce(v_report.verification_status = 'verified',false),
    'posture',coalesce(v_report.evaluation,'unknown'),'reason',v_reason,'valid_until',v_report.valid_until);
end
$$;

revoke all on function private.valid_enterprise_regions(text[]),private.valid_siem_event_types(text[]),
  private.append_enterprise_trust_event(uuid,uuid,text,jsonb) from public,anon,authenticated;
revoke all on function public.enterprise_trust_dashboard(uuid),
  public.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text),
  public.register_enterprise_siem_destination(uuid,text,text,bytea,text[]),
  public.request_enterprise_siem_activation(uuid),
  public.evaluate_enterprise_ai_routing(uuid,text,text),
  public.evaluate_enterprise_device_trust(uuid,uuid,uuid) from public,anon;
grant execute on function public.enterprise_trust_dashboard(uuid),
  public.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text),
  public.register_enterprise_siem_destination(uuid,text,text,bytea,text[]),
  public.request_enterprise_siem_activation(uuid),
  public.evaluate_enterprise_ai_routing(uuid,text,text),
  public.evaluate_enterprise_device_trust(uuid,uuid,uuid) to authenticated;
grant execute on function private.append_enterprise_trust_event(uuid,uuid,text,jsonb) to service_role;

create trigger lifecycle_workflows_business_audit after insert or update on public.lifecycle_workflows
  for each row execute function private.phase2_audit_event();
create trigger automation_action_items_audit after insert or update on public.automation_action_items
  for each row execute function private.phase2_audit_event();
create trigger enterprise_trust_policies_audit after insert or update on public.enterprise_trust_policies
  for each row execute function private.phase2_audit_event();
create trigger enterprise_siem_destinations_audit after insert or update on public.enterprise_siem_destinations
  for each row execute function private.phase2_audit_event();

-- Supabase Cron executes only the internal metadata-only dispatcher. It never
-- performs connector, vault, notification, or privileged side effects.
create extension if not exists pg_cron with schema pg_catalog;
grant usage on schema cron to postgres;
grant all privileges on all tables in schema cron to postgres;
do $schedule$
declare v_job_id bigint;
begin
  select jobid into v_job_id from cron.job where jobname = 'passkey-x-business-automations-v1';
  if v_job_id is not null then perform cron.unschedule(v_job_id); end if;
  perform cron.schedule(
    'passkey-x-business-automations-v1','*/15 * * * *',
    'select private.run_due_business_automations(100);'
  );
end
$schedule$;

comment on table public.automation_action_items is
  'Durable Business automation work items. Only tenant metadata is permitted; external side effects require a separately certified adapter.';
comment on table public.business_automation_events is
  'Append-only, hash-chained automation evidence. Browser roles have read-only access.';
comment on table public.enterprise_component_certifications is
  'Backend-authored Phase 7 certification evidence. Tenant policy requests cannot self-certify external controls.';
comment on table public.enterprise_siem_destinations is
  'SIEM destination metadata only. Raw endpoints and credentials remain in a reviewed backend adapter.';
comment on function public.enterprise_trust_dashboard(uuid) is
  'Phase 7 control-plane readiness; acceptance remains false until independent and provider evidence is current.';

commit;
