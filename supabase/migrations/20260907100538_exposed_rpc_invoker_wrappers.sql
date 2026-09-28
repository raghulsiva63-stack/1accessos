-- Exported from production supabase_migrations.schema_migrations (20260907100538_exposed_rpc_invoker_wrappers).
begin;

-- Supabase exposes functions in the public schema through PostgREST. Keep each
-- browser-callable entrypoint SECURITY INVOKER and move the elevated, fully
-- guarded implementation into the non-exposed private schema. Authenticated
-- callers can execute a private implementation only through an explicit public
-- wrapper because `private` is not an API schema.
alter function public.begin_ai_assistant_request(uuid,text,bytea,text[]) set schema private;
alter function public.complete_ai_assistant_request(uuid,text,integer,integer,text) set schema private;
alter function public.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text) set schema private;
alter function public.create_agent_profile(uuid,text,text[],integer) set schema private;
alter function public.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer) set schema private;
alter function public.create_business_automation(uuid,text,text) set schema private;
alter function public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid) set schema private;
alter function public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer) set schema private;
alter function public.decide_business_automation_run(uuid,text) set schema private;
alter function public.decide_privilege_request(uuid,text) set schema private;
alter function public.kill_agent(uuid) set schema private;
alter function public.register_enterprise_siem_destination(uuid,text,text,bytea,text[]) set schema private;
alter function public.request_enterprise_siem_activation(uuid) set schema private;
alter function public.resolve_automation_action_item(uuid,text) set schema private;
alter function public.run_business_automation(uuid,text) set schema private;
alter function public.set_business_automation_enabled(uuid,boolean) set schema private;
alter function public.simulate_access_impact(uuid,uuid,text,jsonb) set schema private;

create function public.begin_ai_assistant_request(
  p_tenant_id uuid,p_use_case text,p_prompt_sha256 bytea,p_context_categories text[]
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.begin_ai_assistant_request(p_tenant_id,p_use_case,p_prompt_sha256,p_context_categories) $$;

create function public.complete_ai_assistant_request(
  p_request_id uuid,p_status text,p_input_tokens integer,p_output_tokens integer,p_failure_code text default null
) returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.complete_ai_assistant_request(p_request_id,p_status,p_input_tokens,p_output_tokens,p_failure_code) $$;

create function public.configure_enterprise_trust(
  p_tenant_id uuid,p_device_trust_mode text,p_posture_max_age_minutes integer,
  p_private_ai_mode text,p_allowed_ai_regions text[],p_siem_mode text,p_msp_mode text,p_procurement_mode text
) returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.configure_enterprise_trust(p_tenant_id,p_device_trust_mode,p_posture_max_age_minutes,p_private_ai_mode,p_allowed_ai_regions,p_siem_mode,p_msp_mode,p_procurement_mode) $$;

create function public.create_agent_profile(
  p_tenant_id uuid,p_display_name text,p_allowed_scopes text[],p_max_lease_minutes integer default 15
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_agent_profile(p_tenant_id,p_display_name,p_allowed_scopes,p_max_lease_minutes) $$;

create function public.create_agent_task_capsule(
  p_agent_profile_id uuid,p_resource_ids uuid[],p_allowed_scopes text[],p_definition_sha256 bytea,
  p_expires_at timestamptz,p_max_uses integer default 1
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_agent_task_capsule(p_agent_profile_id,p_resource_ids,p_allowed_scopes,p_definition_sha256,p_expires_at,p_max_uses) $$;

create function public.create_business_automation(
  p_tenant_id uuid,p_template_key text,p_display_name text default null
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_business_automation(p_tenant_id,p_template_key,p_display_name) $$;

create function public.create_privilege_request(
  p_resource_id uuid,p_subject_identity_id uuid,p_requested_scopes text[],p_duration_minutes integer,
  p_justification_sha256 bytea,p_simulation_id uuid default null
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_privilege_request(p_resource_id,p_subject_identity_id,p_requested_scopes,p_duration_minutes,p_justification_sha256,p_simulation_id) $$;

create function public.create_privileged_resource(
  p_tenant_id uuid,p_display_name text,p_resource_type text,p_adapter_key text,
  p_target_ref_sha256 bytea,p_allowed_scopes text[],p_max_duration_minutes integer default 60
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.create_privileged_resource(p_tenant_id,p_display_name,p_resource_type,p_adapter_key,p_target_ref_sha256,p_allowed_scopes,p_max_duration_minutes) $$;

create function public.decide_business_automation_run(p_run_id uuid,p_decision text)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.decide_business_automation_run(p_run_id,p_decision) $$;

create function public.decide_privilege_request(p_request_id uuid,p_decision text)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.decide_privilege_request(p_request_id,p_decision) $$;

create function public.kill_agent(p_agent_profile_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.kill_agent(p_agent_profile_id) $$;

create function public.register_enterprise_siem_destination(
  p_tenant_id uuid,p_display_name text,p_region text,p_endpoint_origin_sha256 bytea,p_event_types text[]
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.register_enterprise_siem_destination(p_tenant_id,p_display_name,p_region,p_endpoint_origin_sha256,p_event_types) $$;

create function public.request_enterprise_siem_activation(p_destination_id uuid)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.request_enterprise_siem_activation(p_destination_id) $$;

create function public.resolve_automation_action_item(p_action_item_id uuid,p_resolution text)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.resolve_automation_action_item(p_action_item_id,p_resolution) $$;

create function public.run_business_automation(p_workflow_id uuid,p_idempotency_key text)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select private.run_business_automation(p_workflow_id,p_idempotency_key) $$;

create function public.set_business_automation_enabled(p_workflow_id uuid,p_enabled boolean)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.set_business_automation_enabled(p_workflow_id,p_enabled) $$;

create function public.simulate_access_impact(
  p_tenant_id uuid,p_target_identity_id uuid,p_action_type text,p_proposed_change jsonb default '{}'::jsonb
) returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.simulate_access_impact(p_tenant_id,p_target_identity_id,p_action_type,p_proposed_change) $$;

grant usage on schema private to authenticated,service_role;
grant execute on function
  private.begin_ai_assistant_request(uuid,text,bytea,text[]),
  private.complete_ai_assistant_request(uuid,text,integer,integer,text),
  private.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text),
  private.create_agent_profile(uuid,text,text[],integer),
  private.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer),
  private.create_business_automation(uuid,text,text),
  private.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid),
  private.create_privileged_resource(uuid,text,text,text,bytea,text[],integer),
  private.decide_business_automation_run(uuid,text),
  private.decide_privilege_request(uuid,text),
  private.kill_agent(uuid),
  private.register_enterprise_siem_destination(uuid,text,text,bytea,text[]),
  private.request_enterprise_siem_activation(uuid),
  private.resolve_automation_action_item(uuid,text),
  private.run_business_automation(uuid,text),
  private.set_business_automation_enabled(uuid,boolean),
  private.simulate_access_impact(uuid,uuid,text,jsonb)
to authenticated,service_role;

revoke all on function
  public.begin_ai_assistant_request(uuid,text,bytea,text[]),
  public.complete_ai_assistant_request(uuid,text,integer,integer,text),
  public.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text),
  public.create_agent_profile(uuid,text,text[],integer),
  public.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer),
  public.create_business_automation(uuid,text,text),
  public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid),
  public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer),
  public.decide_business_automation_run(uuid,text),
  public.decide_privilege_request(uuid,text),
  public.kill_agent(uuid),
  public.register_enterprise_siem_destination(uuid,text,text,bytea,text[]),
  public.request_enterprise_siem_activation(uuid),
  public.resolve_automation_action_item(uuid,text),
  public.run_business_automation(uuid,text),
  public.set_business_automation_enabled(uuid,boolean),
  public.simulate_access_impact(uuid,uuid,text,jsonb)
from public,anon;

grant execute on function
  public.begin_ai_assistant_request(uuid,text,bytea,text[]),
  public.complete_ai_assistant_request(uuid,text,integer,integer,text),
  public.configure_enterprise_trust(uuid,text,integer,text,text[],text,text,text),
  public.create_agent_profile(uuid,text,text[],integer),
  public.create_agent_task_capsule(uuid,uuid[],text[],bytea,timestamptz,integer),
  public.create_business_automation(uuid,text,text),
  public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid),
  public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer),
  public.decide_business_automation_run(uuid,text),
  public.decide_privilege_request(uuid,text),
  public.kill_agent(uuid),
  public.register_enterprise_siem_destination(uuid,text,text,bytea,text[]),
  public.request_enterprise_siem_activation(uuid),
  public.resolve_automation_action_item(uuid,text),
  public.run_business_automation(uuid,text),
  public.set_business_automation_enabled(uuid,boolean),
  public.simulate_access_impact(uuid,uuid,text,jsonb)
to authenticated,service_role;

comment on schema private is
  'Non-exposed implementation schema for guarded control-plane workers and policy helpers.';

commit;
