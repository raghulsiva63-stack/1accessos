-- Exported from production supabase_migrations.schema_migrations (20260907100259_phase6_runtime_mutation_rpc_fix).
begin;

-- Runtime mutations are deliberately exposed only through guarded RPCs. The
-- original SECURITY INVOKER declarations left these functions unable to write
-- because browser roles correctly have no direct mutation grants on the
-- underlying control-plane tables. Keep those tables sealed and execute the
-- already tenant-checked routines with the function owner's privileges.
alter function public.simulate_access_impact(uuid,uuid,text,jsonb) security definer;
alter function public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer) security definer;
alter function public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid) security definer;
alter function public.decide_privilege_request(uuid,text) security definer;

revoke insert,update,delete on public.access_simulations,public.privileged_resources,
  public.runtime_activation,public.privilege_requests,public.session_evidence
  from public,anon,authenticated;

comment on function public.simulate_access_impact(uuid,uuid,text,jsonb) is
  'Guarded Access Twin RPC. Runs with owner privileges because browser roles have no direct control-plane write grants.';
comment on function public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer) is
  'Guarded Business runtime RPC. Creates a draft resource without exposing direct table writes.';
comment on function public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid) is
  'Guarded runtime request RPC. Tenant, subject, scope, duration, and resource policy are checked before insertion.';
comment on function public.decide_privilege_request(uuid,text) is
  'Guarded manager decision RPC. Credential issuance remains subject to the independent runtime activation gate.';

commit;
