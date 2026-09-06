begin;

-- Web v2.2 control plane. Secret material is stored only in backend-only
-- tables as application-encrypted ciphertext or an opaque broker reference.

create table public.account_deletion_requests (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete restrict,
  auth_user_id uuid not null,
  status text not null default 'requested'
    check (status in ('requested','in_progress','blocked','completed','failed')),
  blocking_tenant_ids uuid[] not null default '{}',
  failure_code text check (failure_code is null or failure_code ~ '^[a-z0-9_]{2,64}$'),
  requested_at timestamptz not null default now(),
  completed_at timestamptz,
  check ((status = 'completed') = (completed_at is not null))
);

create unique index account_deletion_open_identity_idx
  on public.account_deletion_requests(identity_id)
  where status in ('requested','in_progress');

create table public.tenant_notification_settings (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  provider text not null default 'sent' check (provider = 'sent'),
  sms_enabled boolean not null default false,
  security_email_enabled boolean not null default true,
  event_types text[] not null default array['new_device','security_alert','access_approved','recovery_changed'],
  credential_status text not null default 'not_configured'
    check (credential_status in ('not_configured','pending','verified','rejected','revoked')),
  sender_profile_hint text check (sender_profile_hint is null or length(sender_profile_hint) between 3 and 32),
  last_verified_at timestamptz,
  updated_by uuid references public.identities(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (event_types <@ array['new_device','security_alert','access_requested','access_approved','recovery_changed','billing_notice','agent_killed']::text[]),
  check (not sms_enabled or credential_status = 'verified')
);

-- Browser roles have no grants or policies on the next two tables.
create table public.tenant_sms_credentials (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  encrypted_api_key bytea not null check (octet_length(encrypted_api_key) between 32 and 4096),
  encryption_nonce bytea not null check (octet_length(encryption_nonce) = 12),
  key_version integer not null default 1 check (key_version > 0),
  credential_sha256 bytea not null check (octet_length(credential_sha256) = 32),
  sender_profile_id text check (sender_profile_id is null or length(sender_profile_id) between 3 and 160),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  rotated_at timestamptz,
  revoked_at timestamptz
);

create table public.tenant_sms_subscriptions (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  encrypted_phone bytea not null check (octet_length(encrypted_phone) between 24 and 512),
  encryption_nonce bytea not null check (octet_length(encryption_nonce) = 12),
  phone_sha256 bytea not null check (octet_length(phone_sha256) = 32),
  masked_phone text not null check (masked_phone ~ '^\+?[*0-9 -]{4,24}$'),
  event_types text[] not null default array['security_alert'],
  enabled boolean not null default false,
  verified_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key (tenant_id,identity_id),
  foreign key (tenant_id,identity_id) references public.tenant_memberships(tenant_id,identity_id) on delete cascade,
  check (event_types <@ array['new_device','security_alert','access_requested','access_approved','recovery_changed','billing_notice','agent_killed']::text[]),
  check (not enabled or verified_at is not null)
);

create table public.notification_deliveries (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  recipient_identity_id uuid references public.identities(id) on delete set null,
  channel text not null check (channel in ('email','sms')),
  event_type text not null check (event_type in ('new_device','security_alert','access_requested','access_approved','recovery_changed','billing_notice','agent_killed','verification')),
  provider text not null check (provider in ('supabase','sent','smtp')),
  idempotency_key text not null check (length(idempotency_key) between 16 and 160),
  provider_message_id text check (provider_message_id is null or length(provider_message_id) between 3 and 200),
  status text not null default 'queued'
    check (status in ('queued','accepted','delivered','failed','blocked','filtered','read','unknown')),
  error_code text check (error_code is null or error_code ~ '^[A-Z0-9_:-]{2,96}$'),
  accepted_at timestamptz,
  delivered_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,idempotency_key)
);

create table public.sms_verification_challenges (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  code_sha256 bytea not null check (octet_length(code_sha256) = 32),
  phone_sha256 bytea not null check (octet_length(phone_sha256) = 32),
  attempts integer not null default 0 check (attempts between 0 and 5),
  status text not null default 'pending' check (status in ('pending','verified','expired','failed')),
  expires_at timestamptz not null default (now() + interval '10 minutes'),
  created_at timestamptz not null default now(),
  verified_at timestamptz,
  check (expires_at > created_at),
  check ((status = 'verified') = (verified_at is not null))
);

create table public.notification_delivery_events (
  id bigint generated always as identity primary key,
  delivery_id uuid not null references public.notification_deliveries(id) on delete cascade,
  provider_event_name text not null check (length(provider_event_name) between 3 and 120),
  provider_status text not null check (length(provider_status) between 2 and 120),
  payload_sha256 bytea not null check (octet_length(payload_sha256) = 32),
  happened_at timestamptz not null,
  received_at timestamptz not null default now(),
  unique (delivery_id,provider_event_name,happened_at)
);

create index sms_verification_challenges_rate_idx
  on public.sms_verification_challenges(identity_id,created_at desc);

create index notification_deliveries_recipient_idx
  on public.notification_deliveries(recipient_identity_id,created_at desc);
create index notification_deliveries_provider_idx
  on public.notification_deliveries(provider_message_id)
  where provider_message_id is not null;

create table public.ai_assistant_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  requested_by uuid not null references public.identities(id) on delete restrict,
  model text not null default 'gpt-5-mini' check (model = 'gpt-5-mini'),
  use_case text not null check (use_case in ('security_posture','access_review','spend_review','incident_summary')),
  prompt_sha256 bytea not null check (octet_length(prompt_sha256) = 32),
  context_categories text[] not null default '{}',
  status text not null default 'accepted'
    check (status in ('accepted','completed','blocked','failed')),
  input_tokens integer check (input_tokens is null or input_tokens >= 0),
  output_tokens integer check (output_tokens is null or output_tokens >= 0),
  failure_code text check (failure_code is null or failure_code ~ '^[a-z0-9_]{2,64}$'),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  check (context_categories <@ array['tenant_counts','security_counts','spend_totals','access_risk_counts']::text[])
);

create index ai_assistant_requests_rate_idx
  on public.ai_assistant_requests(requested_by,created_at desc);

create table public.runtime_activation (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  control_plane_enabled boolean not null default true,
  issuance_enabled boolean not null default false,
  kill_switch_active boolean not null default true,
  review_status text not null default 'pending'
    check (review_status in ('pending','accepted','rejected','expired')),
  review_evidence_sha256 bytea check (review_evidence_sha256 is null or octet_length(review_evidence_sha256) = 32),
  adapter_status text not null default 'not_configured'
    check (adapter_status in ('not_configured','contract_validated','production_certified','suspended')),
  updated_by uuid references public.identities(id) on delete set null,
  updated_at timestamptz not null default now(),
  check (not issuance_enabled or (
    control_plane_enabled and not kill_switch_active and review_status = 'accepted'
    and review_evidence_sha256 is not null and adapter_status = 'production_certified'
  ))
);

create table public.privileged_resources (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  display_name text not null check (length(display_name) between 2 and 120),
  resource_type text not null check (resource_type in ('database','server','cloud_role','saas_admin','kubernetes','ssh','rdp','custom')),
  adapter_key text not null check (adapter_key ~ '^[a-z0-9][a-z0-9_.-]{1,79}$'),
  adapter_stage text not null default 'manifest'
    check (adapter_stage in ('manifest','contract_validated','production_certified','suspended')),
  target_ref_sha256 bytea not null check (octet_length(target_ref_sha256) = 32),
  allowed_scopes text[] not null check (cardinality(allowed_scopes) > 0),
  max_duration_minutes integer not null default 60 check (max_duration_minutes between 5 and 1440),
  approval_required boolean not null default true,
  status text not null default 'draft' check (status in ('draft','active','suspended','retired')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,id),
  check (status <> 'active' or adapter_stage = 'production_certified')
);

create table public.agent_profiles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null unique references public.identities(id) on delete cascade,
  display_name text not null check (length(display_name) between 2 and 120),
  public_key bytea check (public_key is null or octet_length(public_key) between 32 and 8192),
  responsible_owner_identity_id uuid not null references public.identities(id) on delete restrict,
  allowed_scopes text[] not null default '{}',
  max_lease_minutes integer not null default 15 check (max_lease_minutes between 1 and 60),
  status text not null default 'draft' check (status in ('draft','active','suspended','killed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  killed_at timestamptz,
  foreign key (tenant_id,identity_id) references public.tenant_memberships(tenant_id,identity_id) on delete cascade,
  foreign key (tenant_id,responsible_owner_identity_id) references public.tenant_memberships(tenant_id,identity_id) on delete restrict,
  check ((status = 'killed') = (killed_at is not null))
);

create table public.access_simulations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  requested_by uuid not null references public.identities(id) on delete restrict,
  target_identity_id uuid references public.identities(id) on delete set null,
  action_type text not null check (action_type in ('grant','revoke','role_change','kill_agent','delete_account')),
  proposed_change jsonb not null default '{}'::jsonb
    check (jsonb_typeof(proposed_change) = 'object' and octet_length(convert_to(proposed_change::text,'UTF8')) <= 16384),
  impact_summary jsonb not null,
  risk_level text not null check (risk_level in ('low','medium','high','critical')),
  graph_sha256 bytea not null check (octet_length(graph_sha256) = 32),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '1 hour'),
  check (expires_at > created_at),
  check (not lower(proposed_change::text) ~ '"(password|secret|token|private_key|recovery_key|vault_content|raw_prompt)"[[:space:]]*:')
);

create table public.privilege_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  resource_id uuid not null,
  subject_identity_id uuid not null references public.identities(id) on delete restrict,
  requested_by uuid not null references public.identities(id) on delete restrict,
  requested_scopes text[] not null check (cardinality(requested_scopes) > 0),
  requested_duration_minutes integer not null check (requested_duration_minutes between 1 and 1440),
  justification_sha256 bytea not null check (octet_length(justification_sha256) = 32),
  simulation_id uuid references public.access_simulations(id) on delete restrict,
  status text not null default 'pending'
    check (status in ('pending','approved','denied','cancelled','expired','blocked')),
  decided_by uuid references public.identities(id) on delete restrict,
  decided_at timestamptz,
  decision_code text check (decision_code is null or decision_code ~ '^[a-z0-9_]{2,64}$'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  foreign key (tenant_id,resource_id) references public.privileged_resources(tenant_id,id) on delete cascade,
  check (expires_at > created_at),
  check ((status in ('approved','denied','blocked')) = (decided_at is not null))
);

create table public.privilege_sessions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  request_id uuid not null unique references public.privilege_requests(id) on delete restrict,
  resource_id uuid not null,
  subject_identity_id uuid not null references public.identities(id) on delete restrict,
  status text not null default 'queued'
    check (status in ('queued','active','revoking','revoked','expired','failed','blocked')),
  provider_session_ref_sha256 bytea check (provider_session_ref_sha256 is null or octet_length(provider_session_ref_sha256) = 32),
  started_at timestamptz,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  revoke_reason text check (revoke_reason is null or revoke_reason ~ '^[a-z0-9_]{2,64}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id,resource_id) references public.privileged_resources(tenant_id,id) on delete restrict,
  check (expires_at > created_at),
  check (status <> 'active' or started_at is not null),
  check (status not in ('revoked','expired') or revoked_at is not null)
);

-- Credential values never enter this table. The broker reference resolves only
-- inside a certified server-side adapter.
create table public.credential_leases (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  session_id uuid not null unique references public.privilege_sessions(id) on delete cascade,
  broker_reference text not null check (broker_reference ~ '^broker://[A-Za-z0-9/_:.-]+$'),
  credential_type text not null check (credential_type in ('ssh_certificate','database_token','cloud_token','oauth_token','api_token')),
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  provider_revocation_confirmed_at timestamptz,
  check (expires_at > issued_at)
);

create table public.agent_task_capsules (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  agent_profile_id uuid not null references public.agent_profiles(id) on delete cascade,
  definition_sha256 bytea not null check (octet_length(definition_sha256) = 32),
  resource_ids uuid[] not null default '{}',
  allowed_scopes text[] not null default '{}',
  not_before timestamptz not null default now(),
  expires_at timestamptz not null,
  max_uses integer not null default 1 check (max_uses between 1 and 1000),
  use_count integer not null default 0 check (use_count between 0 and max_uses),
  status text not null default 'active' check (status in ('active','suspended','consumed','expired','revoked')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  check (expires_at > not_before)
);

create table public.access_graph_snapshots (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  generated_by uuid references public.identities(id) on delete set null,
  node_counts jsonb not null check (jsonb_typeof(node_counts) = 'object'),
  edge_counts jsonb not null check (jsonb_typeof(edge_counts) = 'object'),
  risk_counts jsonb not null check (jsonb_typeof(risk_counts) = 'object'),
  graph_sha256 bytea not null check (octet_length(graph_sha256) = 32),
  generated_at timestamptz not null default now()
);

create table public.session_evidence (
  sequence bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  session_id uuid references public.privilege_sessions(id) on delete set null,
  actor_identity_id uuid references public.identities(id) on delete set null,
  event_type text not null check (event_type in ('requested','approved','denied','issued','connected','command','revocation_started','revoked','expired','failed','agent_killed')),
  event_metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(event_metadata) = 'object' and octet_length(convert_to(event_metadata::text,'UTF8')) <= 16384),
  previous_hash bytea,
  event_hash bytea not null check (octet_length(event_hash) = 32),
  occurred_at timestamptz not null default now(),
  check (not lower(event_metadata::text) ~ '"(password|secret|token|private_key|recovery_key|credential|vault_content|raw_prompt|command_output)"[[:space:]]*:')
);

create index privileged_resources_tenant_idx on public.privileged_resources(tenant_id,status,updated_at desc);
create index agent_profiles_tenant_idx on public.agent_profiles(tenant_id,status,updated_at desc);
create index access_simulations_tenant_idx on public.access_simulations(tenant_id,created_at desc);
create index privilege_requests_tenant_idx on public.privilege_requests(tenant_id,status,created_at desc);
create index privilege_sessions_subject_idx on public.privilege_sessions(subject_identity_id,status,expires_at);
create index session_evidence_tenant_idx on public.session_evidence(tenant_id,sequence desc);

create or replace function private.can_view_runtime_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin','member','auditor'])
$$;

create or replace function private.can_manage_runtime_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_tenant_role(target_tenant,array['owner','admin'])
    or private.can_manage_organization(target_tenant,array['organization_admin','security_admin'])
$$;

create or replace function private.runtime_evidence_event(
  p_tenant_id uuid,p_session_id uuid,p_actor_identity_id uuid,p_event_type text,p_metadata jsonb
) returns bigint language plpgsql security definer set search_path = ''
as $$
declare v_previous bytea; v_hash bytea; v_sequence bigint;
begin
  select event_hash into v_previous from public.session_evidence
    where tenant_id = p_tenant_id order by sequence desc limit 1 for update;
  v_hash := extensions.digest(convert_to(concat_ws('|',p_tenant_id::text,
    coalesce(p_session_id::text,''),coalesce(p_actor_identity_id::text,''),p_event_type,
    coalesce(p_metadata,'{}'::jsonb)::text,coalesce(encode(v_previous,'hex'),''),
    clock_timestamp()::text),'UTF8'),'sha256');
  insert into public.session_evidence(
    tenant_id,session_id,actor_identity_id,event_type,event_metadata,previous_hash,event_hash
  ) values (p_tenant_id,p_session_id,p_actor_identity_id,p_event_type,
    coalesce(p_metadata,'{}'::jsonb),v_previous,v_hash) returning sequence into v_sequence;
  return v_sequence;
end
$$;

create or replace function public.account_deletion_preflight()
returns jsonb language plpgsql stable security invoker set search_path = ''
as $$
declare v_identity uuid := private.current_identity_id(); v_blocking uuid[]; v_personal integer;
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  select coalesce(array_agg(membership.tenant_id),'{}'::uuid[]) into v_blocking
  from public.tenant_memberships membership
  where membership.identity_id = v_identity and membership.role = 'owner' and membership.status = 'active'
    and exists (
      select 1 from public.tenant_memberships other
      where other.tenant_id = membership.tenant_id and other.identity_id <> v_identity and other.status = 'active'
    )
    and not exists (
      select 1 from public.tenant_memberships owner
      where owner.tenant_id = membership.tenant_id and owner.identity_id <> v_identity
        and owner.role = 'owner' and owner.status = 'active'
    );
  select count(*) into v_personal from public.tenants tenant
  join public.tenant_memberships membership on membership.tenant_id = tenant.id
  where membership.identity_id = v_identity and membership.status = 'active'
    and tenant.kind = 'personal' and tenant.created_by = v_identity;
  return jsonb_build_object(
    'can_delete',cardinality(v_blocking) = 0,
    'blocking_tenant_ids',v_blocking,
    'personal_tenant_count',v_personal,
    'requires_recent_reauthentication',true
  );
end
$$;

create or replace function public.account_deletion_storage_paths(p_auth_user_id uuid)
returns table(storage_path text) language sql stable security definer set search_path = ''
as $$
  select version.storage_path
  from public.identities identity
  join public.tenant_memberships membership on membership.identity_id = identity.id
  join public.tenants tenant on tenant.id = membership.tenant_id
  join public.attachments attachment on attachment.tenant_id = tenant.id
  join public.attachment_versions version on version.attachment_id = attachment.id
  where identity.auth_user_id = p_auth_user_id and tenant.kind = 'personal'
    and tenant.created_by = identity.id
$$;

create or replace function public.complete_account_deletion(
  p_auth_user_id uuid,p_request_id uuid
) returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_identity uuid; v_blocking uuid[]; v_personal_tenants uuid[];
begin
  select id into v_identity from public.identities
    where auth_user_id = p_auth_user_id and status = 'active' for update;
  if v_identity is null then raise exception 'active identity not found' using errcode = 'P0002'; end if;
  if not exists (
    select 1 from public.account_deletion_requests request
    where request.id = p_request_id and request.identity_id = v_identity
      and request.auth_user_id = p_auth_user_id and request.status in ('requested','in_progress')
  ) then raise exception 'deletion request not found' using errcode = 'P0002'; end if;

  select coalesce(array_agg(membership.tenant_id),'{}'::uuid[]) into v_blocking
  from public.tenant_memberships membership
  where membership.identity_id = v_identity and membership.role = 'owner' and membership.status = 'active'
    and exists (
      select 1 from public.tenant_memberships other
      where other.tenant_id = membership.tenant_id and other.identity_id <> v_identity and other.status = 'active'
    )
    and not exists (
      select 1 from public.tenant_memberships owner
      where owner.tenant_id = membership.tenant_id and owner.identity_id <> v_identity
        and owner.role = 'owner' and owner.status = 'active'
    );
  if cardinality(v_blocking) > 0 then
    update public.account_deletion_requests set status = 'blocked',blocking_tenant_ids = v_blocking,
      failure_code = 'ownership_transfer_required' where id = p_request_id;
    return jsonb_build_object('deleted',false,'blocking_tenant_ids',v_blocking);
  end if;

  update public.account_deletion_requests set status = 'in_progress' where id = p_request_id;
  select coalesce(array_agg(tenant.id),'{}'::uuid[]) into v_personal_tenants
  from public.tenants tenant
  where tenant.kind = 'personal' and tenant.created_by = v_identity
    and not exists (
      select 1 from public.tenant_memberships other
      where other.tenant_id = tenant.id and other.identity_id <> v_identity and other.status = 'active'
    );

  delete from public.audit_events where tenant_id = any(v_personal_tenants);
  delete from public.session_evidence where tenant_id = any(v_personal_tenants);
  delete from public.tenants where id = any(v_personal_tenants);
  delete from public.key_envelopes where recipient_identity_id = v_identity;
  delete from public.api_tokens where identity_id = v_identity;
  delete from public.devices where identity_id = v_identity;
  delete from public.account_crypto_profiles where identity_id = v_identity;
  delete from public.account_entitlements where identity_id = v_identity;
  delete from public.tenant_sms_subscriptions where identity_id = v_identity;
  delete from public.notification_deliveries where recipient_identity_id = v_identity;
  delete from public.ai_assistant_requests where requested_by = v_identity;
  update public.access_grants set status = 'revoked',revoked_at = coalesce(revoked_at,now())
    where subject_identity_id = v_identity and status = 'active';
  update public.access_requests set status = 'cancelled',updated_at = now()
    where requester_identity_id = v_identity and status = 'pending';
  update public.organization_profiles set lifecycle_status = 'deprovisioned',updated_at = now()
    where identity_id = v_identity and lifecycle_status <> 'deprovisioned';
  update public.organization_admin_assignments set status = 'revoked',updated_at = now()
    where identity_id = v_identity and status <> 'revoked';
  update public.organization_team_memberships set status = 'revoked',updated_at = now()
    where identity_id = v_identity and status <> 'revoked';
  update public.saas_identity_accounts set identity_id = null,owner_state = 'departed'
    where identity_id = v_identity;
  update public.saas_licenses set assigned_identity_id = null,status = 'reclaim_proposed',updated_at = now()
    where assigned_identity_id = v_identity and status in ('assigned','suspended');
  update public.tenant_memberships set status = 'revoked',updated_at = now()
    where identity_id = v_identity and status <> 'revoked';
  update public.identities set status = 'revoked',auth_user_id = null,updated_at = now()
    where id = v_identity;
  update public.account_deletion_requests set status = 'in_progress',failure_code = null
    where id = p_request_id;
  return jsonb_build_object('cleaned',true,'identity_id',v_identity);
end
$$;

create or replace function public.finalize_account_deletion(p_request_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  update public.account_deletion_requests set status = 'completed',completed_at = now(),failure_code = null
    where id = p_request_id and status = 'in_progress';
  return found;
end
$$;

create or replace function public.simulate_access_impact(
  p_tenant_id uuid,p_target_identity_id uuid,p_action_type text,p_proposed_change jsonb default '{}'::jsonb
) returns uuid language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_summary jsonb; v_risk text; v_id uuid; v_hash bytea;
declare v_memberships integer; v_workspaces integer; v_grants integer; v_apps integer; v_sessions integer; v_agents integer;
begin
  if v_actor is null or not private.can_manage_runtime_tenant(p_tenant_id) then
    raise exception 'runtime manager permission required' using errcode = '42501';
  end if;
  if p_action_type not in ('grant','revoke','role_change','kill_agent','delete_account') then
    raise exception 'unsupported simulation action' using errcode = '22023';
  end if;
  if p_target_identity_id is not null and not exists (
    select 1 from public.tenant_memberships membership
    where membership.tenant_id = p_tenant_id and membership.identity_id = p_target_identity_id
  ) then raise exception 'target identity is outside tenant' using errcode = '42501'; end if;
  select count(*) into v_memberships from public.tenant_memberships
    where identity_id = p_target_identity_id and status = 'active';
  select count(*) into v_workspaces from public.workspace_memberships
    where identity_id = p_target_identity_id and status = 'active';
  select count(*) into v_grants from public.access_grants
    where subject_identity_id = p_target_identity_id and status = 'active' and expires_at > now();
  select count(*) into v_apps from public.saas_identity_accounts
    where identity_id = p_target_identity_id and account_status = 'active';
  select count(*) into v_sessions from public.privilege_sessions
    where subject_identity_id = p_target_identity_id and status in ('queued','active','revoking') and expires_at > now();
  select count(*) into v_agents from public.agent_profiles
    where identity_id = p_target_identity_id and status in ('draft','active','suspended');
  v_summary := jsonb_build_object('tenant_memberships',v_memberships,'workspace_memberships',v_workspaces,
    'active_grants',v_grants,'active_saas_accounts',v_apps,'active_privileged_sessions',v_sessions,
    'agent_profiles',v_agents,'effect','preview_only');
  v_risk := case
    when p_action_type in ('delete_account','kill_agent') and (v_sessions > 0 or v_grants > 0) then 'critical'
    when p_action_type in ('grant','role_change') or v_apps + v_workspaces > 3 then 'high'
    when v_memberships + v_grants > 0 then 'medium' else 'low' end;
  v_hash := extensions.digest(convert_to(concat_ws('|',p_tenant_id::text,
    coalesce(p_target_identity_id::text,''),p_action_type,coalesce(p_proposed_change,'{}'::jsonb)::text,
    v_summary::text),'UTF8'),'sha256');
  insert into public.access_simulations(tenant_id,requested_by,target_identity_id,action_type,
    proposed_change,impact_summary,risk_level,graph_sha256)
  values (p_tenant_id,v_actor,p_target_identity_id,p_action_type,coalesce(p_proposed_change,'{}'::jsonb),
    v_summary,v_risk,v_hash) returning id into v_id;
  return v_id;
end
$$;

create or replace function public.create_privileged_resource(
  p_tenant_id uuid,p_display_name text,p_resource_type text,p_adapter_key text,
  p_target_ref_sha256 bytea,p_allowed_scopes text[],p_max_duration_minutes integer default 60
) returns uuid language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_id uuid;
begin
  if v_actor is null or not private.can_manage_runtime_tenant(p_tenant_id)
    or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'Business runtime manager permission required' using errcode = '42501';
  end if;
  insert into public.privileged_resources(tenant_id,display_name,resource_type,adapter_key,
    target_ref_sha256,allowed_scopes,max_duration_minutes,created_by)
  values (p_tenant_id,trim(p_display_name),p_resource_type,p_adapter_key,p_target_ref_sha256,
    p_allowed_scopes,p_max_duration_minutes,v_actor) returning id into v_id;
  insert into public.runtime_activation(tenant_id,updated_by) values (p_tenant_id,v_actor)
    on conflict (tenant_id) do nothing;
  return v_id;
end
$$;

create or replace function public.create_agent_profile(
  p_tenant_id uuid,p_display_name text,p_allowed_scopes text[],p_max_lease_minutes integer default 15
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_identity uuid; v_profile uuid;
begin
  if v_actor is null or not private.can_manage_runtime_tenant(p_tenant_id)
    or not private.has_business_entitlement(p_tenant_id) then
    raise exception 'Business runtime manager permission required' using errcode = '42501';
  end if;
  insert into public.identities(kind,status) values ('agent','active') returning id into v_identity;
  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
    values (p_tenant_id,v_identity,'member','active');
  insert into public.agent_profiles(tenant_id,identity_id,display_name,responsible_owner_identity_id,
    allowed_scopes,max_lease_minutes)
  values (p_tenant_id,v_identity,trim(p_display_name),v_actor,p_allowed_scopes,p_max_lease_minutes)
  returning id into v_profile;
  return v_profile;
end
$$;

create or replace function public.create_privilege_request(
  p_resource_id uuid,p_subject_identity_id uuid,p_requested_scopes text[],
  p_duration_minutes integer,p_justification_sha256 bytea,p_simulation_id uuid default null
) returns uuid language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_resource public.privileged_resources%rowtype; v_id uuid;
begin
  if v_actor is null then raise exception 'active identity required' using errcode = '28000'; end if;
  select * into v_resource from public.privileged_resources resource where resource.id = p_resource_id;
  if not found or not private.has_tenant_role(v_resource.tenant_id,array['owner','admin','member']) then
    raise exception 'resource access denied' using errcode = '42501';
  end if;
  if v_resource.status <> 'active' or not (p_requested_scopes <@ v_resource.allowed_scopes)
    or p_duration_minutes > v_resource.max_duration_minutes then
    raise exception 'request exceeds resource policy' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tenant_memberships membership
    where membership.tenant_id = v_resource.tenant_id and membership.identity_id = p_subject_identity_id
      and membership.status = 'active') then
    raise exception 'subject identity is outside tenant' using errcode = '42501';
  end if;
  insert into public.privilege_requests(tenant_id,resource_id,subject_identity_id,requested_by,
    requested_scopes,requested_duration_minutes,justification_sha256,simulation_id)
  values (v_resource.tenant_id,v_resource.id,p_subject_identity_id,v_actor,p_requested_scopes,
    p_duration_minutes,p_justification_sha256,p_simulation_id) returning id into v_id;
  perform private.runtime_evidence_event(v_resource.tenant_id,null,v_actor,'requested',
    jsonb_build_object('request_id',v_id,'resource_id',v_resource.id,'subject_identity_id',p_subject_identity_id,
      'duration_minutes',p_duration_minutes,'scope_count',cardinality(p_requested_scopes)));
  return v_id;
end
$$;

create or replace function public.decide_privilege_request(p_request_id uuid,p_decision text)
returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_request public.privilege_requests%rowtype;
declare v_activation public.runtime_activation%rowtype; v_status text; v_code text;
begin
  if p_decision not in ('approved','denied') then raise exception 'invalid decision' using errcode = '22023'; end if;
  select * into v_request from public.privilege_requests request where request.id = p_request_id for update;
  if not found or v_actor is null or not private.can_manage_runtime_tenant(v_request.tenant_id) then
    raise exception 'runtime manager permission required' using errcode = '42501';
  end if;
  if v_request.status <> 'pending' or v_request.expires_at <= now() then
    raise exception 'request is not pending' using errcode = '55000';
  end if;
  select * into v_activation from public.runtime_activation activation
    where activation.tenant_id = v_request.tenant_id;
  if p_decision = 'denied' then v_status := 'denied'; v_code := 'manager_denied';
  elsif not coalesce(v_activation.issuance_enabled,false) then
    v_status := 'blocked'; v_code := 'runtime_activation_required';
  else v_status := 'approved'; v_code := 'ready_for_broker'; end if;
  update public.privilege_requests set status = v_status,decided_by = v_actor,decided_at = now(),
    decision_code = v_code where id = p_request_id;
  perform private.runtime_evidence_event(v_request.tenant_id,null,v_actor,
    case when v_status = 'approved' then 'approved' else 'denied' end,
    jsonb_build_object('request_id',v_request.id,'decision_code',v_code));
  return jsonb_build_object('status',v_status,'decision_code',v_code);
end
$$;

create or replace function public.kill_agent(p_agent_profile_id uuid)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_agent public.agent_profiles%rowtype; v_revoked integer;
begin
  select * into v_agent from public.agent_profiles profile where profile.id = p_agent_profile_id for update;
  if not found or v_actor is null or not private.can_manage_runtime_tenant(v_agent.tenant_id) then
    raise exception 'runtime manager permission required' using errcode = '42501';
  end if;
  update public.agent_profiles set status = 'killed',killed_at = now(),updated_at = now()
    where id = v_agent.id and status <> 'killed';
  update public.identities set status = 'revoked',updated_at = now() where id = v_agent.identity_id;
  update public.credential_leases lease set revoked_at = coalesce(lease.revoked_at,now())
    from public.privilege_sessions session
    where lease.session_id = session.id and session.tenant_id = v_agent.tenant_id
      and session.subject_identity_id = v_agent.identity_id and lease.revoked_at is null;
  update public.privilege_sessions set status = 'revoked',revoked_at = coalesce(revoked_at,now()),
    revoke_reason = 'agent_killed',updated_at = now()
    where tenant_id = v_agent.tenant_id and subject_identity_id = v_agent.identity_id
      and status in ('queued','active','revoking');
  get diagnostics v_revoked = row_count;
  perform private.runtime_evidence_event(v_agent.tenant_id,null,v_actor,'agent_killed',
    jsonb_build_object('agent_profile_id',v_agent.id,'identity_id',v_agent.identity_id,
      'sessions_revoked',v_revoked));
  return jsonb_build_object('status','killed','sessions_revoked',v_revoked);
end
$$;

create or replace function public.runtime_dashboard(p_tenant_id uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$
  select case when private.can_view_runtime_tenant(p_tenant_id) then jsonb_build_object(
    'activation',(select jsonb_build_object('control_plane_enabled',activation.control_plane_enabled,
      'issuance_enabled',activation.issuance_enabled,'kill_switch_active',activation.kill_switch_active,
      'review_status',activation.review_status,'adapter_status',activation.adapter_status)
      from public.runtime_activation activation where activation.tenant_id = p_tenant_id),
    'resources',(select count(*) from public.privileged_resources resource where resource.tenant_id = p_tenant_id),
    'agents',(select count(*) from public.agent_profiles profile where profile.tenant_id = p_tenant_id and profile.status <> 'killed'),
    'pending_requests',(select count(*) from public.privilege_requests request where request.tenant_id = p_tenant_id and request.status = 'pending'),
    'active_sessions',(select count(*) from public.privilege_sessions session where session.tenant_id = p_tenant_id and session.status = 'active'),
    'evidence_events',(select count(*) from public.session_evidence evidence where evidence.tenant_id = p_tenant_id)
  ) else null end
$$;

create or replace function public.begin_ai_assistant_request(
  p_tenant_id uuid,p_use_case text,p_prompt_sha256 bytea,p_context_categories text[]
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_id uuid; v_recent integer;
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
  insert into public.ai_assistant_requests(
    tenant_id,requested_by,use_case,prompt_sha256,context_categories
  ) values (p_tenant_id,v_actor,p_use_case,p_prompt_sha256,p_context_categories)
  returning id into v_id;
  return v_id;
end
$$;

create or replace function public.complete_ai_assistant_request(
  p_request_id uuid,p_status text,p_input_tokens integer,p_output_tokens integer,p_failure_code text default null
) returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or p_status not in ('completed','blocked','failed')
    or coalesce(p_input_tokens,0) not between 0 and 1000000
    or coalesce(p_output_tokens,0) not between 0 and 1000000
    or (p_failure_code is not null and p_failure_code !~ '^[a-z0-9_]{2,64}$') then
    raise exception 'invalid AI completion' using errcode = '22023';
  end if;
  update public.ai_assistant_requests set status = p_status,input_tokens = p_input_tokens,
    output_tokens = p_output_tokens,failure_code = p_failure_code,completed_at = now()
    where id = p_request_id and requested_by = v_actor and status = 'accepted';
  return found;
end
$$;

create or replace function public.apply_sent_notification_event(
  p_provider_message_id text,p_event_name text,p_provider_status text,
  p_happened_at timestamptz,p_payload_sha256 bytea
) returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_delivery uuid; v_status text;
begin
  if length(p_provider_message_id) < 8 or length(p_event_name) < 3
    or octet_length(p_payload_sha256) <> 32 then
    raise exception 'invalid notification event' using errcode = '22023';
  end if;
  select id into v_delivery from public.notification_deliveries
    where provider = 'sent' and provider_message_id = p_provider_message_id for update;
  if not found then return false; end if;
  insert into public.notification_delivery_events(
    delivery_id,provider_event_name,provider_status,payload_sha256,happened_at
  ) values (v_delivery,p_event_name,p_provider_status,p_payload_sha256,p_happened_at)
  on conflict (delivery_id,provider_event_name,happened_at) do nothing;
  v_status := case lower(p_provider_status)
    when 'queued' then 'queued' when 'accepted' then 'accepted'
    when 'sent' then 'accepted' when 'delivered' then 'delivered'
    when 'read' then 'read' when 'failed' then 'failed'
    when 'blocked' then 'blocked' when 'filtered' then 'filtered'
    else 'unknown' end;
  update public.notification_deliveries set status = v_status,
    delivered_at = case when v_status in ('delivered','read') then p_happened_at else delivered_at end,
    updated_at = now() where id = v_delivery;
  return true;
end
$$;

alter table public.account_deletion_requests enable row level security;
alter table public.tenant_notification_settings enable row level security;
alter table public.tenant_sms_credentials enable row level security;
alter table public.tenant_sms_subscriptions enable row level security;
alter table public.notification_deliveries enable row level security;
alter table public.sms_verification_challenges enable row level security;
alter table public.notification_delivery_events enable row level security;
alter table public.ai_assistant_requests enable row level security;
alter table public.runtime_activation enable row level security;
alter table public.privileged_resources enable row level security;
alter table public.agent_profiles enable row level security;
alter table public.access_simulations enable row level security;
alter table public.privilege_requests enable row level security;
alter table public.privilege_sessions enable row level security;
alter table public.credential_leases enable row level security;
alter table public.agent_task_capsules enable row level security;
alter table public.access_graph_snapshots enable row level security;
alter table public.session_evidence enable row level security;

revoke all on public.account_deletion_requests,public.tenant_notification_settings,
  public.tenant_sms_credentials,public.tenant_sms_subscriptions,public.notification_deliveries,
  public.sms_verification_challenges,
  public.notification_delivery_events,
  public.ai_assistant_requests,public.runtime_activation,public.privileged_resources,
  public.agent_profiles,public.access_simulations,public.privilege_requests,
  public.privilege_sessions,public.credential_leases,public.agent_task_capsules,
  public.access_graph_snapshots,public.session_evidence from public,anon,authenticated;

grant select on public.account_deletion_requests,public.tenant_notification_settings,
  public.notification_deliveries,public.ai_assistant_requests,public.runtime_activation,
  public.privileged_resources,public.agent_profiles,public.access_simulations,
  public.privilege_requests,public.privilege_sessions,public.agent_task_capsules,
  public.access_graph_snapshots,public.session_evidence to authenticated;
grant insert,update,delete on public.agent_task_capsules to authenticated;
grant select,insert,update,delete on public.account_deletion_requests,
  public.tenant_notification_settings,public.tenant_sms_credentials,
  public.tenant_sms_subscriptions,public.notification_deliveries,public.sms_verification_challenges,
  public.notification_delivery_events,
  public.ai_assistant_requests,public.runtime_activation,public.privileged_resources,
  public.agent_profiles,public.access_simulations,public.privilege_requests,
  public.privilege_sessions,public.credential_leases,public.agent_task_capsules,
  public.access_graph_snapshots,public.session_evidence to service_role;

create policy account_deletion_requests_read_self on public.account_deletion_requests for select to authenticated
  using (identity_id = (select private.current_identity_id()));
create policy tenant_notification_settings_read on public.tenant_notification_settings for select to authenticated
  using ((select private.can_view_runtime_tenant(tenant_id)));
create policy notification_deliveries_read on public.notification_deliveries for select to authenticated
  using (recipient_identity_id = (select private.current_identity_id())
    or (select private.can_manage_runtime_tenant(tenant_id)));
create policy ai_assistant_requests_read on public.ai_assistant_requests for select to authenticated
  using (requested_by = (select private.current_identity_id())
    or (select private.can_manage_runtime_tenant(tenant_id)));
create policy runtime_activation_read on public.runtime_activation for select to authenticated
  using ((select private.can_view_runtime_tenant(tenant_id)));
create policy privileged_resources_read on public.privileged_resources for select to authenticated
  using ((select private.can_view_runtime_tenant(tenant_id)));
create policy agent_profiles_read on public.agent_profiles for select to authenticated
  using ((select private.can_view_runtime_tenant(tenant_id)));
create policy access_simulations_read on public.access_simulations for select to authenticated
  using ((select private.can_manage_runtime_tenant(tenant_id)));
create policy privilege_requests_read on public.privilege_requests for select to authenticated
  using (requested_by = (select private.current_identity_id())
    or subject_identity_id = (select private.current_identity_id())
    or (select private.can_manage_runtime_tenant(tenant_id)));
create policy privilege_sessions_read on public.privilege_sessions for select to authenticated
  using (subject_identity_id = (select private.current_identity_id())
    or (select private.can_manage_runtime_tenant(tenant_id)));
create policy agent_task_capsules_read on public.agent_task_capsules for select to authenticated
  using ((select private.can_view_runtime_tenant(tenant_id)));
create policy agent_task_capsules_manage on public.agent_task_capsules for all to authenticated
  using ((select private.can_manage_runtime_tenant(tenant_id)))
  with check ((select private.can_manage_runtime_tenant(tenant_id))
    and created_by = (select private.current_identity_id()));
create policy access_graph_snapshots_read on public.access_graph_snapshots for select to authenticated
  using ((select private.can_manage_runtime_tenant(tenant_id)));
create policy session_evidence_read on public.session_evidence for select to authenticated
  using ((select private.can_manage_runtime_tenant(tenant_id))
    or actor_identity_id = (select private.current_identity_id()));

create trigger tenant_notification_settings_audit after insert or update on public.tenant_notification_settings
  for each row execute function private.phase2_audit_event();
create trigger privileged_resources_audit after insert or update on public.privileged_resources
  for each row execute function private.phase2_audit_event();
create trigger agent_profiles_audit after insert or update on public.agent_profiles
  for each row execute function private.phase2_audit_event();
create trigger privilege_requests_audit after insert or update on public.privilege_requests
  for each row execute function private.phase2_audit_event();
create trigger privilege_sessions_audit after insert or update on public.privilege_sessions
  for each row execute function private.phase2_audit_event();

revoke all on function private.can_view_runtime_tenant(uuid),private.can_manage_runtime_tenant(uuid),
  private.runtime_evidence_event(uuid,uuid,uuid,text,jsonb) from public,anon,authenticated;
revoke all on function public.account_deletion_preflight() from public,anon;
revoke all on function public.account_deletion_storage_paths(uuid),
  public.complete_account_deletion(uuid,uuid),public.finalize_account_deletion(uuid)
  from public,anon,authenticated;
revoke all on function public.simulate_access_impact(uuid,uuid,text,jsonb),
  public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer),
  public.create_agent_profile(uuid,text,text[],integer),
  public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid),
  public.decide_privilege_request(uuid,text),public.kill_agent(uuid),
  public.runtime_dashboard(uuid),
  public.begin_ai_assistant_request(uuid,text,bytea,text[]),
  public.complete_ai_assistant_request(uuid,text,integer,integer,text) from public,anon;
revoke all on function public.apply_sent_notification_event(text,text,text,timestamptz,bytea)
  from public,anon,authenticated;
grant execute on function public.account_deletion_preflight(),
  public.simulate_access_impact(uuid,uuid,text,jsonb),
  public.create_privileged_resource(uuid,text,text,text,bytea,text[],integer),
  public.create_agent_profile(uuid,text,text[],integer),
  public.create_privilege_request(uuid,uuid,text[],integer,bytea,uuid),
  public.decide_privilege_request(uuid,text),public.kill_agent(uuid),
  public.runtime_dashboard(uuid),
  public.begin_ai_assistant_request(uuid,text,bytea,text[]),
  public.complete_ai_assistant_request(uuid,text,integer,integer,text) to authenticated;
grant execute on function public.account_deletion_storage_paths(uuid),
  public.complete_account_deletion(uuid,uuid),public.finalize_account_deletion(uuid),
  private.runtime_evidence_event(uuid,uuid,uuid,text,jsonb) to service_role;
grant execute on function public.apply_sent_notification_event(text,text,text,timestamptz,bytea)
  to service_role;

comment on table public.tenant_sms_credentials is
  'Application-encrypted, backend-only tenant Sent credentials. Never readable by browser roles.';
comment on table public.credential_leases is
  'Backend-only short-lived broker references. Credential values are prohibited.';
comment on table public.session_evidence is
  'Append-only, hash-chained Flight Recorder metadata. Secret values and command output are prohibited.';
comment on function public.simulate_access_impact(uuid,uuid,text,jsonb) is
  'Access Twin preview. Computes impact only and never mutates authorization.';
comment on table public.runtime_activation is
  'Fail-closed Phase 6 activation gate. Issuance requires accepted review evidence and a production-certified adapter.';

commit;
