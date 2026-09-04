begin;

-- Phase 2: Family, Professional and Team collaboration. All labels, mission
-- definitions, purposes and shared item payloads remain client-encrypted.

alter table public.account_entitlements
  drop constraint if exists account_entitlements_plan_code_check;
alter table public.account_entitlements
  add constraint account_entitlements_plan_code_check
  check (plan_code in ('free','personal','family','professional','team'));
alter table public.account_entitlements
  add column phase2_preview_enabled boolean not null default true;

alter table public.workspaces
  add column suite text not null default 'personal',
  add column name_nonce bytea,
  add column name_aad_hash bytea,
  add column current_key_version integer not null default 1,
  add column key_rotation_required boolean not null default false,
  add column status text not null default 'active';
alter table public.workspaces
  add constraint workspaces_suite_check check (suite in ('personal','family','professional','team')),
  add constraint workspaces_name_nonce_length check (name_nonce is null or octet_length(name_nonce) = 12),
  add constraint workspaces_name_aad_hash_length check (name_aad_hash is null or octet_length(name_aad_hash) = 32),
  add constraint workspaces_key_version_positive check (current_key_version > 0),
  add constraint workspaces_status_check check (status in ('active','archived','closed'));

create table public.workspace_invites (
  id uuid primary key,
  tenant_id uuid not null,
  workspace_id uuid not null,
  created_by uuid not null references public.identities(id) on delete restrict,
  recipient_email_hash bytea not null check (octet_length(recipient_email_hash) = 32),
  role text not null check (role in ('manager','editor','viewer')),
  token_hash bytea unique check (token_hash is null or octet_length(token_hash) = 32),
  key_nonce bytea not null check (octet_length(key_nonce) = 12),
  wrapped_workspace_key bytea not null check (octet_length(wrapped_workspace_key) >= 48),
  key_aad_hash bytea not null check (octet_length(key_aad_hash) = 32),
  status text not null default 'pending' check (status in ('pending','accepted','revoked','expired')),
  expires_at timestamptz not null,
  accepted_by uuid references public.identities(id) on delete set null,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  check (expires_at > created_at),
  check ((accepted_by is null) = (accepted_at is null)),
  check (status <> 'accepted' or (accepted_by is not null and accepted_at is not null)),
  check ((status = 'revoked') = (revoked_at is not null))
);

create table public.access_capsules (
  id uuid primary key,
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid not null,
  created_by uuid not null references public.identities(id) on delete restrict,
  recipient_email_hash bytea not null check (octet_length(recipient_email_hash) = 32),
  reveal_policy text not null check (reveal_policy in ('reveal','fill_only')),
  purpose_code text not null default 'other' check (purpose_code in ('family','client','project','support','handover','other')),
  payload_nonce bytea not null check (octet_length(payload_nonce) = 12),
  payload_ciphertext bytea not null check (octet_length(payload_ciphertext) >= 16),
  payload_aad_hash bytea not null check (octet_length(payload_aad_hash) = 32),
  token_hash bytea unique check (token_hash is null or octet_length(token_hash) = 32),
  invite_key_nonce bytea not null check (octet_length(invite_key_nonce) = 12),
  invite_wrapped_key bytea not null check (octet_length(invite_wrapped_key) >= 48),
  invite_key_aad_hash bytea not null check (octet_length(invite_key_aad_hash) = 32),
  recipient_key_nonce bytea,
  recipient_wrapped_key bytea,
  recipient_key_aad_hash bytea,
  status text not null default 'pending' check (status in ('pending','accepted','revoked','expired','consumed')),
  not_before timestamptz not null default now(),
  expires_at timestamptz not null,
  max_uses integer not null default 0 check (max_uses >= 0 and max_uses <= 100000),
  use_count integer not null default 0 check (use_count >= 0),
  requires_approval boolean not null default false,
  accepted_by uuid references public.identities(id) on delete set null,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  check (expires_at > not_before and expires_at > created_at),
  check (recipient_key_nonce is null or octet_length(recipient_key_nonce) = 12),
  check (recipient_wrapped_key is null or octet_length(recipient_wrapped_key) >= 48),
  check (recipient_key_aad_hash is null or octet_length(recipient_key_aad_hash) = 32),
  check ((accepted_by is null) = (accepted_at is null)),
  check (status not in ('accepted','consumed') or (accepted_by is not null and accepted_at is not null)),
  check ((status = 'revoked') = (revoked_at is not null)),
  check (use_count <= case when max_uses = 0 then 100000 else max_uses end)
);

create table public.access_requests (
  id uuid primary key,
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid,
  requester_identity_id uuid not null references public.identities(id) on delete cascade,
  requested_scope text not null check (requested_scope in ('use','reveal','edit','manage')),
  purpose_nonce bytea not null check (octet_length(purpose_nonce) = 12),
  encrypted_purpose bytea not null check (octet_length(encrypted_purpose) >= 16),
  purpose_aad_hash bytea not null check (octet_length(purpose_aad_hash) = 32),
  requested_duration_minutes integer not null check (requested_duration_minutes between 5 and 10080),
  status text not null default 'pending' check (status in ('pending','approved','denied','cancelled','expired')),
  expires_at timestamptz not null,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  check (expires_at > created_at)
);

create table public.approvals (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workspace_id uuid not null,
  request_id uuid not null references public.access_requests(id) on delete cascade,
  approver_identity_id uuid not null references public.identities(id) on delete restrict,
  decision text not null check (decision in ('approved','denied')),
  created_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  unique (request_id, approver_identity_id)
);

create table public.access_grants (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workspace_id uuid not null,
  item_id uuid,
  subject_identity_id uuid not null references public.identities(id) on delete cascade,
  scope text not null check (scope in ('use','reveal','edit','manage')),
  source_request_id uuid references public.access_requests(id) on delete set null,
  starts_at timestamptz not null default now(),
  expires_at timestamptz not null,
  status text not null default 'active' check (status in ('active','revoked','expired')),
  created_by uuid not null references public.identities(id) on delete restrict,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  check (expires_at > starts_at),
  check ((status = 'revoked') = (revoked_at is not null))
);

create table public.missions (
  id uuid primary key,
  tenant_id uuid not null,
  workspace_id uuid not null,
  created_by uuid not null references public.identities(id) on delete restrict,
  definition_nonce bytea not null check (octet_length(definition_nonce) = 12),
  encrypted_definition bytea not null check (octet_length(encrypted_definition) >= 16),
  definition_aad_hash bytea not null check (octet_length(definition_aad_hash) = 32),
  status text not null default 'active' check (status in ('active','archived')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.mission_items (
  mission_id uuid not null references public.missions(id) on delete cascade,
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid not null,
  sort_order integer not null default 0 check (sort_order >= 0),
  primary key (mission_id, item_id),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade
);

create table public.mission_runs (
  id uuid primary key default gen_random_uuid(),
  mission_id uuid not null references public.missions(id) on delete cascade,
  tenant_id uuid not null,
  workspace_id uuid not null,
  started_by uuid not null references public.identities(id) on delete cascade,
  status text not null default 'running' check (status in ('running','completed','cancelled','expired')),
  started_at timestamptz not null default now(),
  expires_at timestamptz not null,
  finished_at timestamptz,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  check (expires_at > started_at)
);

create index workspace_invites_recipient_active_idx on public.workspace_invites(recipient_email_hash, expires_at)
  where status = 'pending';
create index workspace_invites_workspace_idx on public.workspace_invites(tenant_id, workspace_id, created_at desc);
create index access_capsules_recipient_active_idx on public.access_capsules(recipient_email_hash, expires_at)
  where status in ('pending','accepted');
create index access_capsules_workspace_idx on public.access_capsules(tenant_id, workspace_id, created_at desc);
create index access_requests_pending_idx on public.access_requests(tenant_id, workspace_id, created_at)
  where status = 'pending';
create index access_grants_subject_active_idx on public.access_grants(subject_identity_id, expires_at)
  where status = 'active';
create index missions_workspace_idx on public.missions(tenant_id, workspace_id, updated_at desc)
  where status = 'active';
create index mission_items_item_idx on public.mission_items(item_id, mission_id);
create index mission_runs_active_idx on public.mission_runs(mission_id, expires_at)
  where status = 'running';

create or replace function private.phase2_enabled()
returns boolean language sql stable security definer set search_path = ''
as $$
  select coalesce((
    select e.phase2_preview_enabled or e.plan_code in ('family','professional','team')
    from public.account_entitlements e
    where e.identity_id = private.current_identity_id()
  ), false)
$$;

create or replace function private.current_verified_email_hash()
returns bytea language sql stable security definer set search_path = ''
as $$
  select extensions.digest(convert_to(lower(trim(u.email)), 'UTF8'), 'sha256')
  from auth.users u
  where u.id = auth.uid()
    and u.email is not null
    and u.email_confirmed_at is not null
  limit 1
$$;

create or replace function private.can_manage_workspace(target_tenant uuid, target_workspace uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select private.has_workspace_role(target_tenant, target_workspace, array['owner','manager'])
$$;

create or replace function private.owns_phase2_tenant(target_tenant uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.tenants t
    where t.id = target_tenant
      and t.kind in ('family','organization')
      and t.created_by = private.current_identity_id()
  )
$$;

create or replace function private.owns_phase2_workspace(target_tenant uuid, target_workspace uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.workspaces w
    where w.tenant_id = target_tenant
      and w.id = target_workspace
      and w.created_by = private.current_identity_id()
      and w.suite in ('family','professional','team')
      and private.owns_phase2_tenant(target_tenant)
  )
$$;

revoke all on function private.phase2_enabled() from public, anon;
revoke all on function private.current_verified_email_hash() from public, anon;
revoke all on function private.can_manage_workspace(uuid,uuid) from public, anon;
revoke all on function private.owns_phase2_tenant(uuid) from public, anon;
revoke all on function private.owns_phase2_workspace(uuid,uuid) from public, anon;
grant execute on function private.phase2_enabled() to authenticated;
grant execute on function private.current_verified_email_hash() to authenticated;
grant execute on function private.can_manage_workspace(uuid,uuid) to authenticated;
grant execute on function private.owns_phase2_tenant(uuid) to authenticated;
grant execute on function private.owns_phase2_workspace(uuid,uuid) to authenticated;

alter table public.workspace_invites enable row level security;
alter table public.access_capsules enable row level security;
alter table public.access_requests enable row level security;
alter table public.approvals enable row level security;
alter table public.access_grants enable row level security;
alter table public.missions enable row level security;
alter table public.mission_items enable row level security;
alter table public.mission_runs enable row level security;

revoke all on public.workspace_invites, public.access_capsules, public.access_requests,
  public.approvals, public.access_grants, public.missions, public.mission_items,
  public.mission_runs from anon, authenticated;

grant select (id,tenant_id,workspace_id,created_by,recipient_email_hash,role,key_nonce,
  token_hash,wrapped_workspace_key,key_aad_hash,status,expires_at,accepted_by,accepted_at,revoked_at,
  created_at,updated_at) on public.workspace_invites to authenticated;
grant insert (id,tenant_id,workspace_id,created_by,recipient_email_hash,role,token_hash,
  key_nonce,wrapped_workspace_key,key_aad_hash,status,expires_at)
  on public.workspace_invites to authenticated;
grant update (token_hash,status,accepted_by,accepted_at,revoked_at,updated_at)
  on public.workspace_invites to authenticated;

grant select (id,tenant_id,workspace_id,item_id,created_by,recipient_email_hash,reveal_policy,
  purpose_code,payload_nonce,payload_ciphertext,payload_aad_hash,invite_key_nonce,
  token_hash,invite_wrapped_key,invite_key_aad_hash,recipient_key_nonce,recipient_wrapped_key,
  recipient_key_aad_hash,status,not_before,expires_at,max_uses,use_count,requires_approval,
  accepted_by,accepted_at,revoked_at,created_at,updated_at)
  on public.access_capsules to authenticated;
grant insert (id,tenant_id,workspace_id,item_id,created_by,recipient_email_hash,reveal_policy,
  purpose_code,payload_nonce,payload_ciphertext,payload_aad_hash,token_hash,invite_key_nonce,
  invite_wrapped_key,invite_key_aad_hash,status,not_before,expires_at,max_uses,requires_approval)
  on public.access_capsules to authenticated;
grant update (token_hash,recipient_key_nonce,recipient_wrapped_key,recipient_key_aad_hash,
  status,use_count,accepted_by,accepted_at,revoked_at,updated_at)
  on public.access_capsules to authenticated;

grant select, insert on public.access_requests to authenticated;
grant update (status,decided_at,updated_at) on public.access_requests to authenticated;
grant select, insert on public.approvals to authenticated;
grant select, insert on public.access_grants to authenticated;
grant update (status,revoked_at) on public.access_grants to authenticated;
grant select, insert, update on public.missions to authenticated;
grant select, insert, delete on public.mission_items to authenticated;
grant select, insert, update on public.mission_runs to authenticated;
grant insert (id,kind,created_by,encrypted_name) on public.tenants to authenticated;
grant insert (id,tenant_id,kind,encrypted_name,created_by,suite,name_nonce,name_aad_hash,
  current_key_version,key_rotation_required,status) on public.workspaces to authenticated;

create policy tenants_phase2_create on public.tenants for insert to authenticated
with check (
  kind in ('family','organization')
  and created_by = (select private.current_identity_id())
  and (select private.phase2_enabled())
);

create policy tenant_memberships_phase2_owner on public.tenant_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and role = 'owner' and status = 'active'
  and (select private.owns_phase2_tenant(tenant_id))
);

create policy workspaces_phase2_create on public.workspaces for insert to authenticated
with check (
  kind in ('project','client','shared')
  and suite in ('family','professional','team')
  and created_by = (select private.current_identity_id())
  and (select private.owns_phase2_tenant(tenant_id))
  and (select private.phase2_enabled())
);

create policy workspace_memberships_phase2_owner on public.workspace_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and role = 'owner' and status = 'active'
  and (select private.owns_phase2_workspace(tenant_id, workspace_id))
);

create policy workspace_invites_read on public.workspace_invites for select to authenticated
using (
  (select private.can_manage_workspace(tenant_id, workspace_id))
  or (
    status = 'pending' and expires_at > now()
    and recipient_email_hash = (select private.current_verified_email_hash())
  )
  or (
    status = 'accepted' and accepted_by = (select private.current_identity_id())
    and (
      (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer']))
      or current_setting('request.passkey_x_invite_accepting', true) = id::text
    )
  )
);

create policy workspace_invites_create on public.workspace_invites for insert to authenticated
with check (
  created_by = (select private.current_identity_id())
  and status = 'pending' and accepted_by is null and revoked_at is null
  and expires_at > now() and expires_at <= now() + interval '30 days'
  and (select private.can_manage_workspace(tenant_id, workspace_id))
  and (select private.phase2_enabled())
);

create policy workspace_invites_accept on public.workspace_invites for update to authenticated
using (
  status = 'pending' and expires_at > now()
  and recipient_email_hash = (select private.current_verified_email_hash())
  and token_hash = decode(coalesce(current_setting('request.passkey_x_invite_proof', true), ''), 'hex')
)
with check (
  status = 'accepted'
  and accepted_by = (select private.current_identity_id())
  and accepted_at is not null and revoked_at is null
);

create policy workspace_invites_revoke on public.workspace_invites for update to authenticated
using (
  (select private.can_manage_workspace(tenant_id, workspace_id))
  and current_setting('request.passkey_x_invite_revoke', true) = id::text
)
with check (status = 'revoked' and revoked_at is not null);

create policy tenant_memberships_invite_accept on public.tenant_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and role = 'member' and status = 'active'
  and exists (
    select 1 from public.workspace_invites wi
    where wi.tenant_id = tenant_id and wi.accepted_by = identity_id and wi.status = 'accepted'
  )
);

create policy workspace_memberships_invite_accept on public.workspace_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and status = 'active'
  and exists (
    select 1 from public.workspace_invites wi
    where wi.tenant_id = tenant_id and wi.workspace_id = workspace_id
      and wi.accepted_by = identity_id and wi.status = 'accepted' and wi.role = role
  )
);

drop policy if exists key_envelopes_read on public.key_envelopes;
create policy key_envelopes_read on public.key_envelopes for select to authenticated
using (
  revoked_at is null and workspace_id is not null
  and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer']))
  and (
    recipient_identity_id = (select private.current_identity_id())
    or recipient_device_id in (
      select d.id from public.devices d
      where d.identity_id = (select private.current_identity_id()) and d.status = 'trusted'
    )
  )
);

create policy key_envelopes_recipient_insert on public.key_envelopes for insert to authenticated
with check (
  workspace_id is not null and key_kind = 'workspace'
  and recipient_identity_id = (select private.current_identity_id())
  and recipient_device_id is null and revoked_at is null
  and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer']))
);

create policy access_capsules_read on public.access_capsules for select to authenticated
using (
  (select private.can_manage_workspace(tenant_id, workspace_id))
  or (
    status = 'pending' and now() between not_before and expires_at
    and recipient_email_hash = (select private.current_verified_email_hash())
  )
  or (
    status = 'accepted' and accepted_by = (select private.current_identity_id())
    and now() between not_before and expires_at
    and (max_uses = 0 or use_count < max_uses)
  )
  or (
    accepted_by = (select private.current_identity_id())
    and current_setting('request.passkey_x_capsule_consume', true) = id::text
  )
);

create policy access_capsules_create on public.access_capsules for insert to authenticated
with check (
  created_by = (select private.current_identity_id()) and status = 'pending'
  and accepted_by is null and revoked_at is null
  and expires_at > now() and expires_at <= now() + interval '30 days'
  and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor']))
  and (select private.phase2_enabled())
);

create policy access_capsules_accept on public.access_capsules for update to authenticated
using (
  status = 'pending' and now() between not_before and expires_at
  and recipient_email_hash = (select private.current_verified_email_hash())
  and token_hash = decode(coalesce(current_setting('request.passkey_x_capsule_proof', true), ''), 'hex')
)
with check (
  status = 'accepted' and accepted_by = (select private.current_identity_id())
  and accepted_at is not null and recipient_key_nonce is not null
  and recipient_wrapped_key is not null and recipient_key_aad_hash is not null
  and revoked_at is null
);

create policy access_capsules_consume on public.access_capsules for update to authenticated
using (
  status = 'accepted' and accepted_by = (select private.current_identity_id())
  and now() between not_before and expires_at
  and current_setting('request.passkey_x_capsule_consume', true) = id::text
)
with check (
  accepted_by = (select private.current_identity_id())
  and status in ('accepted','consumed')
  and use_count <= case when max_uses = 0 then 100000 else max_uses end
);

create policy access_capsules_revoke on public.access_capsules for update to authenticated
using (
  (select private.can_manage_workspace(tenant_id, workspace_id))
  and current_setting('request.passkey_x_capsule_revoke', true) = id::text
)
with check (status = 'revoked' and revoked_at is not null);

create policy access_requests_read on public.access_requests for select to authenticated
using (
  requester_identity_id = (select private.current_identity_id())
  or (select private.can_manage_workspace(tenant_id, workspace_id))
);
create policy access_requests_create on public.access_requests for insert to authenticated
with check (
  requester_identity_id = (select private.current_identity_id())
  and status = 'pending' and expires_at > now()
  and (select private.has_workspace_role(tenant_id, workspace_id, array['manager','editor','viewer']))
);
create policy access_requests_decide on public.access_requests for update to authenticated
using (
  status = 'pending' and (select private.can_manage_workspace(tenant_id, workspace_id))
  and current_setting('request.passkey_x_approval', true) = id::text
)
with check (status in ('approved','denied') and decided_at is not null);

create policy approvals_read on public.approvals for select to authenticated
using (
  approver_identity_id = (select private.current_identity_id())
  or exists (
    select 1 from public.access_requests ar
    where ar.id = request_id and ar.requester_identity_id = (select private.current_identity_id())
  )
  or (select private.can_manage_workspace(tenant_id, workspace_id))
);
create policy approvals_create on public.approvals for insert to authenticated
with check (
  approver_identity_id = (select private.current_identity_id())
  and (select private.can_manage_workspace(tenant_id, workspace_id))
  and exists (
    select 1 from public.access_requests ar
    where ar.id = request_id and ar.status = 'pending'
      and ar.tenant_id = tenant_id and ar.workspace_id = workspace_id
  )
);

create policy access_grants_read on public.access_grants for select to authenticated
using (
  subject_identity_id = (select private.current_identity_id())
  or (select private.can_manage_workspace(tenant_id, workspace_id))
);
create policy access_grants_create on public.access_grants for insert to authenticated
with check (
  created_by = (select private.current_identity_id())
  and (select private.can_manage_workspace(tenant_id, workspace_id))
  and source_request_id is not null
);
create policy access_grants_revoke on public.access_grants for update to authenticated
using ((select private.can_manage_workspace(tenant_id, workspace_id)))
with check (status = 'revoked' and revoked_at is not null);

create policy missions_read on public.missions for select to authenticated
using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy missions_create on public.missions for insert to authenticated
with check (
  created_by = (select private.current_identity_id())
  and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor']))
);
create policy missions_update on public.missions for update to authenticated
using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])))
with check ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));

create policy mission_items_read on public.mission_items for select to authenticated
using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy mission_items_create on public.mission_items for insert to authenticated
with check (
  (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor']))
  and exists (select 1 from public.missions m where m.id = mission_id and m.tenant_id = tenant_id and m.workspace_id = workspace_id)
);
create policy mission_items_delete on public.mission_items for delete to authenticated
using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));

create policy mission_runs_read on public.mission_runs for select to authenticated
using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy mission_runs_create on public.mission_runs for insert to authenticated
with check (
  started_by = (select private.current_identity_id()) and status = 'running'
  and expires_at <= now() + interval '12 hours'
  and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer']))
);
create policy mission_runs_finish on public.mission_runs for update to authenticated
using (started_by = (select private.current_identity_id()) and status = 'running')
with check (started_by = (select private.current_identity_id()) and status in ('completed','cancelled') and finished_at is not null);

create or replace function public.create_shared_workspace(
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_suite text,
  p_workspace_kind text,
  p_encrypted_name bytea,
  p_name_nonce bytea,
  p_name_aad_hash bytea,
  p_key_nonce bytea,
  p_wrapped_workspace_key bytea
) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_tenant_kind text;
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  if not private.phase2_enabled() then raise exception 'phase 2 entitlement required' using errcode = '42501'; end if;
  if p_suite not in ('family','professional','team') then raise exception 'invalid suite' using errcode = '22023'; end if;
  if octet_length(p_name_nonce) <> 12 or octet_length(p_name_aad_hash) <> 32
    or octet_length(p_key_nonce) <> 12 or octet_length(p_wrapped_workspace_key) < 48
    or octet_length(p_encrypted_name) < 16 then
    raise exception 'invalid encrypted workspace envelope' using errcode = '22023';
  end if;
  if (p_suite = 'family' and p_workspace_kind <> 'shared')
    or (p_suite = 'professional' and p_workspace_kind not in ('client','project'))
    or (p_suite = 'team' and p_workspace_kind not in ('shared','project')) then
    raise exception 'workspace kind does not match suite' using errcode = '22023';
  end if;

  v_tenant_kind := case when p_suite = 'family' then 'family' else 'organization' end;
  insert into public.tenants(id, kind, created_by) values (p_tenant_id, v_tenant_kind, v_identity);
  insert into public.tenant_memberships(tenant_id, identity_id, role, status)
    values (p_tenant_id, v_identity, 'owner', 'active');
  insert into public.workspaces(id, tenant_id, kind, encrypted_name, created_by, suite,
    name_nonce, name_aad_hash, current_key_version, key_rotation_required, status)
    values (p_workspace_id, p_tenant_id, p_workspace_kind, p_encrypted_name, v_identity,
      p_suite, p_name_nonce, p_name_aad_hash, 1, false, 'active');
  insert into public.workspace_memberships(tenant_id, workspace_id, identity_id, role, status)
    values (p_tenant_id, p_workspace_id, v_identity, 'owner', 'active');
  insert into public.key_envelopes(tenant_id, workspace_id, key_kind, key_version,
    recipient_identity_id, algorithm, nonce, wrapped_key)
    values (p_tenant_id, p_workspace_id, 'workspace', 1, v_identity,
      'AES-256-GCM', p_key_nonce, p_wrapped_workspace_key);

  return jsonb_build_object('tenant_id', p_tenant_id, 'workspace_id', p_workspace_id, 'suite', p_suite);
end
$$;

create or replace function public.accept_workspace_invite(
  p_invite_id uuid,
  p_token_hash bytea,
  p_root_key_nonce bytea,
  p_root_wrapped_workspace_key bytea
) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_invite public.workspace_invites%rowtype;
  v_invalidated_hash bytea;
begin
  if v_identity is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_token_hash) <> 32 or octet_length(p_root_key_nonce) <> 12
    or octet_length(p_root_wrapped_workspace_key) < 48 then
    raise exception 'invalid invitation envelope' using errcode = '22023';
  end if;

  perform set_config('request.passkey_x_invite_proof', encode(p_token_hash, 'hex'), true);
  perform set_config('request.passkey_x_invite_accepting', p_invite_id::text, true);
  select * into v_invite from public.workspace_invites
    where id = p_invite_id and status = 'pending' and expires_at > now()
      and recipient_email_hash = private.current_verified_email_hash()
      and token_hash = p_token_hash
    for update;
  if not found then raise exception 'invitation is invalid or expired' using errcode = '28000'; end if;

  v_invalidated_hash := extensions.digest(p_token_hash || uuid_send(p_invite_id), 'sha256');
  update public.workspace_invites set status = 'accepted', accepted_by = v_identity,
    accepted_at = now(), updated_at = now(), token_hash = v_invalidated_hash
    where id = p_invite_id;

  insert into public.tenant_memberships(tenant_id, identity_id, role, status)
    values (v_invite.tenant_id, v_identity, 'member', 'active') on conflict do nothing;
  insert into public.workspace_memberships(tenant_id, workspace_id, identity_id, role, status)
    values (v_invite.tenant_id, v_invite.workspace_id, v_identity, v_invite.role, 'active')
    on conflict do nothing;
  insert into public.key_envelopes(tenant_id, workspace_id, key_kind, key_version,
    recipient_identity_id, algorithm, nonce, wrapped_key)
    select v_invite.tenant_id, v_invite.workspace_id, 'workspace', w.current_key_version,
      v_identity, 'AES-256-GCM', p_root_key_nonce, p_root_wrapped_workspace_key
    from public.workspaces w where w.id = v_invite.workspace_id and w.tenant_id = v_invite.tenant_id;

  return jsonb_build_object('tenant_id', v_invite.tenant_id, 'workspace_id', v_invite.workspace_id, 'role', v_invite.role);
end
$$;

create or replace function public.revoke_workspace_invite(p_invite_id uuid)
returns void language plpgsql security invoker set search_path = ''
as $$
begin
  perform set_config('request.passkey_x_invite_revoke', p_invite_id::text, true);
  update public.workspace_invites set status = 'revoked', revoked_at = now(), updated_at = now()
    where id = p_invite_id and status in ('pending','accepted');
  if not found then raise exception 'invitation cannot be revoked' using errcode = '40001'; end if;
end
$$;

create or replace function public.accept_access_capsule(
  p_capsule_id uuid,
  p_token_hash bytea,
  p_recipient_key_nonce bytea,
  p_recipient_wrapped_key bytea,
  p_recipient_key_aad_hash bytea
) returns void language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_invalidated_hash bytea;
begin
  if v_identity is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_token_hash) <> 32 or octet_length(p_recipient_key_nonce) <> 12
    or octet_length(p_recipient_wrapped_key) < 48 or octet_length(p_recipient_key_aad_hash) <> 32 then
    raise exception 'invalid capsule envelope' using errcode = '22023';
  end if;
  perform set_config('request.passkey_x_capsule_proof', encode(p_token_hash, 'hex'), true);
  v_invalidated_hash := extensions.digest(p_token_hash || uuid_send(p_capsule_id), 'sha256');
  update public.access_capsules set status = 'accepted', accepted_by = v_identity,
    accepted_at = now(), updated_at = now(), token_hash = v_invalidated_hash,
    recipient_key_nonce = p_recipient_key_nonce, recipient_wrapped_key = p_recipient_wrapped_key,
    recipient_key_aad_hash = p_recipient_key_aad_hash
    where id = p_capsule_id and status = 'pending' and now() between not_before and expires_at;
  if not found then raise exception 'capsule is invalid or expired' using errcode = '28000'; end if;
end
$$;

create or replace function public.consume_access_capsule(p_capsule_id uuid)
returns integer language plpgsql security invoker set search_path = ''
as $$
declare v_count integer;
begin
  perform set_config('request.passkey_x_capsule_consume', p_capsule_id::text, true);
  select use_count + 1 into v_count from public.access_capsules
    where id = p_capsule_id and status = 'accepted' and now() between not_before and expires_at
      and (max_uses = 0 or use_count < max_uses)
    for update;
  if not found then raise exception 'capsule is unavailable' using errcode = '40001'; end if;
  update public.access_capsules
  set use_count = use_count + 1,
      status = case when max_uses > 0 and use_count + 1 >= max_uses then 'consumed' else 'accepted' end,
      updated_at = now()
  where id = p_capsule_id and status = 'accepted' and now() between not_before and expires_at
    and (max_uses = 0 or use_count < max_uses);
  return v_count;
end
$$;

create or replace function public.revoke_access_capsule(p_capsule_id uuid)
returns void language plpgsql security invoker set search_path = ''
as $$
begin
  perform set_config('request.passkey_x_capsule_revoke', p_capsule_id::text, true);
  update public.access_capsules set status = 'revoked', revoked_at = now(), updated_at = now()
    where id = p_capsule_id and status in ('pending','accepted');
  if not found then raise exception 'capsule cannot be revoked' using errcode = '40001'; end if;
end
$$;

create or replace function public.decide_access_request(p_request_id uuid, p_decision text)
returns uuid language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_request public.access_requests%rowtype;
  v_approval uuid := gen_random_uuid();
begin
  if p_decision not in ('approved','denied') then raise exception 'invalid decision' using errcode = '22023'; end if;
  perform set_config('request.passkey_x_approval', p_request_id::text, true);
  select * into v_request from public.access_requests where id = p_request_id and status = 'pending' for update;
  if not found or not private.can_manage_workspace(v_request.tenant_id, v_request.workspace_id) then
    raise exception 'request is unavailable' using errcode = '42501';
  end if;
  insert into public.approvals(id,tenant_id,workspace_id,request_id,approver_identity_id,decision)
    values (v_approval,v_request.tenant_id,v_request.workspace_id,p_request_id,v_identity,p_decision);
  update public.access_requests set status = p_decision, decided_at = now(), updated_at = now()
    where id = p_request_id;
  if p_decision = 'approved' then
    insert into public.access_grants(tenant_id,workspace_id,item_id,subject_identity_id,scope,
      source_request_id,starts_at,expires_at,status,created_by)
      values (v_request.tenant_id,v_request.workspace_id,v_request.item_id,
        v_request.requester_identity_id,v_request.requested_scope,p_request_id,now(),
        least(v_request.expires_at, now() + make_interval(mins => v_request.requested_duration_minutes)),
        'active',v_identity);
  end if;
  return v_approval;
end
$$;

create or replace function public.revoke_workspace_member(p_workspace_id uuid, p_identity_id uuid)
returns void language plpgsql security invoker set search_path = ''
as $$
declare v_member public.workspace_memberships%rowtype;
begin
  perform set_config('request.passkey_x_member_revoke', p_workspace_id::text || ':' || p_identity_id::text, true);
  select * into v_member from public.workspace_memberships
    where workspace_id = p_workspace_id and identity_id = p_identity_id and status = 'active'
    for update;
  if not found or v_member.role = 'owner'
    or not private.can_manage_workspace(v_member.tenant_id, v_member.workspace_id) then
    raise exception 'member cannot be revoked' using errcode = '42501';
  end if;
  update public.workspace_memberships set status = 'revoked', updated_at = now()
    where workspace_id = p_workspace_id and identity_id = p_identity_id;
  update public.key_envelopes set revoked_at = now()
    where workspace_id = p_workspace_id and recipient_identity_id = p_identity_id and revoked_at is null;
  update public.workspaces set key_rotation_required = true, updated_at = now()
    where id = p_workspace_id and tenant_id = v_member.tenant_id;
end
$$;

grant update (status,updated_at) on public.workspace_memberships to authenticated;
grant update (revoked_at) on public.key_envelopes to authenticated;
grant update (key_rotation_required,updated_at) on public.workspaces to authenticated;

create policy workspace_memberships_member_revoke on public.workspace_memberships for update to authenticated
using (
  role <> 'owner' and (select private.can_manage_workspace(tenant_id, workspace_id))
  and current_setting('request.passkey_x_member_revoke', true) = workspace_id::text || ':' || identity_id::text
)
with check (status = 'revoked' and role <> 'owner');
create policy key_envelopes_member_revoke on public.key_envelopes for update to authenticated
using (
  workspace_id is not null and (select private.can_manage_workspace(tenant_id, workspace_id))
  and current_setting('request.passkey_x_member_revoke', true) = workspace_id::text || ':' || recipient_identity_id::text
)
with check (revoked_at is not null);
create policy workspaces_mark_rotation on public.workspaces for update to authenticated
using (
  (select private.can_manage_workspace(tenant_id, id))
  and current_setting('request.passkey_x_member_revoke', true) like id::text || ':%'
)
with check (key_rotation_required = true);

-- Use the current workspace key version for all new immutable revisions.
create or replace function public.create_vault_item(
  p_item_id uuid, p_tenant_id uuid, p_workspace_id uuid, p_content_type text,
  p_schema_version integer, p_nonce bytea, p_ciphertext bytea, p_aad_hash bytea
) returns bigint language plpgsql security invoker set search_path = ''
as $$
declare v_identity uuid := private.current_identity_id(); v_key_version integer;
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  select current_key_version into v_key_version from public.workspaces
    where id = p_workspace_id and tenant_id = p_tenant_id and status = 'active';
  if v_key_version is null then raise exception 'workspace unavailable' using errcode = '42501'; end if;
  insert into public.vault_items(id,tenant_id,workspace_id,content_type,schema_version,head_revision,created_by)
    values (p_item_id,p_tenant_id,p_workspace_id,p_content_type,p_schema_version,1,v_identity);
  insert into public.vault_item_revisions(tenant_id,workspace_id,item_id,revision,envelope_version,
    algorithm,key_version,nonce,ciphertext,aad_hash,created_by)
    values (p_tenant_id,p_workspace_id,p_item_id,1,1,'AES-256-GCM',v_key_version,
      p_nonce,p_ciphertext,p_aad_hash,v_identity);
  return 1;
end
$$;

create or replace function public.update_vault_item(
  p_item_id uuid, p_expected_revision bigint, p_nonce bytea,
  p_ciphertext bytea, p_aad_hash bytea
) returns bigint language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_item public.vault_items%rowtype;
  v_key_version integer;
  v_next_revision bigint := p_expected_revision + 1;
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  update public.vault_items set head_revision = v_next_revision, updated_at = now()
    where id = p_item_id and head_revision = p_expected_revision and deleted_at is null
    returning * into v_item;
  if not found then raise exception 'vault item changed or no longer exists' using errcode = '40001'; end if;
  select current_key_version into strict v_key_version from public.workspaces
    where id = v_item.workspace_id and tenant_id = v_item.tenant_id and status = 'active';
  insert into public.vault_item_revisions(tenant_id,workspace_id,item_id,revision,envelope_version,
    algorithm,key_version,nonce,ciphertext,aad_hash,created_by)
    values (v_item.tenant_id,v_item.workspace_id,v_item.id,v_next_revision,1,'AES-256-GCM',
      v_key_version,p_nonce,p_ciphertext,p_aad_hash,v_identity);
  return v_next_revision;
end
$$;

create or replace function private.phase2_audit_event()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  v_row jsonb := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
  v_tenant uuid := (v_row ->> 'tenant_id')::uuid;
  v_target uuid := coalesce((v_row ->> 'id')::uuid, (v_row ->> 'workspace_id')::uuid);
  v_actor uuid := private.current_identity_id();
  v_previous bytea;
  v_metadata jsonb;
  v_action text := tg_table_name || '.' || lower(tg_op);
begin
  select event_hash into v_previous from public.audit_events
    where tenant_id = v_tenant order by sequence desc limit 1;
  v_metadata := jsonb_strip_nulls(jsonb_build_object(
    'status', v_row ->> 'status', 'role', v_row ->> 'role',
    'reveal_policy', v_row ->> 'reveal_policy', 'expires_at', v_row ->> 'expires_at'
  ));
  insert into public.audit_events(tenant_id,actor_identity_id,action,target_type,target_id,
    metadata,previous_hash,event_hash)
  values (v_tenant,v_actor,v_action,tg_table_name,v_target,v_metadata,v_previous,
    extensions.digest(convert_to(concat_ws('|',v_tenant::text,coalesce(v_actor::text,''),
      v_action,coalesce(v_target::text,''),v_metadata::text,coalesce(encode(v_previous,'hex'),''),
      clock_timestamp()::text),'UTF8'),'sha256'));
  return case when tg_op = 'DELETE' then old else new end;
end
$$;

create trigger workspace_invites_audit after insert or update on public.workspace_invites
  for each row execute function private.phase2_audit_event();
create trigger access_capsules_audit after insert or update on public.access_capsules
  for each row execute function private.phase2_audit_event();
create trigger access_requests_audit after insert or update on public.access_requests
  for each row execute function private.phase2_audit_event();
create trigger approvals_audit after insert on public.approvals
  for each row execute function private.phase2_audit_event();
create trigger missions_audit after insert or update on public.missions
  for each row execute function private.phase2_audit_event();
create trigger mission_runs_audit after insert or update on public.mission_runs
  for each row execute function private.phase2_audit_event();

revoke all on function private.phase2_audit_event() from public, anon, authenticated;
revoke all on function public.create_shared_workspace(uuid,uuid,text,text,bytea,bytea,bytea,bytea,bytea) from public, anon;
revoke all on function public.accept_workspace_invite(uuid,bytea,bytea,bytea) from public, anon;
revoke all on function public.revoke_workspace_invite(uuid) from public, anon;
revoke all on function public.accept_access_capsule(uuid,bytea,bytea,bytea,bytea) from public, anon;
revoke all on function public.consume_access_capsule(uuid) from public, anon;
revoke all on function public.revoke_access_capsule(uuid) from public, anon;
revoke all on function public.decide_access_request(uuid,text) from public, anon;
revoke all on function public.revoke_workspace_member(uuid,uuid) from public, anon;
grant execute on function public.create_shared_workspace(uuid,uuid,text,text,bytea,bytea,bytea,bytea,bytea) to authenticated;
grant execute on function public.accept_workspace_invite(uuid,bytea,bytea,bytea) to authenticated;
grant execute on function public.revoke_workspace_invite(uuid) to authenticated;
grant execute on function public.accept_access_capsule(uuid,bytea,bytea,bytea,bytea) to authenticated;
grant execute on function public.consume_access_capsule(uuid) to authenticated;
grant execute on function public.revoke_access_capsule(uuid) to authenticated;
grant execute on function public.decide_access_request(uuid,text) to authenticated;
grant execute on function public.revoke_workspace_member(uuid,uuid) to authenticated;

comment on table public.workspace_invites is 'Email-verified workspace invitations. Raw invite secrets and plaintext labels are prohibited.';
comment on table public.access_capsules is 'Purpose-bound client-encrypted item snapshots. The server stores only ciphertext and token verifiers.';
comment on table public.missions is 'Client-encrypted mission definitions. Item membership is authorization metadata only.';
comment on function public.revoke_workspace_member(uuid,uuid) is 'Atomically revokes server access, all identity envelopes, and marks the workspace for cryptographic rotation.';

commit;
