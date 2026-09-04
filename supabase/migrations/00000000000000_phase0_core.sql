begin;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table public.identities (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique references auth.users(id) on delete restrict,
  kind text not null check (kind in ('human','service','machine','workload','agent')),
  status text not null default 'active' check (status in ('active','suspended','revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('personal','family','organization')),
  encrypted_name bytea,
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.tenant_memberships (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  role text not null check (role in ('owner','admin','member','auditor')),
  status text not null default 'active' check (status in ('invited','active','suspended','revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, identity_id)
);

create table public.workspaces (
  id uuid not null default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  kind text not null default 'vault' check (kind in ('vault','project','client','shared')),
  encrypted_name bytea,
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, id),
  unique (id)
);

create table public.workspace_memberships (
  tenant_id uuid not null,
  workspace_id uuid not null,
  identity_id uuid not null references public.identities(id) on delete cascade,
  role text not null check (role in ('owner','manager','editor','viewer')),
  status text not null default 'active' check (status in ('invited','active','suspended','revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (workspace_id, identity_id),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade,
  foreign key (tenant_id, identity_id) references public.tenant_memberships(tenant_id, identity_id) on delete cascade
);

create table public.devices (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete cascade,
  public_key bytea not null,
  encrypted_label bytea,
  status text not null default 'pending' check (status in ('pending','trusted','revoked')),
  last_seen_at timestamptz,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table public.vault_items (
  id uuid not null default gen_random_uuid(),
  tenant_id uuid not null,
  workspace_id uuid not null,
  content_type text not null check (length(content_type) between 3 and 128),
  schema_version integer not null check (schema_version > 0),
  head_revision bigint not null default 0 check (head_revision >= 0),
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  primary key (tenant_id, id),
  unique (id),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.vault_item_revisions (
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid not null,
  revision bigint not null check (revision > 0),
  envelope_version integer not null check (envelope_version > 0),
  algorithm text not null check (algorithm in ('AES-256-GCM')),
  key_version integer not null check (key_version > 0),
  nonce bytea not null check (octet_length(nonce) = 12),
  ciphertext bytea not null check (octet_length(ciphertext) >= 16),
  aad_hash bytea not null check (octet_length(aad_hash) = 32),
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  primary key (item_id, revision),
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.key_envelopes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workspace_id uuid,
  key_kind text not null check (key_kind in ('account_root','workspace','item','attachment','recovery')),
  key_version integer not null check (key_version > 0),
  recipient_identity_id uuid references public.identities(id) on delete cascade,
  recipient_device_id uuid references public.devices(id) on delete cascade,
  algorithm text not null,
  nonce bytea not null,
  wrapped_key bytea not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  check (num_nonnulls(recipient_identity_id, recipient_device_id) = 1),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.attachments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid not null,
  head_version bigint not null default 0 check (head_version >= 0),
  encrypted_metadata bytea not null,
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.attachment_versions (
  attachment_id uuid not null references public.attachments(id) on delete cascade,
  version bigint not null check (version > 0),
  storage_path text not null unique,
  ciphertext_size bigint not null check (ciphertext_size >= 16),
  ciphertext_sha256 bytea not null check (octet_length(ciphertext_sha256) = 32),
  key_version integer not null check (key_version > 0),
  created_at timestamptz not null default now(),
  primary key (attachment_id, version)
);

create table public.sync_changes (
  sequence bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  workspace_id uuid not null,
  entity_type text not null check (entity_type in ('item','attachment','membership','key_envelope')),
  entity_id uuid not null,
  operation text not null check (operation in ('create','update','delete','revoke')),
  entity_version bigint,
  occurred_at timestamptz not null default now(),
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.conflicts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  workspace_id uuid not null,
  item_id uuid not null,
  base_revision bigint not null,
  proposed_revision bigint not null,
  encrypted_proposal bytea not null,
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  foreign key (tenant_id, item_id) references public.vault_items(tenant_id, id) on delete cascade,
  foreign key (tenant_id, workspace_id) references public.workspaces(tenant_id, id) on delete cascade
);

create table public.api_tokens (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete cascade,
  token_prefix text not null check (length(token_prefix) between 8 and 24),
  token_hash bytea not null unique check (octet_length(token_hash) = 32),
  scopes text[] not null default '{}',
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table public.idempotency_records (
  identity_id uuid not null references public.identities(id) on delete cascade,
  idempotency_key text not null,
  request_hash bytea not null check (octet_length(request_hash) = 32),
  response_status integer,
  response_body jsonb,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  primary key (identity_id, idempotency_key)
);

create table public.audit_events (
  sequence bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  actor_identity_id uuid references public.identities(id) on delete set null,
  action text not null,
  target_type text not null,
  target_id uuid,
  metadata jsonb not null default '{}',
  previous_hash bytea,
  event_hash bytea not null check (octet_length(event_hash) = 32),
  occurred_at timestamptz not null default now()
);

create table public.outbox_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  event_type text not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  published_at timestamptz,
  attempts integer not null default 0 check (attempts >= 0)
);

create index tenant_memberships_identity_idx on public.tenant_memberships(identity_id, tenant_id) where status = 'active';
create index workspace_memberships_identity_idx on public.workspace_memberships(identity_id, workspace_id) where status = 'active';
create index devices_identity_idx on public.devices(identity_id);
create index vault_items_workspace_idx on public.vault_items(tenant_id, workspace_id, updated_at desc);
create index revisions_workspace_idx on public.vault_item_revisions(tenant_id, workspace_id, created_at desc);
create index sync_changes_workspace_idx on public.sync_changes(tenant_id, workspace_id, sequence);
create index audit_events_tenant_idx on public.audit_events(tenant_id, sequence desc);

create or replace function private.current_identity_id()
returns uuid language sql stable security definer set search_path = ''
as $$
  select i.id from public.identities i
  where i.auth_user_id = auth.uid() and i.status = 'active'
  limit 1
$$;

create or replace function private.has_tenant_role(target_tenant uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1 from public.tenant_memberships tm
    join public.identities i on i.id = tm.identity_id
    where tm.tenant_id = target_tenant and i.auth_user_id = auth.uid()
      and i.status = 'active' and tm.status = 'active' and tm.role = any(allowed_roles)
  )
$$;

create or replace function private.has_workspace_role(target_tenant uuid, target_workspace uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1 from public.workspace_memberships wm
    join public.identities i on i.id = wm.identity_id
    where wm.tenant_id = target_tenant and wm.workspace_id = target_workspace
      and i.auth_user_id = auth.uid() and i.status = 'active'
      and wm.status = 'active' and wm.role = any(allowed_roles)
  )
$$;

revoke all on all functions in schema private from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.current_identity_id() to authenticated;
grant execute on function private.has_tenant_role(uuid,text[]) to authenticated;
grant execute on function private.has_workspace_role(uuid,uuid,text[]) to authenticated;

alter table public.identities enable row level security;
alter table public.tenants enable row level security;
alter table public.tenant_memberships enable row level security;
alter table public.workspaces enable row level security;
alter table public.workspace_memberships enable row level security;
alter table public.devices enable row level security;
alter table public.vault_items enable row level security;
alter table public.vault_item_revisions enable row level security;
alter table public.key_envelopes enable row level security;
alter table public.attachments enable row level security;
alter table public.attachment_versions enable row level security;
alter table public.sync_changes enable row level security;
alter table public.conflicts enable row level security;
alter table public.api_tokens enable row level security;
alter table public.idempotency_records enable row level security;
alter table public.audit_events enable row level security;
alter table public.outbox_events enable row level security;

revoke all on all tables in schema public from anon, authenticated;
grant select on public.identities, public.tenants, public.tenant_memberships, public.workspaces,
  public.workspace_memberships, public.devices, public.vault_items, public.vault_item_revisions,
  public.key_envelopes, public.attachments, public.attachment_versions, public.sync_changes,
  public.conflicts, public.api_tokens, public.audit_events to authenticated;
grant insert, update on public.devices, public.vault_items, public.vault_item_revisions,
  public.key_envelopes, public.attachments, public.attachment_versions, public.conflicts,
  public.api_tokens to authenticated;
grant delete on public.api_tokens to authenticated;
grant usage, select on all sequences in schema public to authenticated;

create policy identities_read_self on public.identities for select to authenticated
  using (auth_user_id = (select auth.uid()));
create policy tenants_read_member on public.tenants for select to authenticated
  using ((select private.has_tenant_role(id, array['owner','admin','member','auditor'])));
create policy tenant_memberships_read_member on public.tenant_memberships for select to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner','admin','member','auditor'])));
create policy workspaces_read_member on public.workspaces for select to authenticated
  using ((select private.has_workspace_role(tenant_id, id, array['owner','manager','editor','viewer'])));
create policy workspace_memberships_read_member on public.workspace_memberships for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));

create policy devices_read_self on public.devices for select to authenticated
  using (identity_id = (select private.current_identity_id()));
create policy devices_insert_self on public.devices for insert to authenticated
  with check (identity_id = (select private.current_identity_id()));
create policy devices_update_self on public.devices for update to authenticated
  using (identity_id = (select private.current_identity_id()))
  with check (identity_id = (select private.current_identity_id()));

create policy vault_items_read on public.vault_items for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy vault_items_insert on public.vault_items for insert to authenticated
  with check (created_by = (select private.current_identity_id()) and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));
create policy vault_items_update on public.vault_items for update to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])))
  with check ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));

create policy revisions_read on public.vault_item_revisions for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy revisions_insert on public.vault_item_revisions for insert to authenticated
  with check (created_by = (select private.current_identity_id()) and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));

create policy key_envelopes_read on public.key_envelopes for select to authenticated
  using (recipient_identity_id = (select private.current_identity_id()) or recipient_device_id in (select d.id from public.devices d where d.identity_id = (select private.current_identity_id()) and d.status = 'trusted'));
create policy key_envelopes_insert on public.key_envelopes for insert to authenticated
  with check (workspace_id is not null and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager'])));

create policy attachments_read on public.attachments for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy attachments_insert on public.attachments for insert to authenticated
  with check (created_by = (select private.current_identity_id()) and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));
create policy attachments_update on public.attachments for update to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])))
  with check ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));
create policy attachment_versions_read on public.attachment_versions for select to authenticated
  using (exists (select 1 from public.attachments a where a.id = attachment_id));
create policy attachment_versions_insert on public.attachment_versions for insert to authenticated
  with check (exists (select 1 from public.attachments a where a.id = attachment_id and (select private.has_workspace_role(a.tenant_id, a.workspace_id, array['owner','manager','editor']))));

create policy sync_changes_read on public.sync_changes for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy conflicts_read on public.conflicts for select to authenticated
  using ((select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor','viewer'])));
create policy conflicts_insert on public.conflicts for insert to authenticated
  with check (created_by = (select private.current_identity_id()) and (select private.has_workspace_role(tenant_id, workspace_id, array['owner','manager','editor'])));

create policy api_tokens_read_self on public.api_tokens for select to authenticated
  using (identity_id = (select private.current_identity_id()));
create policy api_tokens_insert_self on public.api_tokens for insert to authenticated
  with check (identity_id = (select private.current_identity_id()));
create policy api_tokens_update_self on public.api_tokens for update to authenticated
  using (identity_id = (select private.current_identity_id()))
  with check (identity_id = (select private.current_identity_id()));
create policy api_tokens_delete_self on public.api_tokens for delete to authenticated
  using (identity_id = (select private.current_identity_id()));
create policy audit_events_read on public.audit_events for select to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner','admin','auditor'])));

comment on schema private is 'Non-exposed authorization helpers; never add to Data API schemas.';
comment on table public.vault_item_revisions is 'Immutable client-encrypted item revisions; plaintext is prohibited.';
comment on table public.key_envelopes is 'Client-generated wrapped keys only; never store unwrapped vault keys.';

commit;

