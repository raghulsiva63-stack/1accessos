begin;

-- Phase 1 Free/Personal entitlement skeleton. Billing providers may only mutate
-- this table through a future server-side webhook; browser clients are read-only.
create table public.account_entitlements (
  identity_id uuid primary key references public.identities(id) on delete cascade,
  plan_code text not null default 'free' check (plan_code in ('free','personal')),
  ai_credits_remaining integer not null default 20 check (ai_credits_remaining >= 0),
  automation_runs_remaining integer not null default 50 check (automation_runs_remaining >= 0),
  period_started_at timestamptz not null default date_trunc('month', now()),
  period_ends_at timestamptz not null default date_trunc('month', now()) + interval '1 month',
  updated_at timestamptz not null default now()
);

alter table public.account_entitlements enable row level security;
revoke all on public.account_entitlements from anon, authenticated;
grant select on public.account_entitlements to authenticated;

create policy account_entitlements_read_self on public.account_entitlements
for select to authenticated
using (identity_id = (select private.current_identity_id()));

create or replace function private.provision_free_entitlement()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.account_entitlements(identity_id) values (new.id)
  on conflict (identity_id) do nothing;
  return new;
end
$$;

create trigger identity_provision_free_entitlement
after insert on public.identities
for each row execute function private.provision_free_entitlement();

insert into public.account_entitlements(identity_id)
select id from public.identities
on conflict (identity_id) do nothing;

revoke all on function private.provision_free_entitlement() from public, anon, authenticated;

-- Recovery rotates only the password-derived wrapper. The user must first
-- decrypt recovery_wrapped_root in the client, so the server never receives a
-- master password, recovery key, or unwrapped account root key.
grant update (salt, kdf_parameters, master_nonce, master_wrapped_root, updated_at)
on public.account_crypto_profiles to authenticated;

create policy crypto_profile_rotate_self on public.account_crypto_profiles
for update to authenticated
using (identity_id = (select private.current_identity_id()))
with check (identity_id = (select private.current_identity_id()));

-- Restrict direct mutations to the columns needed by the reviewed RPCs.
revoke insert, update on public.vault_items from authenticated;
grant insert (id, tenant_id, workspace_id, content_type, schema_version, head_revision, created_by)
on public.vault_items to authenticated;
grant update (head_revision, updated_at, deleted_at)
on public.vault_items to authenticated;

revoke insert, update on public.vault_item_revisions from authenticated;
grant insert (tenant_id, workspace_id, item_id, revision, envelope_version, algorithm,
  key_version, nonce, ciphertext, aad_hash, created_by)
on public.vault_item_revisions to authenticated;

-- A deferred integrity gate prevents a direct metadata update from pointing at
-- a revision that was not appended in the same transaction.
create or replace function private.assert_vault_head_revision()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.head_revision <> old.head_revision and not exists (
    select 1 from public.vault_item_revisions r
    where r.item_id = new.id and r.revision = new.head_revision
  ) then
    raise exception 'vault head must reference an immutable revision' using errcode = '23514';
  end if;
  return null;
end
$$;

create constraint trigger vault_head_revision_exists
after update of head_revision on public.vault_items
deferrable initially deferred
for each row execute function private.assert_vault_head_revision();

revoke all on function private.assert_vault_head_revision() from public, anon, authenticated;

-- Delete and restore are both sync-visible changes.
create or replace function private.record_vault_item_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.deleted_at is distinct from new.deleted_at then
    insert into public.sync_changes(
      tenant_id, workspace_id, entity_type, entity_id, operation, entity_version
    ) values (
      new.tenant_id,
      new.workspace_id,
      'item',
      new.id,
      case when new.deleted_at is null then 'update' else 'delete' end,
      new.head_revision
    );
  end if;
  return new;
end
$$;

create or replace function public.restore_vault_item(
  p_item_id uuid,
  p_expected_revision bigint
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  update public.vault_items
  set deleted_at = null, updated_at = now()
  where id = p_item_id
    and head_revision = p_expected_revision
    and deleted_at is not null;

  if not found then
    raise exception 'vault item changed or is not deleted' using errcode = '40001';
  end if;
end
$$;

revoke all on function public.restore_vault_item(uuid,bigint) from public, anon;
grant execute on function public.restore_vault_item(uuid,bigint) to authenticated;

-- Device mutation is one-way. Authenticated users may add a trusted public key
-- within their plan limit and may revoke it, but a revoked row cannot be trusted again.
drop policy if exists devices_insert_self on public.devices;
drop policy if exists devices_update_self on public.devices;
revoke insert, update on public.devices from authenticated;
grant insert (id, identity_id, public_key, status, last_seen_at) on public.devices to authenticated;
grant update (status, revoked_at) on public.devices to authenticated;

create policy devices_insert_self on public.devices for insert to authenticated
with check (
  identity_id = (select private.current_identity_id())
  and status = 'trusted'
  and revoked_at is null
  and (
    (select count(*) from public.devices d where d.identity_id = (select private.current_identity_id()) and d.status <> 'revoked')
    < case
        when coalesce((select e.plan_code from public.account_entitlements e where e.identity_id = (select private.current_identity_id())), 'free') = 'personal'
        then 2147483647
        else 2
      end
  )
);

create policy devices_revoke_self on public.devices for update to authenticated
using (
  identity_id = (select private.current_identity_id())
  and status in ('pending','trusted')
)
with check (
  identity_id = (select private.current_identity_id())
  and status = 'revoked'
  and revoked_at is not null
);

-- Attachment ciphertext is private in Storage. Paths are tenant/workspace/attachment/version.
alter table public.attachments
  add column metadata_nonce bytea,
  add column metadata_aad_hash bytea;
alter table public.attachments
  add constraint attachments_metadata_nonce_length check (metadata_nonce is null or octet_length(metadata_nonce) = 12),
  add constraint attachments_metadata_aad_hash_length check (metadata_aad_hash is null or octet_length(metadata_aad_hash) = 32);

alter table public.attachment_versions
  add column nonce bytea,
  add column aad_hash bytea;
alter table public.attachment_versions
  add constraint attachment_versions_nonce_length check (nonce is null or octet_length(nonce) = 12),
  add constraint attachment_versions_aad_hash_length check (aad_hash is null or octet_length(aad_hash) = 32);

revoke insert, update on public.attachments from authenticated;
grant insert (id, tenant_id, workspace_id, item_id, head_version, encrypted_metadata,
  metadata_nonce, metadata_aad_hash, created_by)
on public.attachments to authenticated;
grant update (head_version, deleted_at) on public.attachments to authenticated;

revoke insert, update on public.attachment_versions from authenticated;
grant insert (attachment_id, version, storage_path, ciphertext_size, ciphertext_sha256,
  key_version, nonce, aad_hash)
on public.attachment_versions to authenticated;

insert into storage.buckets (id, name, public, file_size_limit)
values ('vault-attachments', 'vault-attachments', false, 26214400)
on conflict (id) do update
set public = excluded.public, file_size_limit = excluded.file_size_limit;

create or replace function private.can_access_attachment_path(object_name text, allowed_roles text[])
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_parts text[] := storage.foldername(object_name);
begin
  if array_length(v_parts, 1) < 3 then return false; end if;
  return private.has_workspace_role(v_parts[1]::uuid, v_parts[2]::uuid, allowed_roles);
exception when others then
  return false;
end
$$;

revoke all on function private.can_access_attachment_path(text,text[]) from public, anon;
grant execute on function private.can_access_attachment_path(text,text[]) to authenticated;

create policy vault_attachment_objects_read on storage.objects
for select to authenticated
using (
  bucket_id = 'vault-attachments'
  and (select private.can_access_attachment_path(name, array['owner','manager','editor','viewer']))
);

create policy vault_attachment_objects_insert on storage.objects
for insert to authenticated
with check (
  bucket_id = 'vault-attachments'
  and (select private.can_access_attachment_path(name, array['owner','manager','editor']))
);

create policy vault_attachment_objects_delete on storage.objects
for delete to authenticated
using (
  bucket_id = 'vault-attachments'
  and (select private.can_access_attachment_path(name, array['owner','manager','editor']))
);

comment on table public.account_entitlements is 'Server-managed Free/Personal capability and credit counters; clients are read-only.';
comment on function public.restore_vault_item(uuid,bigint) is 'Restores a caller-visible soft-deleted item under RLS and optimistic concurrency.';
comment on function private.can_access_attachment_path(text,text[]) is 'Validates tenant/workspace Storage paths without leaking membership rows.';

commit;
