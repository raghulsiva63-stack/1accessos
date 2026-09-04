begin;

create or replace function public.create_vault_item(
  p_item_id uuid,
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_content_type text,
  p_schema_version integer,
  p_nonce bytea,
  p_ciphertext bytea,
  p_aad_hash bytea
) returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
begin
  if v_identity is null then
    raise exception 'active identity required' using errcode = '28000';
  end if;

  insert into public.vault_items(
    id, tenant_id, workspace_id, content_type, schema_version,
    head_revision, created_by
  ) values (
    p_item_id, p_tenant_id, p_workspace_id, p_content_type,
    p_schema_version, 1, v_identity
  );

  insert into public.vault_item_revisions(
    tenant_id, workspace_id, item_id, revision, envelope_version,
    algorithm, key_version, nonce, ciphertext, aad_hash, created_by
  ) values (
    p_tenant_id, p_workspace_id, p_item_id, 1, 1,
    'AES-256-GCM', 1, p_nonce, p_ciphertext, p_aad_hash, v_identity
  );

  return 1;
end
$$;

create or replace function public.update_vault_item(
  p_item_id uuid,
  p_expected_revision bigint,
  p_nonce bytea,
  p_ciphertext bytea,
  p_aad_hash bytea
) returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_item public.vault_items%rowtype;
  v_next_revision bigint := p_expected_revision + 1;
begin
  if v_identity is null then
    raise exception 'active identity required' using errcode = '28000';
  end if;

  update public.vault_items
  set head_revision = v_next_revision, updated_at = now()
  where id = p_item_id
    and head_revision = p_expected_revision
    and deleted_at is null
  returning * into v_item;

  if not found then
    raise exception 'vault item changed or no longer exists' using errcode = '40001';
  end if;

  insert into public.vault_item_revisions(
    tenant_id, workspace_id, item_id, revision, envelope_version,
    algorithm, key_version, nonce, ciphertext, aad_hash, created_by
  ) values (
    v_item.tenant_id, v_item.workspace_id, v_item.id, v_next_revision, 1,
    'AES-256-GCM', 1, p_nonce, p_ciphertext, p_aad_hash, v_identity
  );

  return v_next_revision;
end
$$;

create or replace function public.delete_vault_item(
  p_item_id uuid,
  p_expected_revision bigint
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  update public.vault_items
  set deleted_at = now(), updated_at = now()
  where id = p_item_id
    and head_revision = p_expected_revision
    and deleted_at is null;

  if not found then
    raise exception 'vault item changed or no longer exists' using errcode = '40001';
  end if;
end
$$;

create or replace function private.record_vault_revision_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.sync_changes(
    tenant_id, workspace_id, entity_type, entity_id, operation, entity_version
  ) values (
    new.tenant_id,
    new.workspace_id,
    'item',
    new.item_id,
    case when new.revision = 1 then 'create' else 'update' end,
    new.revision
  );
  return new;
end
$$;

create or replace function private.record_vault_item_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.deleted_at is null and new.deleted_at is not null then
    insert into public.sync_changes(
      tenant_id, workspace_id, entity_type, entity_id, operation, entity_version
    ) values (
      new.tenant_id, new.workspace_id, 'item', new.id, 'delete', new.head_revision
    );
  end if;
  return new;
end
$$;

create trigger vault_revision_sync_change
after insert on public.vault_item_revisions
for each row execute function private.record_vault_revision_change();

create trigger vault_item_delete_sync_change
after update of deleted_at on public.vault_items
for each row execute function private.record_vault_item_delete();

revoke all on function public.create_vault_item(uuid,uuid,uuid,text,integer,bytea,bytea,bytea) from public, anon;
revoke all on function public.update_vault_item(uuid,bigint,bytea,bytea,bytea) from public, anon;
revoke all on function public.delete_vault_item(uuid,bigint) from public, anon;
grant execute on function public.create_vault_item(uuid,uuid,uuid,text,integer,bytea,bytea,bytea) to authenticated;
grant execute on function public.update_vault_item(uuid,bigint,bytea,bytea,bytea) to authenticated;
grant execute on function public.delete_vault_item(uuid,bigint) to authenticated;

revoke all on function private.record_vault_revision_change() from public, anon, authenticated;
revoke all on function private.record_vault_item_delete() from public, anon, authenticated;

comment on function public.create_vault_item(uuid,uuid,uuid,text,integer,bytea,bytea,bytea)
  is 'Atomically creates an encrypted vault item and immutable first revision under caller RLS.';
comment on function public.update_vault_item(uuid,bigint,bytea,bytea,bytea)
  is 'Atomically appends an encrypted revision using optimistic concurrency under caller RLS.';

commit;
