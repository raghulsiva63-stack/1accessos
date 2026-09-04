begin;

create or replace function public.create_attachment(
  p_attachment_id uuid,
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_item_id uuid,
  p_encrypted_metadata bytea,
  p_metadata_nonce bytea,
  p_metadata_aad_hash bytea,
  p_storage_path text,
  p_ciphertext_size bigint,
  p_ciphertext_sha256 bytea,
  p_key_version integer,
  p_nonce bytea,
  p_aad_hash bytea
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_expected_path text := p_tenant_id::text || '/' || p_workspace_id::text || '/' || p_attachment_id::text || '/1';
begin
  if v_identity is null then
    raise exception 'active identity required' using errcode = '28000';
  end if;
  if p_storage_path <> v_expected_path then
    raise exception 'invalid attachment storage path' using errcode = '22023';
  end if;
  if octet_length(p_metadata_nonce) <> 12
    or octet_length(p_metadata_aad_hash) <> 32
    or octet_length(p_nonce) <> 12
    or octet_length(p_aad_hash) <> 32
    or octet_length(p_ciphertext_sha256) <> 32
    or p_ciphertext_size < 16
    or p_ciphertext_size > 26214416
    or p_key_version < 1 then
    raise exception 'invalid attachment envelope' using errcode = '22023';
  end if;

  insert into public.attachments(
    id, tenant_id, workspace_id, item_id, head_version, encrypted_metadata,
    metadata_nonce, metadata_aad_hash, created_by
  ) values (
    p_attachment_id, p_tenant_id, p_workspace_id, p_item_id, 1,
    p_encrypted_metadata, p_metadata_nonce, p_metadata_aad_hash, v_identity
  );

  insert into public.attachment_versions(
    attachment_id, version, storage_path, ciphertext_size,
    ciphertext_sha256, key_version, nonce, aad_hash
  ) values (
    p_attachment_id, 1, p_storage_path, p_ciphertext_size,
    p_ciphertext_sha256, p_key_version, p_nonce, p_aad_hash
  );
end
$$;

revoke all on function public.create_attachment(
  uuid,uuid,uuid,uuid,bytea,bytea,bytea,text,bigint,bytea,integer,bytea,bytea
) from public, anon;
grant execute on function public.create_attachment(
  uuid,uuid,uuid,uuid,bytea,bytea,bytea,text,bigint,bytea,integer,bytea,bytea
) to authenticated;

create or replace function private.record_attachment_version_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_attachment public.attachments%rowtype;
begin
  select * into strict v_attachment
  from public.attachments
  where id = new.attachment_id;

  insert into public.sync_changes(
    tenant_id, workspace_id, entity_type, entity_id, operation, entity_version
  ) values (
    v_attachment.tenant_id,
    v_attachment.workspace_id,
    'attachment',
    new.attachment_id,
    case when new.version = 1 then 'create' else 'update' end,
    new.version
  );
  return new;
end
$$;

create trigger attachment_version_sync_change
after insert on public.attachment_versions
for each row execute function private.record_attachment_version_change();

revoke all on function private.record_attachment_version_change() from public, anon, authenticated;

comment on function public.create_attachment(
  uuid,uuid,uuid,uuid,bytea,bytea,bytea,text,bigint,bytea,integer,bytea,bytea
) is 'Atomically registers a caller-encrypted attachment and first version under RLS after private Storage upload.';

commit;
