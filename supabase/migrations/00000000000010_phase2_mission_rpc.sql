begin;

create or replace function public.create_mission(
  p_mission_id uuid,
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_definition_nonce bytea,
  p_encrypted_definition bytea,
  p_definition_aad_hash bytea,
  p_item_ids uuid[]
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_item_id uuid;
  v_sort_order integer := 0;
begin
  if v_identity is null then raise exception 'active identity required' using errcode = '28000'; end if;
  if octet_length(p_definition_nonce) <> 12
    or octet_length(p_definition_aad_hash) <> 32
    or octet_length(p_encrypted_definition) < 16
    or coalesce(cardinality(p_item_ids), 0) < 1
    or cardinality(p_item_ids) > 50 then
    raise exception 'invalid encrypted mission definition' using errcode = '22023';
  end if;

  insert into public.missions(
    id,tenant_id,workspace_id,created_by,definition_nonce,
    encrypted_definition,definition_aad_hash,status
  ) values (
    p_mission_id,p_tenant_id,p_workspace_id,v_identity,p_definition_nonce,
    p_encrypted_definition,p_definition_aad_hash,'active'
  );

  foreach v_item_id in array p_item_ids loop
    insert into public.mission_items(mission_id,tenant_id,workspace_id,item_id,sort_order)
      select p_mission_id,p_tenant_id,p_workspace_id,v_item_id,v_sort_order
      from public.vault_items vi
      where vi.id = v_item_id and vi.tenant_id = p_tenant_id
        and vi.workspace_id = p_workspace_id and vi.deleted_at is null;
    if not found then raise exception 'mission item is unavailable' using errcode = '42501'; end if;
    v_sort_order := v_sort_order + 1;
  end loop;
end
$$;

revoke all on function public.create_mission(uuid,uuid,uuid,bytea,bytea,bytea,uuid[]) from public, anon;
grant execute on function public.create_mission(uuid,uuid,uuid,bytea,bytea,bytea,uuid[]) to authenticated;

comment on function public.create_mission(uuid,uuid,uuid,bytea,bytea,bytea,uuid[])
  is 'Atomically creates a caller-encrypted Mission and its authorized item set under workspace RLS.';

commit;
