begin;

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
  if not private.phase2_enabled() then raise exception 'collaboration entitlement required' using errcode = '42501'; end if;
  if p_suite not in ('family','professional','team','business') then raise exception 'invalid suite' using errcode = '22023'; end if;
  if octet_length(p_name_nonce) <> 12 or octet_length(p_name_aad_hash) <> 32
    or octet_length(p_key_nonce) <> 12 or octet_length(p_wrapped_workspace_key) < 48
    or octet_length(p_encrypted_name) < 16 then
    raise exception 'invalid encrypted workspace envelope' using errcode = '22023';
  end if;
  if (p_suite = 'family' and p_workspace_kind <> 'shared')
    or (p_suite = 'professional' and p_workspace_kind not in ('client','project'))
    or (p_suite in ('team','business') and p_workspace_kind not in ('shared','project')) then
    raise exception 'workspace kind does not match suite' using errcode = '22023';
  end if;

  v_tenant_kind := case when p_suite = 'family' then 'family' else 'organization' end;
  insert into public.tenants(id,kind,created_by) values (p_tenant_id,v_tenant_kind,v_identity);
  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
    values (p_tenant_id,v_identity,'owner','active');
  insert into public.workspaces(id,tenant_id,kind,encrypted_name,created_by,suite,
    name_nonce,name_aad_hash,current_key_version,key_rotation_required,status)
    values (p_workspace_id,p_tenant_id,p_workspace_kind,p_encrypted_name,v_identity,
      p_suite,p_name_nonce,p_name_aad_hash,1,false,'active');
  insert into public.workspace_memberships(tenant_id,workspace_id,identity_id,role,status)
    values (p_tenant_id,p_workspace_id,v_identity,'owner','active');
  insert into public.key_envelopes(tenant_id,workspace_id,key_kind,key_version,
    recipient_identity_id,algorithm,nonce,wrapped_key)
    values (p_tenant_id,p_workspace_id,'workspace',1,v_identity,
      'AES-256-GCM',p_key_nonce,p_wrapped_workspace_key);

  return jsonb_build_object('tenant_id',p_tenant_id,'workspace_id',p_workspace_id,'suite',p_suite);
end
$$;

revoke all on function public.create_shared_workspace(uuid,uuid,text,text,bytea,bytea,bytea,bytea,bytea)
from public,anon;
grant execute on function public.create_shared_workspace(uuid,uuid,text,text,bytea,bytea,bytea,bytea,bytea)
to authenticated;

commit;
