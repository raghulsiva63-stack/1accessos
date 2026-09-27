-- Resolve RETURNS TABLE / column name ambiguity in open_secure_send (found by the
-- rollback-only integration test).
create or replace function private.open_secure_send(p_id uuid, p_proof bytea)
returns table (kind text, nonce bytea, ciphertext bytea, views_left integer)
language plpgsql volatile security definer set search_path = ''
as $$
#variable_conflict use_column
declare v_send public.secure_sends%rowtype;
begin
  select * into v_send from public.secure_sends s where s.id = p_id for update;
  if not found or v_send.revoked_at is not null or v_send.expires_at <= now()
     or v_send.view_count >= v_send.max_views or v_send.ciphertext is null
     or v_send.failed_attempts >= 10 then
    raise exception 'this link has expired or was already used' using errcode = 'P0002';
  end if;
  -- Only holders of the full link key (and passphrase, if any) can consume a view.
  if p_proof is null or octet_length(p_proof) <> 32
     or extensions.digest(p_proof,'sha256') <> v_send.access_check then
    update public.secure_sends set failed_attempts = failed_attempts + 1 where id = p_id;
    return;
  end if;
  update public.secure_sends set view_count = view_count + 1, last_viewed_at = now(),
    ciphertext = case when view_count + 1 >= max_views then null else ciphertext end
    where id = p_id;
  perform private.append_audit_event(v_send.tenant_id, private.current_identity_id(), 'secure_send.opened',
    'secure_sends', p_id, jsonb_build_object('view', v_send.view_count + 1, 'max_views', v_send.max_views));
  return query select v_send.kind, v_send.nonce, v_send.ciphertext,
    v_send.max_views - v_send.view_count - 1;
end
$$;
