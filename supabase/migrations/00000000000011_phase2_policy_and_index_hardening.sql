begin;

-- Cover every Phase 2 foreign key used by deletes, membership checks, audit
-- lookup, or lifecycle maintenance. The database linter ignores partial
-- indexes when determining full foreign-key coverage.
create index workspace_invites_accepted_by_fk_idx on public.workspace_invites(accepted_by);
create index workspace_invites_created_by_fk_idx on public.workspace_invites(created_by);
create index access_capsules_accepted_by_fk_idx on public.access_capsules(accepted_by);
create index access_capsules_created_by_fk_idx on public.access_capsules(created_by);
create index access_capsules_tenant_item_fk_idx on public.access_capsules(tenant_id,item_id);
create index access_requests_requester_fk_idx on public.access_requests(requester_identity_id);
create index access_requests_tenant_item_fk_idx on public.access_requests(tenant_id,item_id);
create index approvals_approver_fk_idx on public.approvals(approver_identity_id);
create index approvals_tenant_workspace_fk_idx on public.approvals(tenant_id,workspace_id);
create index access_grants_created_by_fk_idx on public.access_grants(created_by);
create index access_grants_source_request_fk_idx on public.access_grants(source_request_id);
create index access_grants_tenant_workspace_fk_idx on public.access_grants(tenant_id,workspace_id);
create index access_grants_tenant_item_fk_idx on public.access_grants(tenant_id,item_id);
create index missions_created_by_fk_idx on public.missions(created_by);
create index mission_items_tenant_workspace_fk_idx on public.mission_items(tenant_id,workspace_id);
create index mission_items_tenant_item_fk_idx on public.mission_items(tenant_id,item_id);
create index mission_runs_started_by_fk_idx on public.mission_runs(started_by);
create index mission_runs_tenant_workspace_fk_idx on public.mission_runs(tenant_id,workspace_id);

-- Merge alternative INSERT paths into one policy per table. Exact outer-table
-- qualification in the invite branches is security-critical: it prevents an
-- accepted invite from authorizing insertion into another tenant or workspace.
drop policy tenants_bootstrap_personal on public.tenants;
drop policy tenants_phase2_create on public.tenants;
create policy tenants_create on public.tenants for insert to authenticated
with check (
  created_by = (select private.current_identity_id())
  and (
    kind = 'personal'
    or (kind in ('family','organization') and (select private.phase2_enabled()))
  )
);

drop policy tenant_memberships_bootstrap_owner on public.tenant_memberships;
drop policy tenant_memberships_phase2_owner on public.tenant_memberships;
drop policy tenant_memberships_invite_accept on public.tenant_memberships;
create policy tenant_memberships_create on public.tenant_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id()) and status = 'active' and (
    (role = 'owner' and (select private.owns_personal_tenant(tenant_memberships.tenant_id)))
    or (role = 'owner' and (select private.owns_phase2_tenant(tenant_memberships.tenant_id)))
    or (role = 'member' and exists (
      select 1 from public.workspace_invites wi
      where wi.tenant_id = tenant_memberships.tenant_id
        and wi.accepted_by = tenant_memberships.identity_id
        and wi.status = 'accepted'
    ))
  )
);

drop policy workspaces_bootstrap_personal on public.workspaces;
drop policy workspaces_phase2_create on public.workspaces;
create policy workspaces_create on public.workspaces for insert to authenticated
with check (
  created_by = (select private.current_identity_id()) and (
    (kind = 'vault' and (select private.owns_personal_tenant(workspaces.tenant_id)))
    or (
      kind in ('project','client','shared')
      and suite in ('family','professional','team')
      and (select private.owns_phase2_tenant(workspaces.tenant_id))
      and (select private.phase2_enabled())
    )
  )
);

drop policy workspace_memberships_bootstrap_owner on public.workspace_memberships;
drop policy workspace_memberships_phase2_owner on public.workspace_memberships;
drop policy workspace_memberships_invite_accept on public.workspace_memberships;
create policy workspace_memberships_create on public.workspace_memberships for insert to authenticated
with check (
  identity_id = (select private.current_identity_id()) and status = 'active' and (
    (role = 'owner' and (select private.owns_personal_workspace(workspace_memberships.tenant_id, workspace_memberships.workspace_id)))
    or (role = 'owner' and (select private.owns_phase2_workspace(workspace_memberships.tenant_id, workspace_memberships.workspace_id)))
    or exists (
      select 1 from public.workspace_invites wi
      where wi.tenant_id = workspace_memberships.tenant_id
        and wi.workspace_id = workspace_memberships.workspace_id
        and wi.accepted_by = workspace_memberships.identity_id
        and wi.status = 'accepted'
        and wi.role = workspace_memberships.role
    )
  )
);

drop policy key_envelopes_insert on public.key_envelopes;
drop policy key_envelopes_recipient_insert on public.key_envelopes;
create policy key_envelopes_insert on public.key_envelopes for insert to authenticated
with check (
  workspace_id is not null and (
    (select private.has_workspace_role(tenant_id,workspace_id,array['owner','manager']))
    or (
      key_kind = 'workspace'
      and recipient_identity_id = (select private.current_identity_id())
      and recipient_device_id is null
      and revoked_at is null
      and (select private.has_workspace_role(tenant_id,workspace_id,array['owner','manager','editor','viewer']))
    )
  )
);

-- Merge alternative state transitions and wrap configuration reads in scalar
-- subqueries so PostgreSQL evaluates them once per statement rather than row.
drop policy workspace_invites_accept on public.workspace_invites;
drop policy workspace_invites_revoke on public.workspace_invites;
create policy workspace_invites_update on public.workspace_invites for update to authenticated
using (
  (
    status = 'pending' and expires_at > now()
    and recipient_email_hash = (select private.current_verified_email_hash())
    and token_hash = decode(coalesce((select current_setting('request.passkey_x_invite_proof',true)),''),'hex')
  )
  or (
    (select private.can_manage_workspace(tenant_id,workspace_id))
    and (select current_setting('request.passkey_x_invite_revoke',true)) = id::text
  )
)
with check (
  (status = 'accepted' and accepted_by = (select private.current_identity_id()) and accepted_at is not null and revoked_at is null)
  or (status = 'revoked' and revoked_at is not null)
);

drop policy access_capsules_accept on public.access_capsules;
drop policy access_capsules_consume on public.access_capsules;
drop policy access_capsules_revoke on public.access_capsules;
create policy access_capsules_update on public.access_capsules for update to authenticated
using (
  (
    status = 'pending' and now() between not_before and expires_at
    and recipient_email_hash = (select private.current_verified_email_hash())
    and token_hash = decode(coalesce((select current_setting('request.passkey_x_capsule_proof',true)),''),'hex')
  )
  or (
    status = 'accepted' and accepted_by = (select private.current_identity_id())
    and now() between not_before and expires_at
    and (select current_setting('request.passkey_x_capsule_consume',true)) = id::text
  )
  or (
    (select private.can_manage_workspace(tenant_id,workspace_id))
    and (select current_setting('request.passkey_x_capsule_revoke',true)) = id::text
  )
)
with check (
  (
    status = 'accepted' and accepted_by = (select private.current_identity_id())
    and accepted_at is not null and recipient_key_nonce is not null
    and recipient_wrapped_key is not null and recipient_key_aad_hash is not null
    and revoked_at is null
  )
  or (
    accepted_by = (select private.current_identity_id())
    and status in ('accepted','consumed')
    and use_count <= case when max_uses = 0 then 100000 else max_uses end
  )
  or (status = 'revoked' and revoked_at is not null)
);

-- Recreate policies whose only issue is per-row current_setting evaluation.
drop policy workspace_invites_read on public.workspace_invites;
create policy workspace_invites_read on public.workspace_invites for select to authenticated
using (
  (select private.can_manage_workspace(tenant_id,workspace_id))
  or (status='pending' and expires_at > now() and recipient_email_hash=(select private.current_verified_email_hash()))
  or (
    status='accepted' and accepted_by=(select private.current_identity_id()) and (
      (select private.has_workspace_role(tenant_id,workspace_id,array['owner','manager','editor','viewer']))
      or (select current_setting('request.passkey_x_invite_accepting',true)) = id::text
    )
  )
);

drop policy access_capsules_read on public.access_capsules;
create policy access_capsules_read on public.access_capsules for select to authenticated
using (
  (select private.can_manage_workspace(tenant_id,workspace_id))
  or (status='pending' and now() between not_before and expires_at and recipient_email_hash=(select private.current_verified_email_hash()))
  or (status='accepted' and accepted_by=(select private.current_identity_id()) and now() between not_before and expires_at and (max_uses=0 or use_count<max_uses))
  or (accepted_by=(select private.current_identity_id()) and (select current_setting('request.passkey_x_capsule_consume',true))=id::text)
);

drop policy access_requests_decide on public.access_requests;
create policy access_requests_decide on public.access_requests for update to authenticated
using (
  status='pending' and (select private.can_manage_workspace(tenant_id,workspace_id))
  and (select current_setting('request.passkey_x_approval',true))=id::text
)
with check (status in ('approved','denied') and decided_at is not null);

drop policy workspace_memberships_member_revoke on public.workspace_memberships;
create policy workspace_memberships_member_revoke on public.workspace_memberships for update to authenticated
using (
  role <> 'owner' and (select private.can_manage_workspace(tenant_id,workspace_id))
  and (select current_setting('request.passkey_x_member_revoke',true))=workspace_id::text||':'||identity_id::text
)
with check (status='revoked' and role <> 'owner');

drop policy key_envelopes_member_revoke on public.key_envelopes;
create policy key_envelopes_member_revoke on public.key_envelopes for update to authenticated
using (
  workspace_id is not null and (select private.can_manage_workspace(tenant_id,workspace_id))
  and (select current_setting('request.passkey_x_member_revoke',true))=workspace_id::text||':'||recipient_identity_id::text
)
with check (revoked_at is not null);

drop policy workspaces_mark_rotation on public.workspaces;
create policy workspaces_mark_rotation on public.workspaces for update to authenticated
using (
  (select private.can_manage_workspace(tenant_id,id))
  and (select current_setting('request.passkey_x_member_revoke',true)) like id::text||':%'
)
with check (key_rotation_required=true);

commit;
