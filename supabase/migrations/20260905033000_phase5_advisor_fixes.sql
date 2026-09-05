begin;

create index identity_lifecycle_events_subject_identity_idx
  on public.identity_lifecycle_events(subject_identity_id);
create index identity_lifecycle_events_from_department_idx
  on public.identity_lifecycle_events(tenant_id,from_department_id);
create index identity_lifecycle_events_to_department_idx
  on public.identity_lifecycle_events(tenant_id,to_department_id);
create index identity_lifecycle_events_from_team_idx
  on public.identity_lifecycle_events(tenant_id,from_team_id);
create index identity_lifecycle_events_to_team_idx
  on public.identity_lifecycle_events(tenant_id,to_team_id);
create index organization_group_memberships_tenant_group_idx
  on public.organization_group_memberships(tenant_id,group_id);
create index organization_team_memberships_tenant_team_idx
  on public.organization_team_memberships(tenant_id,team_id);

drop policy organization_departments_manage on public.organization_departments;
create policy organization_departments_insert on public.organization_departments for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_departments_update on public.organization_departments for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_departments_delete on public.organization_departments for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

drop policy organization_teams_manage on public.organization_teams;
create policy organization_teams_insert on public.organization_teams for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_teams_update on public.organization_teams for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_teams_delete on public.organization_teams for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

drop policy organization_groups_manage on public.organization_groups;
create policy organization_groups_insert on public.organization_groups for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_groups_update on public.organization_groups for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));
create policy organization_groups_delete on public.organization_groups for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin'])));

drop policy organization_profiles_manage on public.organization_profiles;
create policy organization_profiles_insert on public.organization_profiles for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_profiles_update on public.organization_profiles for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_profiles_delete on public.organization_profiles for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

drop policy organization_team_memberships_manage on public.organization_team_memberships;
create policy organization_team_memberships_insert on public.organization_team_memberships for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_team_memberships_update on public.organization_team_memberships for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_team_memberships_delete on public.organization_team_memberships for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

drop policy organization_group_memberships_manage on public.organization_group_memberships;
create policy organization_group_memberships_insert on public.organization_group_memberships for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_group_memberships_update on public.organization_group_memberships for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));
create policy organization_group_memberships_delete on public.organization_group_memberships for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin'])));

drop policy organization_admin_assignments_manage on public.organization_admin_assignments;
create policy organization_admin_assignments_insert on public.organization_admin_assignments for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])));
create policy organization_admin_assignments_update on public.organization_admin_assignments for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])));
create policy organization_admin_assignments_delete on public.organization_admin_assignments for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.has_tenant_role(tenant_id,array['owner','admin'])));

drop policy organization_policies_manage on public.organization_policies;
create policy organization_policies_insert on public.organization_policies for insert to authenticated
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])));
create policy organization_policies_update on public.organization_policies for update to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])))
  with check ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])));
create policy organization_policies_delete on public.organization_policies for delete to authenticated
  using ((select private.has_business_entitlement(tenant_id)) and (select private.can_manage_organization(tenant_id,array['organization_admin','security_admin'])));

drop policy workspace_memberships_member_revoke on public.workspace_memberships;
drop policy workspace_memberships_business_lifecycle_update on public.workspace_memberships;
create policy workspace_memberships_update on public.workspace_memberships for update to authenticated
using (
  (
    role <> 'owner'
    and (select private.can_manage_workspace(tenant_id,workspace_id))
    and (select current_setting('request.passkey_x_member_revoke',true))=workspace_id::text||':'||identity_id::text
  )
  or (
    role <> 'owner'
    and (select private.has_business_entitlement(tenant_id))
    and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
  )
)
with check (
  (status='revoked' and role <> 'owner')
  or (
    role <> 'owner' and status in ('active','suspended','revoked')
    and (select private.has_business_entitlement(tenant_id))
    and (select private.can_manage_organization(tenant_id,array['organization_admin','helpdesk_admin','security_admin']))
  )
);

commit;
