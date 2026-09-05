begin;

-- Cover individual foreign keys; tenant-leading indexes serve different lookups.
create index organization_device_posture_device_fk_idx
  on public.organization_device_posture_reports(device_id);
create index organization_device_posture_identity_fk_idx
  on public.organization_device_posture_reports(identity_id);
create index organization_invitations_accepted_by_fk_idx
  on public.organization_invitations(accepted_by)
  where accepted_by is not null;
create index organization_invitations_created_by_fk_idx
  on public.organization_invitations(created_by);

-- Keep one UPDATE policy and evaluate request-local proof values once per statement.
drop policy organization_invitations_accept on public.organization_invitations;
drop policy organization_invitations_revoke on public.organization_invitations;
create policy organization_invitations_update
on public.organization_invitations for update to authenticated
using (
  (
    status = 'pending' and expires_at > now()
    and recipient_email_hash = (select private.current_verified_email_hash())
    and token_hash = decode(
      coalesce((select current_setting('request.passkey_x_org_invite_proof',true)),''),'hex'
    )
  )
  or (
    (select private.can_manage_organization_scope(
      tenant_id,array['organization_admin','helpdesk_admin'],department_id,team_id
    ))
    and (select current_setting('request.passkey_x_org_invite_revoke',true)) = id::text
  )
)
with check (
  (
    status = 'accepted'
    and accepted_by = (select private.current_identity_id())
    and accepted_at is not null and revoked_at is null
    and (select current_setting('request.passkey_x_org_invite_proof',true)) is not null
  )
  or (
    status = 'revoked' and revoked_at is not null
    and (select current_setting('request.passkey_x_org_invite_revoke',true)) = id::text
  )
);

-- Provisioning happens in a non-callable trigger only after the invitation UPDATE
-- has passed its verified-email and token-proof RLS policy. The exposed RPC stays
-- SECURITY INVOKER and never bypasses row security.
create or replace function private.provision_accepted_organization_invitation()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_identity uuid := private.current_identity_id();
begin
  if old.status <> 'pending' or new.status <> 'accepted' then return new; end if;
  if v_identity is null
    or new.accepted_by <> v_identity
    or old.recipient_email_hash <> private.current_verified_email_hash()
    or old.token_hash <> decode(
      coalesce(current_setting('request.passkey_x_org_invite_proof',true),''),'hex'
    ) then
    raise exception 'organization invitation proof is invalid' using errcode = '28000';
  end if;

  insert into public.tenant_memberships(tenant_id,identity_id,role,status)
  values (new.tenant_id,v_identity,'member','active')
  on conflict (tenant_id,identity_id) do nothing;

  insert into public.organization_profiles(
    tenant_id,identity_id,department_id,display_name,job_title,lifecycle_status,joined_on
  ) values (
    new.tenant_id,v_identity,new.department_id,
    new.display_name,new.job_title,'active',current_date
  );

  if new.team_id is not null then
    insert into public.organization_team_memberships(
      tenant_id,team_id,identity_id,role,status,assigned_by
    ) values (
      new.tenant_id,new.team_id,v_identity,new.team_role,'active',new.created_by
    );
  end if;

  insert into public.identity_lifecycle_events(
    tenant_id,subject_identity_id,event_type,to_department_id,to_team_id,
    actor_identity_id,reason_code
  ) values (
    new.tenant_id,v_identity,'joined',new.department_id,
    new.team_id,v_identity,'onboarding'
  );
  return new;
end
$$;
revoke all on function private.provision_accepted_organization_invitation()
  from public,anon,authenticated;
drop trigger if exists organization_invitation_provision on public.organization_invitations;
create trigger organization_invitation_provision
after update of status on public.organization_invitations
for each row execute function private.provision_accepted_organization_invitation();

create or replace function public.accept_organization_invitation(
  p_invitation_id uuid,
  p_token_hash bytea
) returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare
  v_identity uuid := private.current_identity_id();
  v_invitation public.organization_invitations%rowtype;
  v_invalidated_hash bytea;
begin
  if v_identity is null or private.current_verified_email_hash() is null then
    raise exception 'verified account required' using errcode = '28000';
  end if;
  if octet_length(p_token_hash) <> 32 then
    raise exception 'invalid organization invitation proof' using errcode = '22023';
  end if;

  perform set_config('request.passkey_x_org_invite_proof',encode(p_token_hash,'hex'),true);
  select * into v_invitation
  from public.organization_invitations invitation
  where invitation.id = p_invitation_id
    and invitation.status = 'pending'
    and invitation.expires_at > now()
    and invitation.recipient_email_hash = private.current_verified_email_hash()
    and invitation.token_hash = p_token_hash
  for update;
  if not found then
    raise exception 'organization invitation is invalid or expired' using errcode = '28000';
  end if;

  v_invalidated_hash := extensions.digest(p_token_hash || uuid_send(p_invitation_id),'sha256');
  update public.organization_invitations
  set status = 'accepted',accepted_by = v_identity,accepted_at = now(),
      updated_at = now(),token_hash = v_invalidated_hash
  where id = p_invitation_id;

  return jsonb_build_object(
    'tenant_id',v_invitation.tenant_id,
    'department_id',v_invitation.department_id,
    'team_id',v_invitation.team_id
  );
end
$$;

-- Merge equivalent permissive read policies so the planner evaluates one policy.
drop policy audit_events_business_export_read on public.audit_events;
drop policy audit_events_read on public.audit_events;
create policy audit_events_read
on public.audit_events for select to authenticated
using ((select private.can_export_organization_audit(tenant_id)));

drop policy devices_organization_security_read on public.devices;
drop policy devices_read_self on public.devices;
create policy devices_read_authorized
on public.devices for select to authenticated
using (
  identity_id = (select private.current_identity_id())
  or exists (
    select 1
    from public.tenant_memberships membership
    where membership.identity_id = devices.identity_id
      and membership.status = 'active'
      and private.can_manage_organization_identity(
        membership.tenant_id,array['organization_admin','security_admin','auditor'],devices.identity_id
      )
  )
);

comment on function public.accept_organization_invitation(uuid,bytea) is
  'Authenticated SECURITY INVOKER ceremony; RLS verifies the email and token before a non-callable provisioning trigger runs.';

commit;
