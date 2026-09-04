begin;

-- Server-owned tables intentionally deny all direct authenticated access.
create policy idempotency_records_deny_client on public.idempotency_records
  for all to authenticated using (false) with check (false);
create policy outbox_events_deny_client on public.outbox_events
  for all to authenticated using (false) with check (false);

-- Cover foreign keys used by authorization, cascading deletes, and audit queries.
create index api_tokens_identity_fk_idx on public.api_tokens(identity_id);
create index attachments_created_by_fk_idx on public.attachments(created_by);
create index attachments_item_fk_idx on public.attachments(tenant_id, item_id);
create index attachments_workspace_fk_idx on public.attachments(tenant_id, workspace_id);
create index audit_events_actor_fk_idx on public.audit_events(actor_identity_id);
create index conflicts_created_by_fk_idx on public.conflicts(created_by);
create index conflicts_item_fk_idx on public.conflicts(tenant_id, item_id);
create index conflicts_workspace_fk_idx on public.conflicts(tenant_id, workspace_id);
create index key_envelopes_device_fk_idx on public.key_envelopes(recipient_device_id);
create index key_envelopes_identity_fk_idx on public.key_envelopes(recipient_identity_id);
create index key_envelopes_tenant_fk_idx on public.key_envelopes(tenant_id);
create index key_envelopes_workspace_fk_idx on public.key_envelopes(tenant_id, workspace_id);
create index outbox_events_tenant_fk_idx on public.outbox_events(tenant_id);
create index tenants_created_by_fk_idx on public.tenants(created_by);
create index revisions_created_by_fk_idx on public.vault_item_revisions(created_by);
create index revisions_item_fk_idx on public.vault_item_revisions(tenant_id, item_id);
create index vault_items_created_by_fk_idx on public.vault_items(created_by);
create index workspace_memberships_tenant_identity_fk_idx on public.workspace_memberships(tenant_id, identity_id);
create index workspace_memberships_workspace_fk_idx on public.workspace_memberships(tenant_id, workspace_id);
create index workspaces_created_by_fk_idx on public.workspaces(created_by);

commit;
