-- Exported from production supabase_migrations.schema_migrations (20260907100028_phase6_runtime_invoker_permission_fix).
begin;

-- The Phase 6 public SECURITY INVOKER RPCs call these boolean-only helpers.
-- The original migration revoked them from authenticated, which made the
-- dashboard and Access Twin simulation fail before their tenant checks ran.
grant execute on function private.can_view_runtime_tenant(uuid),
  private.can_manage_runtime_tenant(uuid) to authenticated;

commit;
