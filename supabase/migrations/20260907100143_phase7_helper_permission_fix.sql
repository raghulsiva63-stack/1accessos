-- Exported from production supabase_migrations.schema_migrations (20260907100143_phase7_helper_permission_fix).
begin;

-- Backend certification and delivery writers must be able to evaluate the
-- immutable validation helpers used by table CHECK constraints.
grant execute on function private.valid_enterprise_regions(text[]),
  private.valid_siem_event_types(text[]) to service_role;

commit;
