-- Exported from production supabase_migrations.schema_migrations (20260907100418_phase6_scope_validator_permission_fix).
begin;

-- PostgreSQL evaluates this immutable boolean helper from CHECK constraints
-- under the statement caller. Guarded runtime RPCs therefore need the caller
-- to execute the validator even though direct table writes remain revoked.
grant execute on function private.valid_runtime_scopes(text[],boolean)
  to authenticated,service_role;

comment on function private.valid_runtime_scopes(text[],boolean) is
  'Pure runtime-scope shape validator used by CHECK constraints; it reads no data and performs no writes.';

commit;
