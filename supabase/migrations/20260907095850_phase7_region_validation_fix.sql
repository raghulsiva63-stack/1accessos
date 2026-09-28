-- Exported from production supabase_migrations.schema_migrations (20260907095850_phase7_region_validation_fix).
begin;

create or replace function private.valid_enterprise_regions(p_regions text[])
returns boolean language sql immutable strict set search_path = ''
as $$
  select cardinality(p_regions) <= 12 and not exists (
    select 1 from unnest(p_regions) as region(value)
    where value !~ '^[a-z]{2}(?:-[a-z]+)+(?:-[0-9]+)?$'
  )
$$;

revoke all on function private.valid_enterprise_regions(text[]) from public,anon,authenticated;

commit;
