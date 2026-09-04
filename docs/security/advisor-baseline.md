# Supabase Advisor Baseline

Date: 2026-09-04

- Phase 0 security errors and warnings are zero. Phase 1 permits only the reviewed authenticated bootstrap-function warning documented in `docs/phase1/checkpoint-01.md`.
- All application tables use RLS.
- Server-owned public tables have explicit deny policies and no client grants.
- Foreign-key coverage findings are fixed.
- `unused_index` information notices are expected on an empty development database. They are reviewed after representative Phase 1 load tests; authorization and sync indexes are not removed merely because the database has no traffic.
