# Supabase Advisor Baseline

Date: 2026-09-05

- Database-facing security errors and warnings are zero after the Phase 1 invoker/RLS hardening migrations.
- Supabase Auth leaked-password screening is a separate project setting and remains a release gate until enabled in the dashboard.
- All application tables use RLS.
- Server-owned public tables have explicit deny policies and no client grants.
- Foreign-key coverage and multiple-permissive-policy findings are fixed through Phase 5.
- `unused_index` information notices are expected on the near-empty development database. They are reviewed after representative Business load tests; authorization, lifecycle and sync indexes are not removed merely because the database has no traffic.
