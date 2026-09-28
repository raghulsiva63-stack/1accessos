#!/usr/bin/env bash
# Applies every migration to a throwaway PostgreSQL cluster (with stand-ins for the
# Supabase platform schemas) and runs supabase/tests/*.sql. Used by CI.
# Requires PostgreSQL 15+ server binaries; set PG_BIN if they are not on PATH.
set -euo pipefail
export PGOPTIONS="${PGOPTIONS:--c client_min_messages=warning}"
here="$(cd "$(dirname "$0")" && pwd)"
PG_BIN="${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
ext_dir="$("$PG_BIN/pg_config" --sharedir)/extension"
sudo_cmd=""; [ "$(id -u)" -ne 0 ] && sudo_cmd="sudo"
$sudo_cmd cp "$here"/support/pg_cron.control "$here"/support/pg_cron--1.0.sql "$here"/support/pg_net.control "$here"/support/pg_net--1.0.sql "$ext_dir/"

work="$(mktemp -d)"; chmod 777 "$work"
run_as=""; [ "$(id -u)" -eq 0 ] && run_as="su nobody -s /bin/sh -c"
start() { if [ -n "$run_as" ]; then $run_as "$*"; else sh -c "$*"; fi; }
start "$PG_BIN/initdb -D $work/data -U postgres --auth=trust >/dev/null"
start "$PG_BIN/pg_ctl -D $work/data -o '-k $work -p 55439 -c listen_addresses=' -l $work/log -w start >/dev/null"
trap 'start "$PG_BIN/pg_ctl -D $work/data -m immediate stop >/dev/null" || true' EXIT

psql_cmd=(psql -h "$work" -p 55439 -U postgres -v ON_ERROR_STOP=1 -q -o /dev/null)
"${psql_cmd[@]}" -c "create database px"
"${psql_cmd[@]}" -d px -f "$here/support/supabase_stub.sql" -c "create extension pg_cron"
for file in $(ls "$here"/../migrations/*.sql | sort); do
  "${psql_cmd[@]}" -d px -f "$file" || { echo "migration failed: $(basename "$file")"; exit 1; }
done
echo "migrations: ok"
failed=0
for file in "$here"/*.sql; do
  if "${psql_cmd[@]}" -d px -f "$file" > "$work/out.txt" 2>&1; then echo "ok   $(basename "$file")"
  else echo "FAIL $(basename "$file")"; grep -i error "$work/out.txt" | head -5; failed=1; fi
done
exit $failed
