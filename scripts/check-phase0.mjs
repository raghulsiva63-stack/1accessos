import { readFile, readdir } from 'node:fs/promises';
import assert from 'node:assert/strict';

const migration = await readFile('supabase/migrations/00000000000000_phase0_core.sql', 'utf8');
const tables = [...migration.matchAll(/create table public\.([a-z_]+)/g)].map((match) => match[1]);
const rls = new Set([...migration.matchAll(/alter table public\.([a-z_]+) enable row level security/g)].map((match) => match[1]));
assert.ok(tables.length >= 15, 'expected the Phase 0 core tables');
for (const table of tables) assert.ok(rls.has(table), `RLS missing for ${table}`);
assert.doesNotMatch(migration, /auth\.role\s*\(/i, 'deprecated auth.role() is prohibited');
assert.match(migration, /revoke all on all tables in schema public from anon, authenticated/i);

const openapi = await readFile('docs/api/openapi.yaml', 'utf8');
assert.match(openapi, /^openapi: 3\.1\.0/m);
assert.match(openapi, /\/sync\/changes:/);
assert.doesNotMatch(openapi, /plaintext_password|master_password|private_key:/i);

const securityDocs = await readdir('docs/security');
for (const required of ['threat-model.md', 'crypto-envelope.md', 'phase-0-gates.md']) {
  assert.ok(securityDocs.includes(required), `missing ${required}`);
}

console.log(`Phase 0 static checks passed for ${tables.length} RLS-enabled tables.`);

