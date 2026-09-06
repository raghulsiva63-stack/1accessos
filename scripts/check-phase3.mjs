import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const client = await readFile("apps/web/lib/supabase/client.ts", "utf8");
const page = await readFile("apps/web/app/page.tsx", "utf8");
const environment = await readFile("apps/web/.env.example", "utf8");
const netlify = await readFile("netlify.toml", "utf8");
const decision = await readFile("docs/architecture/ADR-0007-passkey-relying-party.md", "utf8");
const scope = await readFile("docs/phase3/phase-3-scope.md", "utf8");
const manifest = JSON.parse(await readFile("apps/web/package.json", "utf8"));

assert.equal(environment.match(/NEXT_PUBLIC_PASSKEYS_ENABLED=(.*)/)?.[1], "false");
assert.match(netlify, /\[context\.production\.environment\][\s\S]*?NEXT_PUBLIC_PASSKEYS_ENABLED = "true"/);
assert.match(netlify, /\[context\.deploy-preview\.environment\][\s\S]*?NEXT_PUBLIC_PASSKEYS_ENABLED = "false"/);
assert.match(netlify, /\[context\.branch-deploy\.environment\][\s\S]*?NEXT_PUBLIC_PASSKEYS_ENABLED = "false"/);
assert.match(client, /experimental:\s*\{\s*passkey:\s*passkeysEnabled\s*\}/);
assert.match(page, /auth\.signInWithPasskey\(/);
assert.match(page, /auth\.registerPasskey\(\)/);
assert.match(page, /auth\.passkey\.list\(\)/);
assert.match(page, /auth\.passkey\.update\(/);
assert.match(page, /auth\.passkey\.delete\(/);
assert.match(page, /separate vault password/i);
assert.match(decision, /passkey-x\.com/);
assert.match(scope, /https:\/\/passkey-x\.com/);
assert.doesNotMatch(`${decision}\n${scope}\n${page}`, /app\.passkey-x\.com/);
assert.doesNotMatch(page, /Ready for domain activation|Supabase Auth activation pending|Connect the development project|Phase 2 preview|development environment/);
assert.match(page, /Passkeys are unavailable/);
assert.match(page, /customerError\(result\.error/);

const [major, minor] = manifest.dependencies["@supabase/supabase-js"].split(".").map(Number);
assert.ok(major > 2 || (major === 2 && minor >= 105), "Supabase client lacks passkey support");

console.log("Phase 3 passkey boundary, production activation, preview isolation, and customer-safe UI checks passed.");
