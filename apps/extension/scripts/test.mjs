import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const run = (script, args = [], env = process.env) => execFileSync(process.execPath, [script, ...args], { cwd: root, env, stdio: 'inherit' });
run(`${root}node_modules/typescript/bin/tsc`, ['--noEmit']);
// Test bundles never replace the production package or need a real account key.
run(`${root}node_modules/vite/bin/vite.js`, ['build', '--outDir', 'dist-test'], {
  ...process.env, VITE_SUPABASE_URL: 'https://wkkmyacbhqloubtwvjom.supabase.co',
  VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_test_placeholder',
});
run('--test', readdirSync(`${root}tests`).filter(name => name.endsWith('.test.mjs')).sort().map(name => `tests/${name}`));
