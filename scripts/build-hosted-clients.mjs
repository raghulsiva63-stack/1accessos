import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const env = { ...process.env,
  VITE_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
  VITE_SUPABASE_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
};
if (!env.VITE_SUPABASE_URL || !env.VITE_SUPABASE_PUBLISHABLE_KEY) throw new Error('Hosted client build needs the public Supabase configuration.');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
execFileSync(npm, ['--prefix', 'apps/extension', 'ci', '--no-audit', '--no-fund'], { cwd: root, env, stdio: 'inherit' });
execFileSync(npm, ['run', 'build:clients'], { cwd: root, env, stdio: 'inherit' });
