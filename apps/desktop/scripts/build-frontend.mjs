// Builds everything the desktop app bundles:
//  1. native icons from the brand icon;
//  2. the Passkey-X web app as a static export, baked into the app (dist/), so the desktop
//     app never runs code downloaded from a website.
// Tauri calls this again as beforeBuildCommand; the second call reuses dist/ when it was
// built from the same sources (set PASSKEY_X_REBUILD=1 to force a rebuild).
import { access, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const web = fileURLToPath(new URL('../../web/', import.meta.url));
const dist = join(root, 'dist');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (command, args, options) => execFileSync(command, args, { stdio: 'inherit', shell: process.platform === 'win32' && command.endsWith('.cmd'), ...options });

// 1. Icons
run(process.execPath, ['node_modules/@tauri-apps/cli/tauri.js', 'icon', 'icons/icon.png', '--output', 'src-tauri/icons'], { cwd: root });

// 2. Web app
const config = JSON.parse(await readFile(join(root, 'desktop.config.json'), 'utf8'));
delete config.comment;
const commit = process.env.GITHUB_SHA ?? 'local';
const stamp = createHash('sha256').update(JSON.stringify(config) + commit).digest('hex');
const marker = join(dist, '.passkey-x-build');
const fresh = await readFile(marker, 'utf8').then((value) => value.trim() === stamp, () => false);
if (fresh && process.env.PASSKEY_X_REBUILD !== '1') {
  console.log('desktop frontend: reusing dist/');
  process.exit(0);
}

const hasModules = await access(join(web, 'node_modules', 'next')).then(() => true, () => false);
if (!hasModules) run(npm, ['ci', '--no-audit', '--no-fund'], { cwd: web });
run(npm, ['run', 'build'], { cwd: web, env: { ...process.env, ...config, PASSKEY_X_DESKTOP_BUILD: '1', NEXT_TELEMETRY_DISABLED: '1' } });

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
// Large or web-only folders are not needed inside the app.
const skip = new Set(['downloads', 'releases', 'client-testing.md', 'openapi.yaml', 'sw.js']);
await cp(join(web, 'out'), dist, { recursive: true, filter: (source) => !skip.has(source.slice(join(web, 'out').length + 1).split(/[\\/]/u)[0]) });
await access(join(dist, 'index.html'));
await writeFile(marker, stamp + '\n');
console.log('desktop frontend: bundled web app into dist/');
