// `npm run build -- <tauri build args>`.
// Signed automatic updates are switched on only when this build can sign them: the public
// key is committed in updater.pub and the private key is provided by CI as
// TAURI_SIGNING_PRIVATE_KEY (never committed). Otherwise the app is built without the
// updater and tells people to download new versions manually.
import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const pubkey = (await readFile(join(root, 'updater.pub'), 'utf8').catch(() => '')).trim();
const canSign = Boolean(pubkey && process.env.TAURI_SIGNING_PRIVATE_KEY);
const extra = [];
if (canSign) {
  const overlay = join(root, 'src-tauri', 'tauri.updater.conf.json');
  await writeFile(overlay, JSON.stringify({
    bundle: { createUpdaterArtifacts: true },
    plugins: { updater: { pubkey, endpoints: ['https://passkey-x.com/releases/desktop/latest.json'] } },
  }, null, 2));
  extra.push('--features', 'updater', '--config', overlay);
  console.log('desktop build: signed updates enabled');
} else {
  console.log('desktop build: no updater signing key, building without automatic updates');
}
const split = args.indexOf('--');
const tauriArgs = split === -1 ? [...args, ...extra] : [...args.slice(0, split), ...extra, ...args.slice(split)];
execFileSync(process.execPath, [join(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js'), 'build', ...tauriArgs], { cwd: root, stdio: 'inherit' });
