// `npm run build -- <tauri build args>`.
// Signed automatic updates are switched on only when this build can sign them: the public
// key is committed in updater.pub and the private key is provided by CI as
// TAURI_SIGNING_PRIVATE_KEY (never committed). Otherwise the app is built without the
// updater and tells people to download new versions manually.
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
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
// Windows: build the MSI (for IT deployment through Intune, Group Policy or SCCM) next to the
// per-user NSIS installer.
const bundles = args.indexOf('--bundles');
if (process.platform === 'win32' && bundles !== -1 && args[bundles + 1] === 'nsis' && process.env.PASSKEY_X_SKIP_MSI !== '1') {
  args[bundles + 1] = 'nsis,msi';
}
// macOS universal builds: Tauri merges only the app binary into a universal one, but the bundle
// also ships the `pkx` command-line tool. Build pkx for both architectures and merge it first so
// the bundler finds target/universal-apple-darwin/release/pkx.
const targetIndex = args.indexOf('--target');
if (targetIndex !== -1 && args[targetIndex + 1] === 'universal-apple-darwin') {
  const manifest = join(root, 'src-tauri', 'Cargo.toml');
  const targetDir = join(root, 'src-tauri', 'target');
  const locked = args.includes('--locked') ? ['--locked'] : [];
  const parts = [];
  for (const triple of ['aarch64-apple-darwin', 'x86_64-apple-darwin']) {
    execFileSync('cargo', ['build', '--release', '--manifest-path', manifest, '--bin', 'pkx', '--target', triple, ...locked], { cwd: root, stdio: 'inherit' });
    parts.push(join(targetDir, triple, 'release', 'pkx'));
  }
  const out = join(targetDir, 'universal-apple-darwin', 'release');
  await mkdir(out, { recursive: true });
  execFileSync('lipo', ['-create', '-output', join(out, 'pkx'), ...parts], { stdio: 'inherit' });
  // lipo drops the linker's ad-hoc signature; codesign of the app refuses unsigned subcomponents.
  execFileSync('codesign', ['--force', '--sign', '-', join(out, 'pkx')], { stdio: 'inherit' });
  console.log('desktop build: universal pkx ready');
}
const split = args.indexOf('--');
const tauriArgs = split === -1 ? [...args, ...extra] : [...args.slice(0, split), ...extra, ...args.slice(split)];
execFileSync(process.execPath, [join(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js'), 'build', ...tauriArgs], { cwd: root, stdio: 'inherit' });
