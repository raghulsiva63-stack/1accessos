import { readdir, readFile, mkdir, copyFile, writeFile, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { createHash } from 'node:crypto';
const platform = process.argv[2];
const extensions = { 'windows-x64': ['.exe', '.msi'], 'macos-universal': ['.dmg'], 'linux-x64': ['.deb'] }[platform];
if (!extensions) throw new Error('Unknown release platform');
const version = JSON.parse(await readFile('src-tauri/tauri.conf.json', 'utf8')).version;
async function walk(directory, extension) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path, extension));
    else if (path.includes(`${process.platform === 'win32' ? '\\' : '/'}bundle${process.platform === 'win32' ? '\\' : '/'}`) && path.endsWith(extension)) files.push(path);
  }
  return files;
}
async function walkAll(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walkAll(path)); else files.push(path);
  }
  return files;
}
await mkdir('artifacts', { recursive: true });
const installers = [];
for (const extension of extensions) {
  // The build cache can still hold installers of earlier versions: keep this version's only.
  const found = (await walk('src-tauri/target', extension)).filter((file) => basename(file).includes(`_${version}_`));
  const files = [];
  for (const file of found) files.push({ file, modified: (await stat(file)).mtimeMs });
  files.sort((a, b) => b.modified - a.modified);
  if (files.length > 1) console.log(`::warning::Found ${files.length} ${extension} installers for ${version}; using the newest.`);
  if (files.length === 0) {
    // The MSI is optional (PASSKEY_X_SKIP_MSI=1); every other installer is required.
    if (extension === '.msi' && files.length === 0) continue;
    throw new Error(`Expected one ${extension} installer, found ${files.length}`);
  }
  const filename = `passkey-x-desktop-${version}-${platform}${extension}`;
  await copyFile(files[0].file, join('artifacts', filename));
  const bytes = await readFile(files[0].file);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  await writeFile(join('artifacts', filename + '.sha256'), `${sha256}  ${filename}\n`);
  installers.push({ filename, sha256, bytes: bytes.length });
}
const [{ filename, sha256, bytes: size }] = installers;
await copyFile('src-tauri/Cargo.lock', join('artifacts', 'Cargo.lock'));
// Signed update bundles (only when the build had an updater signing key).
for (const file of await walkAll('src-tauri/target')) {
  if (/[\\/]bundle[\\/]/u.test(file) && (file.endsWith('.sig') || file.endsWith('.app.tar.gz'))) {
    await copyFile(file, join('artifacts', file.split(/[\\/]/u).pop()));
  }
}
await writeFile(join('artifacts', 'release.json'), JSON.stringify({ version, platform, filename, sha256, bytes: size, installers, commit: process.env.GITHUB_SHA, run: process.env.GITHUB_RUN_ID, signing: platform === 'macos-universal' ? 'ad-hoc, not notarized' : 'unsigned' }, null, 2) + '\n');
