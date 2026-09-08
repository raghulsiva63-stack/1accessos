import { readdir, readFile, mkdir, copyFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
const platform = process.argv[2];
const extension = { 'windows-x64': '.exe', 'macos-universal': '.dmg', 'linux-x64': '.deb' }[platform];
if (!extension) throw new Error('Unknown release platform');
const version = JSON.parse(await readFile('src-tauri/tauri.conf.json', 'utf8')).version;
async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (path.includes(`${process.platform === 'win32' ? '\\' : '/'}bundle${process.platform === 'win32' ? '\\' : '/'}`) && path.endsWith(extension)) files.push(path);
  }
  return files;
}
const files = await walk('src-tauri/target');
if (files.length !== 1) throw new Error(`Expected one installer, found ${files.length}`);
const filename = `passkey-x-desktop-${version}-${platform}${extension}`;
await mkdir('artifacts', { recursive: true });
await copyFile(files[0], join('artifacts', filename));
const bytes = await readFile(files[0]);
const sha256 = createHash('sha256').update(bytes).digest('hex');
await writeFile(join('artifacts', filename + '.sha256'), `${sha256}  ${filename}\n`);
await copyFile('src-tauri/Cargo.lock', join('artifacts', 'Cargo.lock'));
await writeFile(join('artifacts', 'release.json'), JSON.stringify({ version, platform, filename, sha256, bytes: bytes.length, commit: process.env.GITHUB_SHA, run: process.env.GITHUB_RUN_ID, signing: platform === 'macos-universal' ? 'ad-hoc, not notarized' : 'unsigned' }, null, 2) + '\n');
