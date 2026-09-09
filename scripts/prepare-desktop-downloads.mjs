import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('../', import.meta.url);
const { version } = JSON.parse(await readFile(new URL('apps/desktop/src-tauri/tauri.conf.json', root), 'utf8'));
if (!/^\d+\.\d+\.\d+$/u.test(version)) throw new Error('Invalid desktop version');
const source = new URL(`releases/desktop/${version}/`, root);
const manifest = JSON.parse(await readFile(new URL('manifest.json', source), 'utf8'));
const formats = { 'windows-x64': 'exe', 'macos-universal': 'dmg', 'linux-x64': 'deb' };
if (manifest.version !== version || manifest.platforms?.length !== 3) throw new Error('Incomplete desktop release');
const seen = new Set();
for (const release of manifest.platforms) {
  const format = formats[release.platform];
  if (!format || seen.has(release.platform)) throw new Error('Unexpected desktop platform');
  seen.add(release.platform);
  const filename = `passkey-x-desktop-${version}-${release.platform}.${format}`;
  if (release.filename !== filename || release.commit !== manifest.commit || release.run !== manifest.run || release.version !== version) throw new Error('Desktop provenance differs');
  if (!Array.isArray(release.parts) || !release.parts.length || release.parts.length > 100) throw new Error('Invalid desktop asset parts');
  const chunks = [];
  for (const [index, path] of release.parts.entries()) {
    if (path !== `${release.platform}/part-${String(index).padStart(3, '0')}.bin`) throw new Error('Invalid desktop asset path');
    const chunk = await readFile(new URL(path, source));
    if (chunk.length < 1 || chunk.length > 524288) throw new Error('Invalid desktop asset size');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (bytes.length !== release.bytes || digest !== release.sha256) throw new Error(`Desktop installer integrity check failed: ${release.platform}`);
  const destination = new URL(`apps/web/public/downloads/desktop/${version}/`, root);
  await mkdir(destination, { recursive: true });
  await writeFile(new URL(filename, destination), bytes);
  await writeFile(new URL(filename + '.sha256', destination), `${digest}  ${filename}\n`);
}
const publicManifest = { ...manifest, platforms: manifest.platforms.map(({ parts, ...release }) => release) };
const publicDirectory = new URL('apps/web/public/releases/', root);
await mkdir(publicDirectory, { recursive: true });
await writeFile(new URL(`desktop-${version}.json`, publicDirectory), JSON.stringify(publicManifest, null, 2) + '\n');
console.log('Prepared three desktop installers with verified checksums.');
