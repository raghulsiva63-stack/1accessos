import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('../', import.meta.url);
const { android: version } = JSON.parse(await readFile(new URL('apps/web/lib/client-releases.json', root), 'utf8'));
if (version !== null) {
if (!/^\d+\.\d+\.\d+$/u.test(version)) throw new Error('Invalid Android release version');
const source = new URL(`releases/android/${version}/`, root);
const manifest = JSON.parse(await readFile(new URL('manifest.json', source), 'utf8'));
const filename = `passkey-x-android-${version}-preview.apk`;
if (manifest.version !== version || manifest.platform !== 'android' || manifest.filename !== filename || !/^[a-f0-9]{40}$/u.test(manifest.commit) || !/^\d+$/u.test(String(manifest.run))) throw new Error('Invalid Android release metadata');
if (!Array.isArray(manifest.parts) || !manifest.parts.length || manifest.parts.length > 100) throw new Error('Invalid Android parts');
const chunks = [];
for (const [index, path] of manifest.parts.entries()) {
  if (path !== `part-${String(index).padStart(3, '0')}.bin`) throw new Error('Invalid Android part path');
  const chunk = await readFile(new URL(path, source));
  if (!chunk.length || chunk.length > 524288) throw new Error('Invalid Android part size');
  chunks.push(chunk);
}
const bytes = Buffer.concat(chunks);
const digest = createHash('sha256').update(bytes).digest('hex');
if (bytes.length !== manifest.bytes || digest !== manifest.sha256 || bytes.readUInt32LE(0) !== 0x04034b50) throw new Error('Android installer integrity check failed');
const destination = new URL(`apps/web/public/downloads/android/${version}/`, root);
await mkdir(destination, { recursive: true });
await writeFile(new URL(filename, destination), bytes);
await writeFile(new URL(filename + '.sha256', destination), `${digest}  ${filename}\n`);
const { parts, ...publicManifest } = manifest;
const releases = new URL('apps/web/public/releases/', root);
await mkdir(releases, { recursive: true });
await writeFile(new URL(`android-${version}.json`, releases), JSON.stringify(publicManifest, null, 2) + '\n');
console.log('Prepared the verified Android installer.');

}
