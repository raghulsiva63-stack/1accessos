import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import './prepare-desktop-downloads.mjs';
import './prepare-android-downloads.mjs';

const root = new URL('../', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('apps/extension/public/manifest.json', root), 'utf8'));
const name = `passkey-x-extension-${manifest.version}-uat.zip`;
const archive = new URL(`apps/extension/artifacts/${name}`, root);
const checksum = new URL(`apps/extension/artifacts/${name}.sha256`, root);
const actual = createHash('sha256').update(await readFile(archive)).digest('hex');
if (!(await readFile(checksum, 'utf8')).startsWith(actual + '  ')) throw new Error('Extension archive checksum mismatch. Rebuild it before publishing.');
const destination = new URL('apps/web/public/downloads/', root);
await mkdir(destination, { recursive: true });
await copyFile(archive, new URL(name, destination));
await copyFile(checksum, new URL(name + '.sha256', destination));
console.log('Prepared the verified extension download for the web release.');
