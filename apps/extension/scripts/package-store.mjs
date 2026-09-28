import { readFile } from 'node:fs/promises';
import { assertProductionBuild, writeZip } from './zip.mjs';

// Package for the Chrome Web Store and Microsoft Edge Add-ons. The stores reject a manifest "key"
// and assign the extension ID themselves; add that ID to NEXT_PUBLIC_EXTENSION_IDS on Netlify so
// the web pairing page accepts it.
const dist = new URL('../dist/', import.meta.url);
await assertProductionBuild(dist);
const manifest = JSON.parse(await readFile(new URL('manifest.json', dist), 'utf8'));
if ('key' in manifest) throw new Error('Store packages must not contain a manifest key.');
if (manifest.content_scripts.some(script => script.matches.includes('http://*/*'))) throw new Error('Store packages must not run on plain-HTTP sites.');
for (const size of Object.keys(manifest.icons)) await readFile(new URL(manifest.icons[size], dist));
const name = `passkey-x-extension-${manifest.version}-store.zip`;
const digest = await writeZip(dist, name);
console.log(`Store package: artifacts/${name}\nSHA-256: ${digest}\nUpload it to the Chrome Web Store and Edge Add-ons dashboards.`);
