import { readFile } from 'node:fs/promises';
import { assertProductionBuild, extensionIdFromKey, writeZip } from './zip.mjs';

// UAT builds are loaded unpacked, so they carry this public key to keep a stable extension ID
// that the web pairing page allowlists. Store builds must NOT contain a key (see package-store.mjs):
// the Chrome Web Store and Edge Add-ons assign their own IDs.
const UAT_PUBLIC_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunqxf4i7u7acU6GhD62Vby2N1sOvLU+ulpM0Kt9fTY3NNlUglwDdpKC7bUrHRoOmGKmV7ffEo42omwH7rTl6NuD/9Nx5X+OxU+QN7iKlHqRjcI5u1Eav4tLZ8Stv+chBvIpNkZnwLpi55yYkCHcWU1T4FFJWzIu3hKvoc4q2NXjguuS7H5F2R4BDck1/kxgsRe7tvpwgWqljsMcm5wkHJadP8S6cPAqKdRKSEs7OonHIHftwmAKEwdadFDVEsonciyz72JUW5UrlajffrSfNxiOKyfulh4nxtjhZs7HB1AfpdGdEtlrgiMl6YW/o6yFUrFhJG6W2hAKn9tNKLrLyWwIDAQAB';
export const UAT_EXTENSION_ID = 'egkaneajfcaomheahcmopioiemmplebg';

const dist = new URL('../dist/', import.meta.url);
await assertProductionBuild(dist);
const manifest = JSON.parse(await readFile(new URL('manifest.json', dist), 'utf8'));
const identity = extensionIdFromKey(UAT_PUBLIC_KEY);
if (identity !== UAT_EXTENSION_ID) throw new Error('UAT extension ID does not match the production web allowlist.');
const name = `passkey-x-extension-${manifest.version}-uat.zip`;
const digest = await writeZip(dist, name, { 'manifest.json': JSON.stringify({ key: UAT_PUBLIC_KEY, ...manifest }, null, 2) + '\n' });
console.log(`UAT package: artifacts/${name}\nExtension ID: ${identity}\nSHA-256: ${digest}`);
