import { readFile, mkdir, writeFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { crc32 } from 'node:zlib';

const manifest = JSON.parse(await readFile(new URL('../dist/manifest.json', import.meta.url), 'utf8'));
const worker = await readFile(new URL('../dist/background.js', import.meta.url), 'utf8');
if (!worker.includes('https://wkkmyacbhqloubtwvjom.supabase.co') || /test_placeholder|sb_secret_[A-Za-z0-9_-]{20,}|BEGIN (?:RSA )?PRIVATE KEY/u.test(worker)) {
  throw new Error('Refusing to package missing production configuration or private key material.');
}
const identity = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32)
  .replace(/[0-9a-f]/g, character => String.fromCharCode(97 + parseInt(character, 16)));
if (identity !== 'egkaneajfcaomheahcmopioiemmplebg') throw new Error('Packaged extension ID does not match the production web allowlist.');
await mkdir(new URL('../artifacts/', import.meta.url), { recursive: true });
const name = `passkey-x-extension-${manifest.version}-uat.zip`;
const archive = new URL(`../artifacts/${name}`, import.meta.url);
// A deterministic, portable ZIP writer: only regular files in Vite's output
// are included. Stored entries need no external zip utility on Windows.
const entries = [];
async function collect(directory, prefix = '') {
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = prefix + entry.name;
    if (entry.isSymbolicLink()) throw new Error('Symlinks are not allowed in extension packages.');
    if (entry.isDirectory()) await collect(new URL(entry.name + '/', directory), name + '/');
    else if (entry.isFile()) {
      const body = await readFile(new URL(entry.name, directory));
      if (/\.(?:js|json|html|css)$/u.test(name) && /test_placeholder|sb_secret_[A-Za-z0-9_-]{20,}|BEGIN (?:RSA )?PRIVATE KEY/u.test(body.toString('utf8'))) throw new Error('Refusing nonproduction or secret material in ' + name);
      entries.push({ name, body });
    }
  }
}
await collect(new URL('../dist/', import.meta.url));
let offset = 0;
const chunks = [], central = [];
for (const { name, body } of entries) {
  const filename = Buffer.from(name);
  const crc = crc32(body);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x800, 6);
  local.writeUInt16LE(33, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(body.length, 22); local.writeUInt16LE(filename.length, 26);
  chunks.push(local, filename, body);
  const header = Buffer.alloc(46);
  header.writeUInt32LE(0x02014b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(20, 6); header.writeUInt16LE(0x800, 8);
  header.writeUInt16LE(33, 14); header.writeUInt32LE(crc, 16); header.writeUInt32LE(body.length, 20); header.writeUInt32LE(body.length, 24); header.writeUInt16LE(filename.length, 28); header.writeUInt32LE(offset, 42);
  central.push(header, filename); offset += local.length + filename.length + body.length;
}
const directory = Buffer.concat(central), end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
await writeFile(archive, Buffer.concat([...chunks, directory, end]));
const digest = createHash('sha256').update(await readFile(archive)).digest('hex');
await writeFile(new URL(`../artifacts/${name}.sha256`, import.meta.url), `${digest}  ${name}\n`);
console.log(`UAT package: artifacts/${name}\nExtension ID: ${identity}\nSHA-256: ${digest}`);
