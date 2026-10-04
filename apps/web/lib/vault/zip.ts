// Minimal, defensive ZIP reader for import files (e.g. 1Password .1pux).
// Reads only the central directory and the single entry asked for, so large archives with
// attachments are never loaded into memory as a whole. Supports stored (0) and deflate (8)
// entries; rejects encrypted entries, ZIP64 and multi-disk archives, and anything that would
// decompress beyond the size limit. Never logs contents.

export const MAX_ZIP_ENTRY_BYTES = 50 * 1024 * 1024;
const MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 100_000;

export type ZipSource = { size: number; read(offset: number, length: number): Promise<Uint8Array> };

export type ZipEntryInfo = {
  name: string;
  flags: number;
  method: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
};

export function zipSourceFromBytes(bytes: Uint8Array): ZipSource {
  return {
    size: bytes.length,
    read: async (offset, length) => bytes.subarray(offset, Math.min(bytes.length, offset + length)),
  };
}

export function zipSourceFromBlob(blob: Blob): ZipSource {
  return {
    size: blob.size,
    read: async (offset, length) => new Uint8Array(await blob.slice(offset, Math.min(blob.size, offset + length)).arrayBuffer()),
  };
}

const u16 = (data: Uint8Array, at: number) => data[at] | (data[at + 1] << 8);
const u32 = (data: Uint8Array, at: number) => (data[at] | (data[at + 1] << 8) | (data[at + 2] << 16) | (data[at + 3] << 24)) >>> 0;

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

/** True when the source starts with a local-file-header signature ("PK\x03\x04"). */
export async function isZip(source: ZipSource): Promise<boolean> {
  if (source.size < 4) return false;
  const head = await source.read(0, 4);
  return head.length === 4 && u32(head, 0) === SIG_LOCAL;
}

const invalid = () => new Error("This archive is damaged or is not a ZIP file.");

export async function listZipEntries(source: ZipSource): Promise<ZipEntryInfo[]> {
  if (source.size < 22) throw invalid();
  const tailLength = Math.min(source.size, 22 + 0xffff);
  const tailStart = source.size - tailLength;
  const tail = await source.read(tailStart, tailLength);
  let eocd = -1;
  for (let at = tail.length - 22; at >= 0; at -= 1) {
    if (u32(tail, at) === SIG_EOCD && at + 22 + u16(tail, at + 20) <= tail.length) { eocd = at; break; }
  }
  if (eocd < 0) throw invalid();
  if (eocd >= 20 && u32(tail, eocd - 20) === SIG_ZIP64_LOCATOR) throw new Error("ZIP64 archives are not supported. Export again without attachments.");
  const disk = u16(tail, eocd + 4);
  const cdDisk = u16(tail, eocd + 6);
  const entriesOnDisk = u16(tail, eocd + 8);
  const totalEntries = u16(tail, eocd + 10);
  const cdSize = u32(tail, eocd + 12);
  const cdOffset = u32(tail, eocd + 16);
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new Error("ZIP64 archives are not supported. Export again without attachments.");
  if (disk !== 0 || cdDisk !== 0 || entriesOnDisk !== totalEntries) throw new Error("Split ZIP archives are not supported.");
  if (cdSize > MAX_CENTRAL_DIRECTORY_BYTES || totalEntries > MAX_ZIP_ENTRIES) throw invalid();
  if (cdOffset + cdSize > tailStart + eocd) throw invalid();
  const cd = await source.read(cdOffset, cdSize);
  if (cd.length !== cdSize) throw invalid();
  const entries: ZipEntryInfo[] = [];
  const utf8 = new TextDecoder("utf-8");
  let at = 0;
  for (let index = 0; index < totalEntries; index += 1) {
    if (at + 46 > cd.length || u32(cd, at) !== SIG_CENTRAL) throw invalid();
    const nameLength = u16(cd, at + 28);
    const extraLength = u16(cd, at + 30);
    const commentLength = u16(cd, at + 32);
    if (at + 46 + nameLength + extraLength + commentLength > cd.length) throw invalid();
    entries.push({
      flags: u16(cd, at + 8),
      method: u16(cd, at + 10),
      crc32: u32(cd, at + 16),
      compressedSize: u32(cd, at + 20),
      uncompressedSize: u32(cd, at + 24),
      localHeaderOffset: u32(cd, at + 42),
      name: utf8.decode(cd.subarray(at + 46, at + 46 + nameLength)),
    });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

let crcTable: Uint32Array | null = null;
export function crc32(data: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let index = 0; index < data.length; index += 1) crc = crcTable[(crc ^ data[index]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

async function inflateRaw(data: Uint8Array, limit: number): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") throw new Error("This browser cannot open compressed exports. Update your browser and try again.");
  const input = new Uint8Array(data.length);
  input.set(data);
  const reader = new Blob([input]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => undefined);
        throw new Error("The export inside this archive is larger than expected and was not opened.");
      }
      chunks.push(value);
    }
  } catch (reason) {
    if (reason instanceof Error && reason.message.startsWith("The export inside")) throw reason;
    throw invalid();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

/**
 * Extract one entry by exact name. Returns null when the archive has no such entry.
 * Rejects encrypted entries, ZIP64 sizes, unsupported methods and entries above `maxBytes`.
 */
export async function readZipEntry(source: ZipSource, name: string, maxBytes = MAX_ZIP_ENTRY_BYTES, entries?: ZipEntryInfo[]): Promise<Uint8Array | null> {
  const list = entries ?? await listZipEntries(source);
  const entry = list.find((candidate) => candidate.name === name);
  if (!entry) return null;
  if (entry.flags & 0x1 || entry.method === 99) throw new Error("This archive is encrypted. Export again without a password.");
  if (entry.compressedSize === 0xffffffff || entry.uncompressedSize === 0xffffffff || entry.localHeaderOffset === 0xffffffff) throw new Error("ZIP64 archives are not supported. Export again without attachments.");
  if (entry.uncompressedSize > maxBytes) throw new Error("The export inside this archive is too large to import here.");
  if (entry.method !== 0 && entry.method !== 8) throw new Error("This archive uses an unsupported compression method.");
  const header = await source.read(entry.localHeaderOffset, 30);
  if (header.length !== 30 || u32(header, 0) !== SIG_LOCAL) throw invalid();
  if (u16(header, 6) & 0x1) throw new Error("This archive is encrypted. Export again without a password.");
  const dataStart = entry.localHeaderOffset + 30 + u16(header, 26) + u16(header, 28);
  if (dataStart + entry.compressedSize > source.size) throw invalid();
  const compressed = await source.read(dataStart, entry.compressedSize);
  if (compressed.length !== entry.compressedSize) throw invalid();
  let output: Uint8Array;
  if (entry.method === 0) {
    if (entry.compressedSize !== entry.uncompressedSize) throw invalid();
    output = compressed;
  } else {
    output = await inflateRaw(compressed, Math.min(maxBytes, entry.uncompressedSize));
    if (output.length !== entry.uncompressedSize) throw invalid();
  }
  if (crc32(output) !== entry.crc32) throw invalid();
  return output;
}
