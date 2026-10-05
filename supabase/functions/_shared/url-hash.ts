// URL canonicalization and hash prefixes for threat lists (the Safe Browsing / Web Risk scheme).
//
// A page address is turned into up to 30 "expressions" (host suffixes × path prefixes). Each
// expression is hashed with SHA-256; threat lists hold those hashes. Devices keep only 4-byte
// prefixes locally and ask the server about a prefix only when it matches, so the visited
// address never leaves the device.
//
// Dependency-free: the same file is copied to supabase/functions/_shared/url-hash.ts (a test keeps
// the copies identical) so that the server hashes feed entries exactly like the devices do.

const encoder = new TextEncoder();

function unescapeRepeatedly(value: string): string {
  let current = value;
  for (let round = 0; round < 8; round += 1) {
    let next: string;
    try { next = current.replace(/%([0-9a-fA-F]{2})/gu, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16))); }
    catch { return current; }
    if (next === current) return current;
    current = next;
  }
  return current;
}

/**
 * Percent-escapes control characters, spaces, '#', '%' and bytes ≥ 0x7f. The input is a "byte
 * string" (one character per byte): WHATWG URL parts are ASCII, and unescaping yields bytes.
 */
function escapeSpecial(value: string): string {
  let out = "";
  for (let index = 0; index < value.length; index += 1) {
    const byte = value.charCodeAt(index) & 0xff;
    out += byte <= 32 || byte >= 127 || byte === 35 || byte === 37 ? `%${byte.toString(16).toUpperCase().padStart(2, "0")}` : String.fromCharCode(byte);
  }
  return out;
}

/**
 * Canonical "host/path?query" for an http(s) address, or null. Lower-case host without
 * surrounding or repeated dots, no fragment, no user info or port, resolved "." and ".."
 * segments, single slashes, and consistent escaping.
 */
export function canonicalExpression(input: string): { host: string; path: string; query: string } | null {
  const cleaned = input.replace(/[\t\r\n]/gu, "").trim();
  if (!cleaned) return null;
  let url: URL;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:/iu.test(cleaned) ? cleaned : `http://${cleaned}`); } catch { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  let host = unescapeRepeatedly(url.hostname).toLowerCase().replace(/^\.+|\.+$/gu, "").replace(/\.{2,}/gu, ".");
  if (!host || host.length > 253) return null;
  host = escapeSpecial(host);
  let path = unescapeRepeatedly(url.pathname || "/");
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "..") segments.pop();
    else if (segment !== ".") segments.push(segment);
  }
  path = segments.join("/").replace(/\/{2,}/gu, "/");
  if (!path.startsWith("/")) path = `/${path}`;
  if ((url.pathname.endsWith("/") || /\/\.\.?$/u.test(url.pathname)) && !path.endsWith("/")) path += "/";
  path = escapeSpecial(path);
  const query = url.search ? escapeSpecial(unescapeRepeatedly(url.search.slice(1))) : "";
  return { host, path, query: url.search ? `?${query}` : "" };
}

function isIpAddress(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/u.test(host) || host.startsWith("[");
}

/** The host/path combinations that are looked up for an address (at most 5 hosts × 6 paths). */
export function urlExpressions(input: string): string[] {
  const canonical = canonicalExpression(input);
  if (!canonical) return [];
  const { host, path, query } = canonical;
  const hosts = [host];
  if (!isIpAddress(host)) {
    const labels = host.split(".");
    // Up to four more: start from the last five labels and drop leading labels; never the TLD alone.
    const start = Math.max(1, labels.length - 5);
    for (let index = start; index < labels.length - 1 && hosts.length < 5; index += 1) {
      const suffix = labels.slice(index).join(".");
      if (!hosts.includes(suffix)) hosts.push(suffix);
    }
  }
  const paths: string[] = [];
  const add = (value: string) => { if (!paths.includes(value)) paths.push(value); };
  if (query) add(path + query);
  add(path);
  add("/");
  const parts = path.split("/").filter(Boolean);
  let prefix = "/";
  for (let index = 0; index < parts.length - (path.endsWith("/") ? 0 : 1) && paths.length < 6; index += 1) {
    prefix += `${parts[index]}/`;
    add(prefix);
  }
  const expressions: string[] = [];
  for (const h of hosts) for (const p of paths.slice(0, 6)) expressions.push(`${h}${p}`);
  return expressions;
}

/** Expression for a whole domain (an organization's block list entry): "example.com/". */
export function domainExpression(domain: string): string | null {
  const canonical = canonicalExpression(domain.replace(/^\*\./u, ""));
  return canonical ? `${canonical.host}/` : null;
}

export async function sha256Bytes(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export function prefixOf(hash: Uint8Array): number {
  return ((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]) >>> 0;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

export function prefixBytes(prefix: number): Uint8Array {
  return Uint8Array.of(prefix >>> 24, (prefix >>> 16) & 255, (prefix >>> 8) & 255, prefix & 255);
}

/** All expressions of an address with their full hashes. */
export async function hashedExpressions(input: string): Promise<{ expression: string; hash: Uint8Array; prefix: number }[]> {
  const result = [];
  for (const expression of urlExpressions(input)) {
    const hash = await sha256Bytes(expression);
    result.push({ expression, hash, prefix: prefixOf(hash) });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Prefix sets: "PXTI" | u32 version | u32 count | count × u32 (sorted, big-endian)
// ---------------------------------------------------------------------------

const MAGIC = 0x50585449; // "PXTI"

export function encodePrefixSet(prefixes: Iterable<number>, version: number): Uint8Array {
  const sorted = Uint32Array.from(new Set(prefixes)).sort();
  const bytes = new Uint8Array(12 + sorted.length * 4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, MAGIC);
  view.setUint32(4, version >>> 0);
  view.setUint32(8, sorted.length);
  sorted.forEach((prefix, index) => view.setUint32(12 + index * 4, prefix));
  return bytes;
}

export class PrefixSet {
  readonly version: number;
  private readonly values: Uint32Array;

  constructor(values: Uint32Array, version: number) {
    this.values = values;
    this.version = version;
  }

  static decode(bytes: Uint8Array): PrefixSet {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.byteLength < 12 || view.getUint32(0) !== MAGIC) throw new Error("invalid prefix set");
    const count = view.getUint32(8);
    if (bytes.byteLength !== 12 + count * 4) throw new Error("invalid prefix set");
    const values = new Uint32Array(count);
    let previous = -1;
    for (let index = 0; index < count; index += 1) {
      const value = view.getUint32(12 + index * 4);
      if (value <= previous) throw new Error("invalid prefix set");
      values[index] = value;
      previous = value;
    }
    return new PrefixSet(values, view.getUint32(4));
  }

  static empty(): PrefixSet { return new PrefixSet(new Uint32Array(0), 0); }

  get size(): number { return this.values.length; }

  /** The prefixes, sorted. */
  toArray(): number[] { return Array.from(this.values); }

  has(prefix: number): boolean {
    let low = 0; let high = this.values.length - 1;
    while (low <= high) {
      const middle = (low + high) >>> 1;
      const value = this.values[middle];
      if (value === prefix) return true;
      if (value < prefix) low = middle + 1; else high = middle - 1;
    }
    return false;
  }
}
