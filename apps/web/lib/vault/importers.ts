import type { ItemKind, VaultPayload } from "@/lib/vault/items";
import { isZip, listZipEntries, MAX_ZIP_ENTRY_BYTES, readZipEntry, zipSourceFromBlob } from "@/lib/vault/zip";

export type ImportFormat =
  | "1password"
  | "1password-1pux"
  | "bitwarden-csv"
  | "bitwarden-json"
  | "lastpass"
  | "dashlane"
  | "keeper-csv"
  | "keeper-json"
  | "keepass-xml"
  | "keepassxc-csv"
  | "apple-csv"
  | "chrome"
  | "firefox"
  | "generic";

export type ImportedEntry = {
  kind: ItemKind;
  payload: Omit<VaultPayload, "version" | "updatedAt">;
  /** Source folder / shared folder / collection path, " / " separated, at most 120 characters. */
  collection?: string;
  /** True when the source marks the folder or collection as shared with other people. */
  shared?: boolean;
};

export type ImportCollection = { name: string; count: number; shared: boolean };

export type ImportResult = {
  format: ImportFormat;
  entries: ImportedEntry[];
  skipped: number;
  /** Folders and collections found in the file, sorted by name. */
  collections: ImportCollection[];
  /** Notes about what was not imported. Never contains item contents. */
  warnings: string[];
};

/** A file picked by the user, or any Blob with a name (tests, drag and drop). */
export type ImportFile = Blob & { name: string };

/** Minimal shape of an item already in the vault, for duplicate detection. */
export type ExistingImportItem = { kind: ItemKind; payload: Pick<VaultPayload, "title"> & Partial<Pick<VaultPayload, "username" | "secret" | "url" | "notes">> };

export const FORMAT_LABELS: Record<ImportFormat, string> = {
  "1password": "1Password (CSV)",
  "1password-1pux": "1Password (1PUX)",
  "bitwarden-csv": "Bitwarden (CSV)",
  "bitwarden-json": "Bitwarden (JSON)",
  lastpass: "LastPass (CSV)",
  dashlane: "Dashlane (CSV)",
  "keeper-csv": "Keeper (CSV)",
  "keeper-json": "Keeper (JSON)",
  "keepass-xml": "KeePass (XML)",
  "keepassxc-csv": "KeePassXC (CSV)",
  "apple-csv": "Apple Passwords / Safari (CSV)",
  chrome: "Chrome / Edge / Brave (CSV)",
  firefox: "Firefox (CSV)",
  generic: "Generic CSV",
};

export const MAX_IMPORT_BYTES = 10 * 1024 * 1024;
export const MAX_IMPORT_ITEMS = 5000;
export const MAX_COLLECTION_LENGTH = 120;

/** RFC 4180 CSV parser: quoted fields, escaped quotes, commas and newlines inside quotes. */
export function parseCsv(text: string): string[][] {
  const input = text.replace(/^﻿/u, "");
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === "\"") {
        if (input[index + 1] === "\"") { field += "\""; index += 1; } else quoted = false;
      } else field += char;
      continue;
    }
    if (char === "\"" && field === "") quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n" || char === "\r") {
      if (char === "\r" && input[index + 1] === "\n") index += 1;
      row.push(field); field = "";
      if (row.some((cell) => cell !== "")) rows.push(row);
      row = [];
    } else field += char;
  }
  row.push(field);
  if (row.some((cell) => cell !== "")) rows.push(row);
  return rows;
}

const clean = (value: unknown) => {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return trimmed ? trimmed : undefined;
};

function hostTitle(url: string | undefined) {
  if (!url) return undefined;
  try { return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./u, ""); } catch { return undefined; }
}

function totpFields(value: string | undefined): Record<string, string> | undefined {
  const secret = clean(value);
  return secret ? { TOTP: secret } : undefined;
}

/**
 * Normalize a folder path to "A / B / C". A string is split on "/" and "\"; an array is
 * treated as already-split segments. Returns undefined for empty paths.
 */
export function normalizeCollection(path: string | string[] | undefined | null): string | undefined {
  if (!path) return undefined;
  const segments = (Array.isArray(path) ? path : path.split(/[\\/]/u)).map((segment) => segment.replace(/\s+/gu, " ").trim()).filter(Boolean);
  if (!segments.length) return undefined;
  const joined = segments.join(" / ");
  return joined.length > MAX_COLLECTION_LENGTH ? joined.slice(0, MAX_COLLECTION_LENGTH).trimEnd() : joined;
}

/** Tags derived from a normalized collection path (one tag per segment). */
export function collectionTags(collection: string | undefined): string[] {
  return collection ? collection.split(" / ").map((segment) => segment.trim()).filter(Boolean) : [];
}

function mergeTags(...groups: (string[] | undefined)[]): string[] | undefined {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const group of groups) for (const tag of group ?? []) {
    const value = tag.trim();
    if (value && !seen.has(value.toLowerCase())) { seen.add(value.toLowerCase()); tags.push(value); }
  }
  return tags.length ? tags : undefined;
}

function entry(kind: ItemKind, payload: ImportedEntry["payload"], collection?: string, shared?: boolean): ImportedEntry {
  const result: ImportedEntry = { kind, payload };
  if (collection) result.collection = collection;
  if (shared) result.shared = true;
  return result;
}

function addField(fields: Record<string, string>, label: string, value: string | undefined) {
  const text = clean(value);
  if (!text) return;
  const base = clean(label) ?? "Field";
  let key = base;
  for (let suffix = 2; key in fields; suffix += 1) key = `${base} (${suffix})`;
  fields[key] = text;
}

const nonEmpty = (fields: Record<string, string>) => (Object.keys(fields).length ? fields : undefined);
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const str = (value: unknown) => (typeof value === "string" ? value : typeof value === "number" ? String(value) : undefined);

export function detectCsvFormat(headers: string[]): ImportFormat {
  const has = (...names: string[]) => names.every((name) => headers.includes(name));
  if (has("login_uri", "login_username", "login_password")) return "bitwarden-csv";
  if (has("url", "username", "password", "extra", "grouping")) return "lastpass";
  if (has("group", "title", "username", "password", "url", "notes")) return "keepassxc-csv";
  if (has("title", "url", "username", "password", "notes", "otpauth") && !headers.some((name) => ["archived", "favorite", "tags"].includes(name))) return "apple-csv";
  if (has("title", "url", "username", "password") && (headers.includes("otpauth") || headers.includes("archived"))) return "1password";
  if (has("username", "title", "password", "note", "url") && headers.includes("category")) return "dashlane";
  if (has("url", "username", "password", "httprealm")) return "firefox";
  if (has("name", "url", "username", "password")) return "chrome";
  return "generic";
}

function emptyResult(format: ImportFormat): ImportResult {
  return { format, entries: [], skipped: 0, collections: [], warnings: [] };
}

function fromCsv(text: string): ImportResult {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error("The file does not contain any records.");
  const headers = rows[0].map((value) => value.trim().toLowerCase());
  const format = detectCsvFormat(headers);
  const column = (...names: string[]) => names.map((name) => headers.indexOf(name)).find((index) => index >= 0) ?? -1;
  const get = (cells: string[], ...names: string[]) => { const index = column(...names); return index >= 0 ? cells[index] : undefined; };
  if (column("password", "login_password", "secret") < 0 && column("username", "login_username", "email") < 0 && format === "generic") {
    throw new Error("This CSV needs at least a username or password column. If this is a Keeper CSV export, choose Keeper as the source.");
  }
  const result = emptyResult(format);
  let recycled = 0;
  for (const cells of rows.slice(1)) {
    const url = clean(get(cells, "url", "login_uri", "website"));
    const username = clean(get(cells, "username", "login_username", "email"));
    const secret = clean(get(cells, "password", "login_password", "secret"));
    const notes = clean(get(cells, "notes", "note", "extra"));
    const totp = get(cells, "otpauth", "totp", "login_totp", "otpsecret");
    const folder = clean(get(cells, "grouping", "folder", "tags", "category"));
    const title = clean(get(cells, "name", "title", "service")) ?? hostTitle(url);
    const favorite = ["1", "true", "yes"].includes((get(cells, "fav", "favorite") ?? "").trim().toLowerCase());
    const bitwardenType = (get(cells, "type") ?? "").trim().toLowerCase();
    const isNote = (format === "lastpass" && url === "http://sn") || (format === "bitwarden-csv" && bitwardenType === "note");
    if (!title && !username && !secret && !notes) { result.skipped += 1; continue; }

    let collection: string | undefined;
    let shared = false;
    if (format === "keepassxc-csv") {
      const segments = (get(cells, "group") ?? "").split("/").map((segment) => segment.trim()).filter(Boolean).slice(1);
      if (segments[0] === "Recycle Bin") { result.skipped += 1; recycled += 1; continue; }
      collection = normalizeCollection(segments);
    } else if (format === "bitwarden-csv" && clean(get(cells, "collections"))) {
      collection = normalizeCollection(clean(get(cells, "collections"))!.split(",")[0]);
      shared = true;
    } else {
      const grouping = clean(get(cells, "grouping", "folder", "category", "group"));
      collection = normalizeCollection(grouping);
      shared = format === "lastpass" && /^shared-/iu.test(grouping ?? "");
    }

    const legacyTags = folder ? folder.split(/[,/\\]/u).map((tag) => tag.trim()).filter(Boolean) : undefined;
    const tags = legacyTags ?? mergeTags(collectionTags(collection));
    if (isNote) {
      result.entries.push(entry("secure-note", { title: title ?? "Imported note", notes, tags, favorite }, collection, shared));
    } else {
      result.entries.push(entry("login", { title: title ?? username ?? "Imported login", username, secret, url, notes, tags, favorite, fields: totpFields(totp) }, collection, shared));
    }
  }
  if (recycled) result.warnings.push(`${plural(recycled, "item")} in the Recycle Bin ${recycled === 1 ? "was" : "were"} not imported.`);
  return result;
}

// ---------------------------------------------------------------- Keeper CSV (no header row)

function fromKeeperCsv(text: string): ImportResult {
  const rows = parseCsv(text);
  const result = emptyResult("keeper-csv");
  for (const [index, cells] of rows.entries()) {
    if (index === 0 && (cells[0] ?? "").trim().toLowerCase() === "folder" && (cells[1] ?? "").trim().toLowerCase() === "title") continue;
    const [folderCell, titleCell, loginCell, passwordCell, urlCell, notesCell, sharedCell] = cells;
    const url = clean(urlCell);
    const username = clean(loginCell);
    const secret = clean(passwordCell);
    const notes = clean(notesCell);
    const title = clean(titleCell) ?? hostTitle(url);
    if (!title && !username && !secret && !notes) { result.skipped += 1; continue; }
    const sharedFolder = normalizeCollection(clean(sharedCell));
    const collection = sharedFolder ?? normalizeCollection(clean(folderCell));
    const fields: Record<string, string> = {};
    for (let at = 7; at + 1 < cells.length; at += 2) {
      const name = clean(cells[at]);
      const value = clean(cells[at + 1]);
      if (!name || !value) continue;
      if (name === "TFC:Keeper" || /^\$?onetimecode/iu.test(name)) { if (!fields.TOTP) fields.TOTP = value; } else addField(fields, name, value);
    }
    const kind: ItemKind = username || secret || url ? "login" : "secure-note";
    result.entries.push(entry(kind, { title: title ?? username ?? "Imported item", username, secret, url, notes, tags: mergeTags(collectionTags(collection)), fields: nonEmpty(fields) }, collection, Boolean(sharedFolder)));
  }
  return result;
}

// ---------------------------------------------------------------- Keeper JSON

function keeperValue(value: unknown, depth = 0): string | undefined {
  if (depth > 4) return undefined;
  if (typeof value === "string") return clean(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return clean(value.map((part) => keeperValue(part, depth + 1)).filter(Boolean).join(", "));
  if (isRecord(value)) return clean(Object.entries(value).map(([key, part]) => { const text = keeperValue(part, depth + 1); return text ? `${key}: ${text}` : ""; }).filter(Boolean).join("; "));
  return undefined;
}

function keeperLabel(key: string) {
  if (!key.startsWith("$")) return key;
  const withoutIndex = key.replace(/::\d+$/u, "");
  const colon = withoutIndex.indexOf(":");
  return colon >= 0 ? withoutIndex.slice(colon + 1) : withoutIndex.slice(1);
}

function fromKeeperJson(data: Record<string, unknown>): ImportResult {
  const result = emptyResult("keeper-json");
  const records = Array.isArray(data.records) ? data.records : [];
  for (const raw of records) {
    if (!isRecord(raw)) { result.skipped += 1; continue; }
    const type = str(raw.$type) ?? "login";
    const url = clean(str(raw.login_url));
    const username = clean(str(raw.login));
    let secret = clean(str(raw.password));
    const notes = clean(str(raw.notes));
    const title = clean(str(raw.title)) ?? hostTitle(url);
    const fields: Record<string, string> = {};
    let cardHolder: string | undefined;
    if (isRecord(raw.custom_fields)) {
      for (const [key, value] of Object.entries(raw.custom_fields)) {
        if (key === "TFC:Keeper" || key.startsWith("$oneTimeCode") || (typeof value === "string" && value.startsWith("otpauth://"))) {
          const code = keeperValue(value);
          if (code && !fields.TOTP) fields.TOTP = code;
          continue;
        }
        if (type === "bankCard" && key.startsWith("$paymentCard") && isRecord(value)) {
          secret = secret ?? clean(str(value.cardNumber));
          addField(fields, "Expiry", str(value.cardExpirationDate));
          addField(fields, "Security code", str(value.cardSecurityCode));
          continue;
        }
        if (type === "bankCard" && /^\$text:cardholder/iu.test(key)) { cardHolder = keeperValue(value); continue; }
        addField(fields, keeperLabel(key), keeperValue(value));
      }
    }
    if (!title && !username && !secret && !notes && !Object.keys(fields).length) { result.skipped += 1; continue; }
    let collection: string | undefined;
    let shared = false;
    const folders = Array.isArray(raw.folders) ? raw.folders.filter(isRecord) : [];
    const sharedFolder = folders.find((folder) => clean(str(folder.shared_folder)));
    const location = sharedFolder ?? folders.find((folder) => clean(str(folder.folder)));
    if (location) {
      const parts = [str(location.shared_folder), str(location.folder)].filter((part): part is string => Boolean(clean(part)));
      collection = normalizeCollection(parts.flatMap((part) => part.split(/[\\/]/u)));
      shared = Boolean(sharedFolder);
    }
    const kind: ItemKind = type === "encryptedNotes" ? "secure-note"
      : type === "bankCard" ? "payment-card"
        : ["address", "contact", "personInformation", "driverLicense", "passport", "ssnCard"].includes(type) ? "identity"
          : username || secret || url ? "login" : "secure-note";
    const tags = mergeTags(collectionTags(collection));
    result.entries.push(entry(kind, { title: title ?? username ?? "Imported item", username: kind === "payment-card" ? cardHolder ?? username : username, secret, url, notes, tags, fields: nonEmpty(fields) }, collection, shared));
  }
  return result;
}

// ---------------------------------------------------------------- 1Password 1PUX (export.data)

const PERSONAL_1P_VAULTS = new Set(["private", "personal", "employee"]);
const ONEPASSWORD_KINDS: Record<string, ItemKind> = {
  "001": "login", "002": "payment-card", "003": "secure-note", "004": "identity", "005": "login",
  "100": "software-license", "102": "database", "109": "wifi", "112": "api-key", "114": "ssh-key",
};

function onePuxValue(value: unknown): { type: string; text?: string } {
  if (!isRecord(value)) return { type: "" };
  const [type, raw] = Object.entries(value)[0] ?? ["", undefined];
  if (typeof raw === "string") return { type, text: clean(raw) };
  if (typeof raw === "number") {
    if (type === "monthYear") { const digits = String(raw); return { type, text: digits.length === 6 ? `${digits.slice(4)}/${digits.slice(0, 4)}` : digits }; }
    if (type === "date") { const date = new Date(raw * 1000); return { type, text: Number.isNaN(date.getTime()) ? String(raw) : date.toISOString().slice(0, 10) }; }
    return { type, text: String(raw) };
  }
  if (isRecord(raw)) {
    if (type === "email") return { type, text: clean(str(raw.email_address)) };
    return { type, text: clean(Object.values(raw).map(str).filter(Boolean).join(", ")) };
  }
  return { type };
}

function from1PuxData(data: Record<string, unknown>): ImportResult {
  const result = emptyResult("1password-1pux");
  let archived = 0;
  let documents = 0;
  const accounts = Array.isArray(data.accounts) ? data.accounts.filter(isRecord) : [];
  for (const account of accounts) {
    const vaults = Array.isArray(account.vaults) ? account.vaults.filter(isRecord) : [];
    for (const vault of vaults) {
      const attrs = isRecord(vault.attrs) ? vault.attrs : {};
      const vaultName = clean(str(attrs.name)) ?? "Imported vault";
      const shared = !PERSONAL_1P_VAULTS.has(vaultName.toLowerCase());
      const collection = normalizeCollection([vaultName]);
      const items = Array.isArray(vault.items) ? vault.items.filter(isRecord) : [];
      for (const item of items) {
        const state = str(item.state);
        if (state === "archived" || state === "trashed" || state === "deleted") { archived += 1; result.skipped += 1; continue; }
        const category = str(item.categoryUuid) ?? "";
        if (category === "006") { documents += 1; result.skipped += 1; continue; }
        const overview = isRecord(item.overview) ? item.overview : {};
        const details = isRecord(item.details) ? item.details : {};
        const urls = Array.isArray(overview.urls) ? overview.urls.filter(isRecord) : [];
        const url = clean(str(overview.url)) ?? clean(str(urls[0]?.url));
        let username: string | undefined;
        let secret: string | undefined;
        for (const field of Array.isArray(details.loginFields) ? details.loginFields.filter(isRecord) : []) {
          if (field.designation === "username" && !username) username = clean(str(field.value));
          if (field.designation === "password" && !secret) secret = clean(str(field.value));
        }
        secret = secret ?? clean(str(details.password));
        const notes = clean(str(details.notesPlain));
        const fields: Record<string, string> = {};
        let firstName: string | undefined;
        let lastName: string | undefined;
        for (const section of Array.isArray(details.sections) ? details.sections.filter(isRecord) : []) {
          for (const field of Array.isArray(section.fields) ? section.fields.filter(isRecord) : []) {
            const { type, text } = onePuxValue(field.value);
            if (!text) continue;
            const id = str(field.id) ?? "";
            const label = clean(str(field.title)) ?? clean(id) ?? "Field";
            if (type === "totp") { if (!fields.TOTP) fields.TOTP = text; else addField(fields, label, text); continue; }
            if (category === "002") {
              if (id === "ccnum" && !secret) { secret = text; continue; }
              if (id === "cardholder" && !username) { username = text; continue; }
              if (id === "cvv") { addField(fields, "Security code", text); continue; }
              if (id === "expiry") { addField(fields, "Expiry", text); continue; }
              if (id === "type") { addField(fields, "Brand", text); continue; }
            }
            if (category === "004" && id === "firstname") firstName = text;
            if (category === "004" && id === "lastname") lastName = text;
            addField(fields, label, text);
          }
        }
        if (category === "004" && !username) username = clean([firstName, lastName].filter(Boolean).join(" "));
        const title = clean(str(overview.title)) ?? hostTitle(url);
        if (!title && !username && !secret && !notes && !Object.keys(fields).length) { result.skipped += 1; continue; }
        const kind: ItemKind = ONEPASSWORD_KINDS[category] ?? (username || secret ? "login" : "secure-note");
        const sourceTags = Array.isArray(overview.tags) ? overview.tags.map(str).filter((tag): tag is string => Boolean(tag)) : [];
        const favIndex = typeof item.favIndex === "number" ? item.favIndex : 0;
        result.entries.push(entry(kind, {
          title: title ?? username ?? "Imported item", username, secret, url, notes,
          tags: mergeTags(sourceTags, shared ? [vaultName] : undefined), favorite: favIndex > 0, fields: nonEmpty(fields),
        }, collection, shared));
      }
    }
  }
  if (archived) result.warnings.push(`${plural(archived, "archived or deleted item")} ${archived === 1 ? "was" : "were"} not imported.`);
  if (documents) result.warnings.push(`${plural(documents, "document item")} ${documents === 1 ? "was" : "were"} skipped. Download documents from 1Password and add them as attachments.`);
  return result;
}

// ---------------------------------------------------------------- Bitwarden JSON

type BitwardenItem = {
  type?: number; name?: string; notes?: string | null; favorite?: boolean; folderId?: string | null;
  collectionIds?: string[] | null; organizationId?: string | null;
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: { uri?: string | null }[] | null } | null;
  card?: { cardholderName?: string | null; number?: string | null; expMonth?: string | null; expYear?: string | null; code?: string | null; brand?: string | null } | null;
  identity?: Record<string, string | null> | null;
};

function fromBitwardenJson(data: { encrypted?: boolean; items?: BitwardenItem[]; folders?: { id: string; name: string }[]; collections?: { id: string; name: string }[] }): ImportResult {
  if (data.encrypted) throw new Error("This is an encrypted Bitwarden export. Export again as unencrypted JSON, import it, then delete the file.");
  if (!Array.isArray(data.items)) throw new Error("This JSON file is not a Bitwarden export.");
  const folders = new Map((Array.isArray(data.folders) ? data.folders : []).filter(isRecord).map((folder) => [folder.id, folder.name]));
  const collections = new Map((Array.isArray(data.collections) ? data.collections : []).filter(isRecord).map((collection) => [collection.id, collection.name]));
  const result = emptyResult("bitwarden-json");
  for (const item of data.items) {
    if (!isRecord(item)) { result.skipped += 1; continue; }
    const title = clean(item.name) ?? "Imported item";
    const notes = clean(item.notes ?? undefined);
    const folder = item.folderId ? folders.get(item.folderId) : undefined;
    const collectionIds = Array.isArray(item.collectionIds) ? item.collectionIds : [];
    const collectionName = collectionIds.map((id) => collections.get(id)).find((name): name is string => Boolean(clean(name)));
    const shared = collectionIds.length > 0;
    const collection = normalizeCollection(collectionName ?? folder);
    const tags = folder ? [folder] : collectionName ? [collectionName] : undefined;
    const base = { title, notes, favorite: Boolean(item.favorite), tags };
    if (item.type === 1 && item.login) {
      result.entries.push(entry("login", { ...base, username: clean(item.login.username ?? undefined), secret: clean(item.login.password ?? undefined), url: clean(item.login.uris?.[0]?.uri ?? undefined), fields: totpFields(item.login.totp ?? undefined) }, collection, shared));
    } else if (item.type === 2) {
      result.entries.push(entry("secure-note", base, collection, shared));
    } else if (item.type === 3 && item.card) {
      const fields: Record<string, string> = {};
      if (item.card.expMonth || item.card.expYear) fields.Expiry = `${item.card.expMonth ?? ""}/${item.card.expYear ?? ""}`;
      if (item.card.code) fields["Security code"] = item.card.code;
      if (item.card.brand) fields.Brand = item.card.brand;
      result.entries.push(entry("payment-card", { ...base, username: clean(item.card.cardholderName ?? undefined), secret: clean(item.card.number ?? undefined), fields }, collection, shared));
    } else if (item.type === 4 && item.identity) {
      const identity = item.identity;
      const fields = Object.fromEntries(Object.entries(identity).filter(([, value]) => typeof value === "string" && value.trim()).map(([key, value]) => [key, String(value)]));
      const fullName = [identity.firstName, identity.middleName, identity.lastName].filter(Boolean).join(" ");
      result.entries.push(entry("identity", { ...base, username: fullName || undefined, secret: clean(identity.passportNumber ?? identity.licenseNumber ?? identity.ssn ?? undefined), fields }, collection, shared));
    } else result.skipped += 1;
  }
  if (collectionIds(data.items).some((ids) => ids.length > 0) && !collections.size) {
    result.warnings.push("Collection names were not included in this export. Shared items were imported without their collection.");
  }
  return result;
}

function collectionIds(items: BitwardenItem[]) {
  return items.map((item) => (isRecord(item) && Array.isArray(item.collectionIds) ? item.collectionIds : []));
}

// ---------------------------------------------------------------- KeePass 2.x XML

type XmlNode = { name: string; attrs: Record<string, string>; children: XmlNode[]; text: string };
const MAX_XML_DEPTH = 128;

/** Decodes only the five predefined XML entities and numeric references. Anything else stays literal. */
export function decodeXmlEntities(value: string): string {
  return value.replace(/&(#[xX][0-9a-fA-F]{1,6}|#[0-9]{1,7}|amp|lt|gt|quot|apos);/gu, (match, body: string) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X" ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      if (!Number.isFinite(code) || code < 1 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return match;
      return String.fromCodePoint(code);
    }
    return ({ amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" } as Record<string, string>)[body];
  });
}

const xmlError = () => new Error("This XML file could not be read. Export again from KeePass as \"KeePass XML (2.x)\".");

/** Small non-validating XML parser: elements, attributes, text, CDATA, comments. No DTDs, no entity expansion. */
export function parseXml(xml: string): XmlNode {
  const root: XmlNode = { name: "#document", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let index = 0;
  while (index < xml.length) {
    const open = xml.indexOf("<", index);
    const textEnd = open < 0 ? xml.length : open;
    if (textEnd > index) {
      const text = xml.slice(index, textEnd);
      if (stack.length > 1) stack[stack.length - 1].text += decodeXmlEntities(text);
      else if (text.trim()) throw xmlError();
    }
    if (open < 0) break;
    if (xml.startsWith("<!--", open)) {
      const end = xml.indexOf("-->", open + 4);
      if (end < 0) throw xmlError();
      index = end + 3;
    } else if (xml.startsWith("<![CDATA[", open)) {
      const end = xml.indexOf("]]>", open + 9);
      if (end < 0 || stack.length < 2) throw xmlError();
      stack[stack.length - 1].text += xml.slice(open + 9, end);
      index = end + 3;
    } else if (xml.startsWith("<?", open)) {
      const end = xml.indexOf("?>", open + 2);
      if (end < 0) throw xmlError();
      index = end + 2;
    } else if (xml.startsWith("<!", open)) {
      throw new Error("This XML file contains a document type definition, which KeePass exports never include. It was not imported.");
    } else if (xml.startsWith("</", open)) {
      const end = xml.indexOf(">", open + 2);
      if (end < 0) throw xmlError();
      const name = xml.slice(open + 2, end).trim();
      const node = stack.pop();
      if (!node || node === root || node.name !== name) throw xmlError();
      index = end + 1;
    } else {
      let end = open + 1;
      let quote = "";
      for (; end < xml.length; end += 1) {
        const char = xml[end];
        if (quote) { if (char === quote) quote = ""; } else if (char === "\"" || char === "'") quote = char; else if (char === ">") break;
      }
      if (end >= xml.length) throw xmlError();
      let body = xml.slice(open + 1, end);
      const selfClosing = body.endsWith("/");
      if (selfClosing) body = body.slice(0, -1);
      const nameMatch = /^([A-Za-z_][\w.:-]*)/u.exec(body);
      if (!nameMatch) throw xmlError();
      const attrs: Record<string, string> = {};
      for (const attr of body.slice(nameMatch[1].length).matchAll(/([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/gu)) {
        attrs[attr[1]] = decodeXmlEntities(attr[2] ?? attr[3] ?? "");
      }
      const node: XmlNode = { name: nameMatch[1], attrs, children: [], text: "" };
      stack[stack.length - 1].children.push(node);
      if (!selfClosing) {
        if (stack.length > MAX_XML_DEPTH) throw xmlError();
        stack.push(node);
      }
      index = end + 1;
    }
  }
  if (stack.length !== 1 || root.children.length !== 1) throw xmlError();
  return root.children[0];
}

function fromDom(element: Element, depth = 0): XmlNode {
  if (depth > MAX_XML_DEPTH) throw xmlError();
  const node: XmlNode = { name: element.localName, attrs: {}, children: [], text: "" };
  for (const attr of Array.from(element.attributes)) node.attrs[attr.name] = attr.value;
  for (const child of Array.from(element.childNodes)) {
    if (child.nodeType === 1) node.children.push(fromDom(child as Element, depth + 1));
    else if (child.nodeType === 3 || child.nodeType === 4) node.text += child.nodeValue ?? "";
  }
  return node;
}

function readXml(text: string): XmlNode {
  // KeePass never writes a DTD; refusing one up front means no parser ever sees entity declarations.
  if (/<!DOCTYPE|<!ENTITY/iu.test(text)) throw new Error("This XML file contains a document type definition, which KeePass exports never include. It was not imported.");
  if (typeof DOMParser !== "undefined") {
    const document = new DOMParser().parseFromString(text, "application/xml");
    if (document.getElementsByTagName("parsererror").length || !document.documentElement) throw xmlError();
    return fromDom(document.documentElement);
  }
  return parseXml(text);
}

const child = (node: XmlNode | undefined, name: string) => node?.children.find((candidate) => candidate.name === name);
const childText = (node: XmlNode | undefined, name: string) => child(node, name)?.text.trim() ?? "";

function countEntries(group: XmlNode, depth = 0): number {
  if (depth > MAX_XML_DEPTH) return 0;
  return group.children.reduce((sum, node) => sum + (node.name === "Entry" ? 1 : node.name === "Group" ? countEntries(node, depth + 1) : 0), 0);
}

const KEEPASS_STANDARD = new Set(["Title", "UserName", "Password", "URL", "Notes", "otp", "TimeOtp-Secret-Base32"]);

function fromKeepassXml(text: string): ImportResult {
  const document = readXml(text);
  if (document.name !== "KeePassFile") throw new Error("This XML file is not a KeePass export.");
  const result = emptyResult("keepass-xml");
  const meta = child(document, "Meta");
  const recycleEnabled = childText(meta, "RecycleBinEnabled").toLowerCase() !== "false";
  const recycleUuid = childText(meta, "RecycleBinUUID");
  let recycled = 0;
  let attachments = 0;
  const rootGroups = (child(document, "Root")?.children ?? []).filter((node) => node.name === "Group");
  if (!rootGroups.length) throw new Error("This KeePass export does not contain any groups.");

  const visit = (group: XmlNode, path: string[], depth: number) => {
    if (depth > MAX_XML_DEPTH) throw xmlError();
    for (const node of group.children) {
      if (node.name === "Group") {
        const name = childText(node, "Name");
        const uuid = childText(node, "UUID");
        if (name === "Recycle Bin" || (recycleEnabled && recycleUuid && uuid === recycleUuid && !/^A{22}==$/u.test(uuid))) {
          const count = countEntries(node);
          recycled += count; result.skipped += count;
          continue;
        }
        visit(node, name ? [...path, name] : path, depth + 1);
      } else if (node.name === "Entry") {
        const strings: Record<string, string> = {};
        for (const pair of node.children) {
          if (pair.name !== "String") continue;
          const key = childText(pair, "Key");
          const value = child(pair, "Value")?.text ?? "";
          if (key && !(key in strings)) strings[key] = value;
        }
        if (node.children.some((part) => part.name === "Binary")) attachments += 1;
        const url = clean(strings.URL);
        const username = clean(strings.UserName);
        const secret = clean(strings.Password);
        const notes = clean(strings.Notes);
        const title = clean(strings.Title) ?? hostTitle(url);
        const fields: Record<string, string> = {};
        const totp = clean(strings.otp) ?? clean(strings["TimeOtp-Secret-Base32"]);
        if (totp) fields.TOTP = totp;
        for (const [key, value] of Object.entries(strings)) if (!KEEPASS_STANDARD.has(key)) addField(fields, key, value);
        if (!title && !username && !secret && !notes && !Object.keys(fields).length) { result.skipped += 1; continue; }
        const collection = normalizeCollection(path);
        const sourceTags = childText(node, "Tags").split(/[;,]/u);
        const kind: ItemKind = username || secret || url ? "login" : "secure-note";
        result.entries.push(entry(kind, { title: title ?? username ?? "Imported item", username, secret, url, notes, tags: mergeTags(collectionTags(collection), sourceTags), fields: nonEmpty(fields) }, collection));
      }
    }
  };
  for (const group of rootGroups) visit(group, [], 0);
  if (recycled) result.warnings.push(`${plural(recycled, "item")} in the Recycle Bin ${recycled === 1 ? "was" : "were"} not imported.`);
  if (attachments) result.warnings.push(`${plural(attachments, "item")} had file attachments, which are not included in KeePass XML exports. Add them again as attachments.`);
  return result;
}

// ---------------------------------------------------------------- Entry points

function fromJson(text: string): ImportResult {
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw new Error("This JSON file could not be read."); }
  if (!isRecord(data)) throw new Error("This JSON file is not a supported export.");
  if (Array.isArray(data.records) || Array.isArray(data.shared_folders)) return fromKeeperJson(data);
  if (Array.isArray(data.accounts)) return from1PuxData(data);
  return fromBitwardenJson(data as Parameters<typeof fromBitwardenJson>[0]);
}

function summarizeCollections(entries: ImportedEntry[]): ImportCollection[] {
  const map = new Map<string, ImportCollection>();
  for (const item of entries) {
    if (!item.collection) continue;
    const current = map.get(item.collection) ?? { name: item.collection, count: 0, shared: false };
    current.count += 1;
    current.shared = current.shared || Boolean(item.shared);
    map.set(item.collection, current);
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name, "en", { sensitivity: "base" }) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function finalize(result: ImportResult): ImportResult {
  if (!result.entries.length) throw new Error("No items were found in this file.");
  if (result.entries.length > MAX_IMPORT_ITEMS) throw new Error(`This file has more than ${MAX_IMPORT_ITEMS} items. Split it and import in parts.`);
  result.collections = summarizeCollections(result.entries);
  return result;
}

/**
 * Parse an export that is already text. `hint` is the format the user picked; it is needed
 * for Keeper CSV (which has no header row). Other formats are detected from the content.
 */
export function importFromText(text: string, fileName: string, hint?: ImportFormat): ImportResult {
  if (text.length > MAX_IMPORT_BYTES) throw new Error("This file is too large. Split it into files under 10 MB.");
  const trimmed = text.trimStart();
  const lowerName = fileName.toLowerCase();
  let result: ImportResult;
  if (lowerName.endsWith(".json") || trimmed.startsWith("{")) result = fromJson(text);
  else if (lowerName.endsWith(".xml") || trimmed.startsWith("<")) result = fromKeepassXml(text);
  else if (hint === "keeper-csv") result = fromKeeperCsv(text);
  else result = fromCsv(text);
  return finalize(result);
}

/**
 * Parse a picked file. Handles 1Password .1pux archives (ZIP containing export.data) on this
 * device; everything else is read as text and passed to importFromText.
 */
export async function importFromFile(file: ImportFile, hint?: ImportFormat): Promise<ImportResult> {
  const name = (file.name ?? "").toLowerCase();
  const source = zipSourceFromBlob(file);
  const zip = await isZip(source);
  if (zip) {
    const entries = await listZipEntries(source);
    const hasExport = entries.some((candidate) => candidate.name === "export.data");
    if (!hasExport) {
      if (name.endsWith(".1pux") || hint === "1password-1pux") throw new Error("This .1pux file does not contain export.data. Export again from 1Password 8.");
      throw new Error("This is a ZIP archive. Unzip it and choose the export file inside (for Dashlane, credentials.csv).");
    }
    const data = await readZipEntry(source, "export.data", MAX_ZIP_ENTRY_BYTES, entries);
    let parsed: unknown;
    try { parsed = JSON.parse(new TextDecoder("utf-8").decode(data!)); } catch { throw new Error("The 1Password export inside this .1pux file could not be read."); }
    if (!isRecord(parsed) || !Array.isArray(parsed.accounts)) throw new Error("The 1Password export inside this .1pux file could not be read.");
    const result = from1PuxData(parsed);
    if (entries.some((candidate) => candidate.name.startsWith("files/") && !candidate.name.endsWith("/"))) {
      result.warnings.push("File attachments in this .1pux were not imported. Add important files again as attachments.");
    }
    return finalize(result);
  }
  if (name.endsWith(".1pux")) throw new Error("This .1pux file is not a valid 1Password export. Export again from 1Password 8.");
  if (file.size > MAX_IMPORT_BYTES) throw new Error("This file is too large. Split it into files under 10 MB.");
  return importFromText(await file.text(), file.name ?? "", hint);
}

// ---------------------------------------------------------------- Duplicates

function duplicateKey(kind: ItemKind, payload: ExistingImportItem["payload"]) {
  const host = hostTitle(clean(payload.url))?.toLowerCase() ?? "";
  const username = (payload.username ?? "").trim().toLowerCase();
  const secret = payload.secret ?? "";
  // Without a username or secret, fall back to title + notes so unrelated notes are not merged.
  if (!username && !secret) return [kind, host, "", "", (payload.title ?? "").trim().toLowerCase(), (payload.notes ?? "").trim()].join("\\u0000");
  return [kind, host, username, secret].join("\\u0000");
}

/**
 * Indexes of `entries` that match an item already in the vault, or an earlier entry in the
 * same file, by kind, URL host, username and secret.
 */
export function findDuplicates(entries: ImportedEntry[], existing: ExistingImportItem[]): number[] {
  const seen = new Set(existing.map((item) => duplicateKey(item.kind, item.payload)));
  const duplicates: number[] = [];
  entries.forEach((item, index) => {
    const key = duplicateKey(item.kind, item.payload);
    if (seen.has(key)) duplicates.push(index); else seen.add(key);
  });
  return duplicates;
}
