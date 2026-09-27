import type { ItemKind, VaultPayload } from "@/lib/vault/items";

export type ImportFormat = "1password" | "bitwarden-csv" | "bitwarden-json" | "lastpass" | "dashlane" | "chrome" | "firefox" | "generic";

export type ImportedEntry = { kind: ItemKind; payload: Omit<VaultPayload, "version" | "updatedAt"> };

export type ImportResult = { format: ImportFormat; entries: ImportedEntry[]; skipped: number };

export const FORMAT_LABELS: Record<ImportFormat, string> = {
  "1password": "1Password (CSV)",
  "bitwarden-csv": "Bitwarden (CSV)",
  "bitwarden-json": "Bitwarden (JSON)",
  lastpass: "LastPass (CSV)",
  dashlane: "Dashlane (CSV)",
  chrome: "Chrome / Edge / Brave (CSV)",
  firefox: "Firefox (CSV)",
  generic: "Generic CSV",
};

export const MAX_IMPORT_BYTES = 10 * 1024 * 1024;
export const MAX_IMPORT_ITEMS = 5000;

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

const clean = (value: string | undefined) => {
  const trimmed = (value ?? "").trim();
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

export function detectCsvFormat(headers: string[]): ImportFormat {
  const has = (...names: string[]) => names.every((name) => headers.includes(name));
  if (has("login_uri", "login_username", "login_password")) return "bitwarden-csv";
  if (has("url", "username", "password", "extra", "grouping")) return "lastpass";
  if (has("title", "url", "username", "password") && (headers.includes("otpauth") || headers.includes("archived"))) return "1password";
  if (has("username", "title", "password", "note", "url") && headers.includes("category")) return "dashlane";
  if (has("url", "username", "password", "httprealm")) return "firefox";
  if (has("name", "url", "username", "password")) return "chrome";
  return "generic";
}

function fromCsv(text: string): ImportResult {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error("The file does not contain any records.");
  const headers = rows[0].map((value) => value.trim().toLowerCase());
  const format = detectCsvFormat(headers);
  const column = (...names: string[]) => names.map((name) => headers.indexOf(name)).find((index) => index >= 0) ?? -1;
  const get = (cells: string[], ...names: string[]) => { const index = column(...names); return index >= 0 ? cells[index] : undefined; };
  if (column("password", "login_password", "secret") < 0 && column("username", "login_username", "email") < 0 && format === "generic") {
    throw new Error("This CSV needs at least a username or password column.");
  }
  let skipped = 0;
  const entries: ImportedEntry[] = [];
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
    if (!title && !username && !secret && !notes) { skipped += 1; continue; }
    const tags = folder ? folder.split(/[,/\\]/u).map((tag) => tag.trim()).filter(Boolean) : undefined;
    if (isNote) {
      entries.push({ kind: "secure-note", payload: { title: title ?? "Imported note", notes, tags, favorite } });
    } else {
      entries.push({ kind: "login", payload: { title: title ?? username ?? "Imported login", username, secret, url, notes, tags, favorite, fields: totpFields(totp) } });
    }
  }
  return { format, entries, skipped };
}

type BitwardenItem = {
  type?: number; name?: string; notes?: string | null; favorite?: boolean; folderId?: string | null;
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: { uri?: string | null }[] | null } | null;
  card?: { cardholderName?: string | null; number?: string | null; expMonth?: string | null; expYear?: string | null; code?: string | null; brand?: string | null } | null;
  identity?: Record<string, string | null> | null;
};

function fromBitwardenJson(text: string): ImportResult {
  let data: { encrypted?: boolean; items?: BitwardenItem[]; folders?: { id: string; name: string }[] };
  try { data = JSON.parse(text); } catch { throw new Error("This JSON file could not be read."); }
  if (data.encrypted) throw new Error("This is an encrypted Bitwarden export. Export again as unencrypted JSON, import it, then delete the file.");
  if (!Array.isArray(data.items)) throw new Error("This JSON file is not a Bitwarden export.");
  const folders = new Map((data.folders ?? []).map((folder) => [folder.id, folder.name]));
  let skipped = 0;
  const entries: ImportedEntry[] = [];
  for (const item of data.items) {
    const title = clean(item.name) ?? "Imported item";
    const notes = clean(item.notes ?? undefined);
    const folder = item.folderId ? folders.get(item.folderId) : undefined;
    const base = { title, notes, favorite: Boolean(item.favorite), tags: folder ? [folder] : undefined };
    if (item.type === 1 && item.login) {
      entries.push({ kind: "login", payload: { ...base, username: clean(item.login.username ?? undefined), secret: clean(item.login.password ?? undefined), url: clean(item.login.uris?.[0]?.uri ?? undefined), fields: totpFields(item.login.totp ?? undefined) } });
    } else if (item.type === 2) {
      entries.push({ kind: "secure-note", payload: base });
    } else if (item.type === 3 && item.card) {
      const fields: Record<string, string> = {};
      if (item.card.expMonth || item.card.expYear) fields.Expiry = `${item.card.expMonth ?? ""}/${item.card.expYear ?? ""}`;
      if (item.card.code) fields["Security code"] = item.card.code;
      if (item.card.brand) fields.Brand = item.card.brand;
      entries.push({ kind: "payment-card", payload: { ...base, username: clean(item.card.cardholderName ?? undefined), secret: clean(item.card.number ?? undefined), fields } });
    } else if (item.type === 4 && item.identity) {
      const identity = item.identity;
      const fields = Object.fromEntries(Object.entries(identity).filter(([, value]) => typeof value === "string" && value.trim()).map(([key, value]) => [key, String(value)]));
      const fullName = [identity.firstName, identity.middleName, identity.lastName].filter(Boolean).join(" ");
      entries.push({ kind: "identity", payload: { ...base, username: fullName || undefined, secret: clean(identity.passportNumber ?? identity.licenseNumber ?? identity.ssn ?? undefined), fields } });
    } else skipped += 1;
  }
  return { format: "bitwarden-json", entries, skipped };
}

export function importFromText(text: string, fileName: string): ImportResult {
  if (text.length > MAX_IMPORT_BYTES) throw new Error("This file is too large. Split it into files under 10 MB.");
  const trimmed = text.trimStart();
  const result = fileName.toLowerCase().endsWith(".json") || trimmed.startsWith("{") ? fromBitwardenJson(text) : fromCsv(text);
  if (!result.entries.length) throw new Error("No items were found in this file.");
  if (result.entries.length > MAX_IMPORT_ITEMS) throw new Error(`This file has more than ${MAX_IMPORT_ITEMS} items. Split it and import in parts.`);
  return result;
}
