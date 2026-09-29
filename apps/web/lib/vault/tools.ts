import type { VaultItem } from "@/lib/vault/items";

// EFF large wordlist; attribution and source hash in THIRD_PARTY_NOTICES.md.
import WORDS from "./eff-words.json";
import { analyzeVaultHealth, summarizeHealth } from "@/lib/security/score";

function randomIndex(max: number) {
  if (!Number.isSafeInteger(max) || max < 1) throw new Error("Invalid random range.");
  const cutoff = Math.floor(0x1_0000_0000 / max) * max;
  const sample = new Uint32Array(1);
  do crypto.getRandomValues(sample); while (sample[0] >= cutoff);
  return sample[0] % max;
}

export type PasswordOptions = {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
};

export function generatePassword(options: PasswordOptions) {
  if (!Number.isFinite(options.length)) throw new Error("Password length must be finite.");
  const length = Math.min(128, Math.max(12, Math.floor(options.length)));
  const groups = [
    options.uppercase ? (options.avoidAmbiguous ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ") : "",
    options.lowercase ? (options.avoidAmbiguous ? "abcdefghijkmnopqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz") : "",
    options.numbers ? (options.avoidAmbiguous ? "23456789" : "0123456789") : "",
    options.symbols ? "!@#$%^&*()-_=+[]{}" : "",
  ].filter(Boolean);
  if (!groups.length) throw new Error("Select at least one character group.");
  const alphabet = groups.join("");
  const result = groups.map((group) => group[randomIndex(group.length)]);
  while (result.length < length) result.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = randomIndex(index + 1);
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result.join("");
}

export function generatePassphrase(words = 7, separator = " ") {
  if (!Number.isFinite(words)) throw new Error("Word count must be finite.");
  if (![" ", "."].includes(separator)) throw new Error("Choose a supported separator.");
  const count = Math.min(12, Math.max(6, Math.floor(words)));
  return Array.from({ length: count }, () => WORDS[randomIndex(WORDS.length)]).join(separator);
}

export type { HealthFinding } from "@/lib/security/score";

/**
 * Home and reminder summary. Uses the same analysis as the Security page, so both always show the
 * same score (breach results are added on the Security page once a check has run).
 */
export function passwordHealth(items: VaultItem[], now = Date.now(), rotationDays = 365) {
  return summarizeHealth(analyzeVaultHealth(items, undefined, now, rotationDays));
}

export type CsvLogin = { title: string; username?: string; secret?: string; url?: string; notes?: string };

function parseCsvRow(row: string) {
  const cells: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < row.length; index += 1) {
    const character = row[index];
    if (character === '"' && quoted && row[index + 1] === '"') {
      value += '"';
      index += 1;
    } else if (character === '"') quoted = !quoted;
    else if (character === "," && !quoted) {
      cells.push(value);
      value = "";
    } else value += character;
  }
  cells.push(value);
  return cells;
}

export function parseLoginCsv(csv: string): CsvLogin[] {
  const rows = csv.replace(/^\\uFEFF/u, "").split(/\r?\n/u).filter((row) => row.trim());
  if (rows.length < 2) throw new Error("The CSV does not contain any records.");
  const headers = parseCsvRow(rows[0]).map((value) => value.trim().toLowerCase());
  const find = (...names: string[]) => names.map((name) => headers.indexOf(name)).find((index) => index >= 0) ?? -1;
  const titleIndex = find("name", "title", "service");
  const usernameIndex = find("username", "login_username", "email");
  const passwordIndex = find("password", "login_password", "secret");
  const urlIndex = find("url", "login_uri", "website");
  const notesIndex = find("notes", "extra");
  if (passwordIndex < 0 && usernameIndex < 0) throw new Error("CSV must include a username or password column.");
  return rows.slice(1).map(parseCsvRow).map((cells, index) => ({
    title: (titleIndex >= 0 ? cells[titleIndex] : "") || (urlIndex >= 0 ? cells[urlIndex] : "") || `Imported login ${index + 1}`,
    username: usernameIndex >= 0 ? cells[usernameIndex] || undefined : undefined,
    secret: passwordIndex >= 0 ? cells[passwordIndex] || undefined : undefined,
    url: urlIndex >= 0 ? cells[urlIndex] || undefined : undefined,
    notes: notesIndex >= 0 ? cells[notesIndex] || undefined : undefined,
  }));
}
