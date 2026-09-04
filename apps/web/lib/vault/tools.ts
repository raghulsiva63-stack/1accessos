import type { VaultItem } from "@/lib/vault/items";

const WORDS = [
  "amber", "anchor", "atlas", "birch", "bloom", "cedar", "cipher", "cloud",
  "comet", "coral", "delta", "ember", "falcon", "fjord", "forest", "globe",
  "harbor", "indigo", "jungle", "lilac", "lumen", "maple", "meadow", "nebula",
  "ocean", "orbit", "pearl", "pixel", "quartz", "raven", "river", "saffron",
  "signal", "silver", "spruce", "summit", "tiger", "velvet", "willow", "zenith",
] as const;

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
  const length = Math.min(128, Math.max(12, Math.floor(options.length)));
  const groups = [
    options.uppercase ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
    options.lowercase ? "abcdefghijkmnopqrstuvwxyz" : "",
    options.numbers ? "23456789" : "",
    options.symbols ? "!@#$%^&*()-_=+[]{}" : "",
  ].filter(Boolean);
  if (!groups.length) throw new Error("Select at least one character group.");
  let alphabet = groups.join("");
  if (!options.avoidAmbiguous) alphabet += "Il1O0|`'\"";
  const result = groups.map((group) => group[randomIndex(group.length)]);
  while (result.length < length) result.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = randomIndex(index + 1);
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result.join("");
}

export function generatePassphrase(words = 5, separator = "-") {
  return Array.from({ length: Math.min(12, Math.max(4, words)) }, () => WORDS[randomIndex(WORDS.length)]).join(separator);
}

export type HealthFinding = {
  id: string;
  severity: "critical" | "warning" | "good";
  title: string;
  detail: string;
  itemIds: string[];
};

export function passwordHealth(items: VaultItem[]) {
  const logins = items.filter((item) => item.contentType === "login" && item.payload.secret);
  const bySecret = new Map<string, VaultItem[]>();
  for (const item of logins) {
    const secret = item.payload.secret!;
    bySecret.set(secret, [...(bySecret.get(secret) ?? []), item]);
  }
  const reused = [...bySecret.values()].filter((group) => group.length > 1);
  const weak = logins.filter((item) => {
    const value = item.payload.secret!;
    return value.length < 14 || !/[A-Z]/u.test(value) || !/[a-z]/u.test(value) || !/\d/u.test(value);
  });
  const old = logins.filter((item) => Date.now() - Date.parse(item.payload.updatedAt) > 365 * 86_400_000);
  const findings: HealthFinding[] = [
    ...reused.map((group, index) => ({
      id: `reused-${index}`,
      severity: "critical" as const,
      title: "Reused password",
      detail: `${group.length} logins share the same password. Change each to a unique value.`,
      itemIds: group.map((item) => item.id),
    })),
    ...(weak.length ? [{
      id: "weak",
      severity: "warning" as const,
      title: "Weak passwords",
      detail: `${weak.length} login${weak.length === 1 ? "" : "s"} should use a longer, more varied password.`,
      itemIds: weak.map((item) => item.id),
    }] : []),
    ...(old.length ? [{
      id: "old",
      severity: "warning" as const,
      title: "Passwords not updated for a year",
      detail: `${old.length} login${old.length === 1 ? "" : "s"} may need review.`,
      itemIds: old.map((item) => item.id),
    }] : []),
  ];
  const deductions = Math.min(100, reused.reduce((sum, group) => sum + group.length * 12, 0) + weak.length * 5 + old.length * 2);
  return {
    score: Math.max(0, 100 - deductions),
    findings: findings.length ? findings : [{
      id: "healthy",
      severity: "good" as const,
      title: "No obvious password risks",
      detail: "Passkey-X found no reused, weak, or stale login passwords in this vault.",
      itemIds: [],
    }],
    loginCount: logins.length,
  };
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
  const rows = csv.replace(/^\uFEFF/u, "").split(/\r?\n/u).filter((row) => row.trim());
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
