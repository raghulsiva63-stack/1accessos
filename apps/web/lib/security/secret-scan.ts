// Finds secrets that were pasted into notes or custom fields instead of a proper item type.
// Notes are shown in plain view (screen shares, over-the-shoulder), are not masked, are not
// covered by rotation reminders and are copied without clipboard clearing. Runs on the device only.

import type { ItemKind, VaultItem } from "@/lib/vault/items";

export type SecretKind =
  | "private_key" | "aws_key" | "github_token" | "slack_token" | "stripe_key"
  | "google_api_key" | "ai_api_key" | "jwt" | "card_number";

export type SecretFinding = {
  itemId: string;
  title: string;
  kind: SecretKind;
  /** "notes" or "field:<name>". */
  location: string;
  /** Never the secret itself: at most the first 4 and last 4 characters. */
  preview: string;
  suggestedType: ItemKind;
};

type Rule = { kind: SecretKind; pattern: RegExp; suggestedType: ItemKind; allowedIn: ItemKind[] };

const API_TYPES: ItemKind[] = ["api-key", "custom-secret", "database", "software-license"];

const RULES: Rule[] = [
  { kind: "private_key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/gu, suggestedType: "ssh-key", allowedIn: ["ssh-key", "certificate", "custom-secret"] },
  { kind: "aws_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "github_token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "slack_token", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,200}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "stripe_key", pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "ai_api_key", pattern: /\bsk-(?:proj-|ant-(?:api\d{2}-)?|svcacct-)?[A-Za-z0-9_-]{32,200}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
  { kind: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu, suggestedType: "api-key", allowedIn: API_TYPES },
];

export const SECRET_LABELS: Record<SecretKind, string> = {
  private_key: "Private key",
  aws_key: "AWS access key",
  github_token: "GitHub token",
  slack_token: "Slack token",
  stripe_key: "Stripe live key",
  google_api_key: "Google API key",
  ai_api_key: "AI service API key",
  jwt: "Access token (JWT)",
  card_number: "Card number",
};

function luhn(digits: string): boolean {
  let sum = 0;
  for (let index = 0; index < digits.length; index += 1) {
    let digit = Number(digits[digits.length - 1 - index]);
    if (index % 2 === 1) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
  }
  return sum % 10 === 0;
}

function mask(value: string): string {
  const compact = value.replace(/\s|-/gu, "");
  if (compact.length <= 8) return "••••";
  return `${compact.slice(0, 4)}…${compact.slice(-4)}`;
}

function cardNumbers(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(/(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/gu)) {
    const digits = match[0].replace(/\D/gu, "");
    if (digits.length >= 13 && digits.length <= 19 && /^[3456]/u.test(digits) && !/^(\d)\1+$/u.test(digits) && luhn(digits)) found.push(match[0]);
  }
  return found;
}

/** Scans notes and custom fields. The login password field itself is never scanned. */
export function scanForExposedSecrets(items: VaultItem[]): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const item of items) {
    if (item.deletedAt || item.payload.archived) continue;
    const places: [string, string][] = [];
    if (item.payload.notes) places.push(["notes", item.payload.notes]);
    for (const [name, value] of Object.entries(item.payload.fields ?? {})) {
      if (typeof value === "string" && value) places.push([`field:${name}`, value]);
    }
    const seen = new Set<string>();
    for (const [location, text] of places) {
      const sample = text.slice(0, 20_000);
      for (const rule of RULES) {
        if (rule.allowedIn.includes(item.contentType)) continue;
        for (const match of sample.matchAll(rule.pattern)) {
          const key = `${rule.kind}:${match[0]}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({ itemId: item.id, title: item.payload.title, kind: rule.kind, location,
            preview: rule.kind === "private_key" ? "-----BEGIN … PRIVATE KEY-----" : mask(match[0]), suggestedType: rule.suggestedType });
        }
      }
      if (item.contentType !== "payment-card") {
        for (const card of cardNumbers(sample)) {
          const key = `card:${card.replace(/\D/gu, "")}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({ itemId: item.id, title: item.payload.title, kind: "card_number", location, preview: `•••• ${card.replace(/\D/gu, "").slice(-4)}`, suggestedType: "payment-card" });
        }
      }
    }
  }
  return findings;
}
