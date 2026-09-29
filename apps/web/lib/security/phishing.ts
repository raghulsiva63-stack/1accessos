// Look-alike website detection. Runs on the device against the sites already saved in the vault:
// nothing is sent anywhere. Pure functions.

import { hostnameOf, splitDomain } from "./domains";

export type LookalikeReason = "homoglyph" | "typo" | "punycode" | "other_ending" | "subdomain_trick";

export type SiteVerdict =
  | { kind: "trusted"; domain: string }
  | { kind: "lookalike"; domain: string; resembles: string; reason: LookalikeReason }
  | { kind: "unknown"; domain: string | null };

// Characters that are easy to mistake for others. Keys are mapped to the Latin letter they imitate.
const CONFUSABLES: Record<string, string> = {
  "0": "o", "1": "l", "i": "l", "|": "l", "!": "l", "3": "e", "4": "a", "@": "a", "5": "s", "$": "s", "7": "t", "8": "b", "9": "g",
  // Cyrillic
  "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
  "ѕ": "s", "і": "l", "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
  // Greek
  "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "ι": "l", "κ": "k", "χ": "x",
  // Latin look-alikes
  "ı": "l", "ł": "l", "ɩ": "l", "ǀ": "l", "ß": "b", "ø": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o",
  "á": "a", "à": "a", "â": "a", "ä": "a", "å": "a", "ã": "a", "é": "e", "è": "e", "ê": "e", "ë": "e",
  "í": "l", "ì": "l", "î": "l", "ï": "l", "ú": "u", "ù": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n", "ý": "y", "ÿ": "y",
};

/** Normalises a domain label so visually similar spellings compare equal. */
export function skeleton(label: string): string {
  let result = "";
  for (const character of label.toLowerCase()) result += CONFUSABLES[character] ?? character;
  return result.replace(/rn/gu, "m").replace(/vv/gu, "w").replace(/cl/gu, "d").replace(/-/gu, "");
}

/** Optimal string alignment distance (Damerau–Levenshtein without repeated edits), capped. */
export function editDistance(a: string, b: string, cap = 3): number {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const rows = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) rows[i][j] = Math.min(rows[i][j], rows[i - 2][j - 2] + 1);
    }
  }
  return Math.min(rows[a.length][b.length], cap + 1);
}

// RFC 3492 Punycode decoding (for "xn--" labels), so "xn--pypal-4ve.com" can be compared as "pаypal".
export function decodePunycode(input: string): string | null {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const output: number[] = [];
  const basic = input.lastIndexOf("-");
  for (let index = 0; index < Math.max(basic, 0); index += 1) {
    const code = input.charCodeAt(index);
    if (code >= 0x80) return null;
    output.push(code);
  }
  let n = 128, bias = 72, i = 0;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldI = i;
    for (let w = 1, k = base; ; k += base) {
      if (index >= input.length) return null;
      const code = input.charCodeAt(index++);
      const digit = code - 48 < 10 ? code - 22 : code - 65 < 26 ? code - 65 : code - 97 < 26 ? code - 97 : base;
      if (digit >= base) return null;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
      if (w > 1e9 || i > 1e9) return null;
    }
    const length = output.length + 1;
    let delta = oldI === 0 ? Math.floor((i - oldI) / damp) : (i - oldI) >> 1;
    delta += Math.floor(delta / length);
    let k = 0;
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    bias = Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff) return null;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

function unicodeLabel(label: string): { text: string; punycode: boolean } {
  if (!label.startsWith("xn--")) return { text: label, punycode: false };
  const decoded = decodePunycode(label.slice(4));
  return decoded ? { text: decoded, punycode: true } : { text: label, punycode: true };
}

function compareLabels(visit: string, saved: string): LookalikeReason | null {
  const { text, punycode } = unicodeLabel(visit);
  if (text === saved) return punycode ? "punycode" : null;
  if (skeleton(text) === skeleton(saved)) return punycode ? "punycode" : "homoglyph";
  if (saved.length < 5) return null;
  const a = skeleton(text); const b = skeleton(saved);
  const distance = editDistance(a, b, 2);
  // Swapped or replaced letters ("githbu", "paypak"). Added or missing letters only for longer
  // names, so different real brands such as gmail/mail are not flagged.
  if (distance === 1 && (a.length === b.length || Math.min(a.length, b.length) >= 7)) return "typo";
  if (distance === 2 && a.length === b.length && saved.length >= 10) return "typo";
  return null;
}

/**
 * Compares the site being visited with the sites saved in the vault.
 * "trusted": the same registrable domain as a saved login. "lookalike": suspiciously similar to one.
 */
export function assessSite(visitUrl: string, savedUrls: Iterable<string | null | undefined>): SiteVerdict {
  const host = hostnameOf(visitUrl);
  if (!host) return { kind: "unknown", domain: null };
  const visit = splitDomain(host);
  const saved = new Map<string, { label: string; suffix: string }>();
  for (const url of savedUrls) {
    const savedHost = hostnameOf(url ?? "");
    if (!savedHost) continue;
    const parts = splitDomain(savedHost);
    if (parts.suffix) saved.set(parts.domain, { label: parts.label, suffix: parts.suffix });
  }
  if (saved.has(visit.domain)) return { kind: "trusted", domain: visit.domain };
  let best: { reason: LookalikeReason; resembles: string; rank: number } | null = null;
  const rank: Record<LookalikeReason, number> = { punycode: 0, homoglyph: 1, subdomain_trick: 2, typo: 3, other_ending: 4 };
  for (const [domain, parts] of saved) {
    let reason: LookalikeReason | null = null;
    if (parts.label.length >= 4 && (host.startsWith(`${domain}.`) || host.includes(`.${domain}.`) || host.startsWith(`${parts.label}-`))) reason = "subdomain_trick";
    else if (visit.label === parts.label && visit.suffix !== parts.suffix && parts.label.length >= 4) reason = "other_ending";
    else reason = compareLabels(visit.label, parts.label);
    if (reason && (!best || rank[reason] < best.rank)) best = { reason, resembles: domain, rank: rank[reason] };
  }
  return best ? { kind: "lookalike", domain: visit.domain, resembles: best.resembles, reason: best.reason } : { kind: "unknown", domain: visit.domain };
}

/** Pairs of saved sites that look alike (one of them may be a phishing copy saved by mistake). */
export function lookalikePairs(entries: { id: string; url?: string | null }[]): { itemId: string; otherId: string; domain: string; resembles: string; reason: LookalikeReason }[] {
  const byDomain = new Map<string, string>();
  for (const entry of entries) {
    const host = hostnameOf(entry.url ?? "");
    if (host) { const domain = splitDomain(host).domain; if (!byDomain.has(domain)) byDomain.set(domain, entry.id); }
  }
  const domains = [...byDomain.keys()];
  const pairs: { itemId: string; otherId: string; domain: string; resembles: string; reason: LookalikeReason }[] = [];
  for (let a = 0; a < domains.length && pairs.length < 200; a += 1) {
    for (let b = a + 1; b < domains.length; b += 1) {
      const left = splitDomain(domains[a]); const right = splitDomain(domains[b]);
      if (left.label === right.label) continue; // same brand, other country ending: common and legitimate
      const reason = compareLabels(left.label, right.label) ?? compareLabels(right.label, left.label);
      if (reason) pairs.push({ itemId: byDomain.get(domains[a])!, otherId: byDomain.get(domains[b])!, domain: domains[a], resembles: domains[b], reason });
    }
  }
  return pairs;
}

export const LOOKALIKE_EXPLANATIONS: Record<LookalikeReason, string> = {
  homoglyph: "uses characters that look like the real name (for example 0 for o, or rn for m)",
  typo: "is one or two letters different from the real name",
  punycode: "uses letters from another alphabet that look identical",
  other_ending: "has the same name with a different ending",
  subdomain_trick: "puts the real name at the start of a different website's address",
};
