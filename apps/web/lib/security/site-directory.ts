// Which websites support two-step verification and passkeys, from the public 2fa.directory
// data (served and cached by passkey-x.com/api/security/site-directory). The whole list is
// downloaded; matching happens on the device, so the server never learns which sites you use.

import type { VaultItem } from "@/lib/vault/items";
import { hostnameOf, splitDomain } from "./domains";

export const SITE_FLAGS = { totp: 1, sms: 2, securityKey: 4, passkeySignIn: 8, passkeyTwoStep: 16 } as const;

/** domain → [flags, documentation URL] */
export type SiteDirectory = { generatedAt: string; sites: Record<string, [number, string?]> };

const DOMAIN = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/u;

function docUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try { const url = new URL(value); return url.protocol === "https:" && value.length <= 300 ? url.href : undefined; } catch { return undefined; }
}

function add(sites: SiteDirectory["sites"], domain: unknown, flags: number, docs?: string) {
  if (typeof domain !== "string") return;
  const key = domain.trim().toLowerCase().replace(/^www\./u, "");
  if (!DOMAIN.test(key) || key.length > 253 || flags === 0) return;
  const current = sites[key];
  sites[key] = current ? [current[0] | flags, current[1] ?? docs] : docs ? [flags, docs] : [flags];
}

/** 2fa.directory v3 "tfa" data: [[name, { domain, tfa: [...], documentation, "additional-domains" }], ...] or a keyed object. */
export function normalizeTwoFactorDirectory(raw: unknown, sites: SiteDirectory["sites"] = {}): SiteDirectory["sites"] {
  const entries: unknown[] = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? Object.entries(raw as Record<string, unknown>) : [];
  for (const entry of entries.slice(0, 20_000)) {
    const info = (Array.isArray(entry) ? entry[1] : entry) as Record<string, unknown> | null;
    if (!info || typeof info !== "object") continue;
    const methods = Array.isArray(info.tfa) ? info.tfa.map(String) : [];
    let flags = 0;
    if (methods.some((method) => method === "totp" || method === "custom-software")) flags |= SITE_FLAGS.totp;
    if (methods.some((method) => method === "sms" || method === "call" || method === "email")) flags |= SITE_FLAGS.sms;
    if (methods.some((method) => method === "u2f" || method === "custom-hardware")) flags |= SITE_FLAGS.securityKey;
    const docs = docUrl(info.documentation);
    add(sites, info.domain, flags, docs);
    if (Array.isArray(info["additional-domains"])) for (const extra of info["additional-domains"].slice(0, 20)) add(sites, extra, flags, docs);
  }
  return sites;
}

/** passkeys.directory data: { "example.com": { passwordless, mfa, documentation } } or an array of such objects with a domain. */
export function normalizePasskeyDirectory(raw: unknown, sites: SiteDirectory["sites"] = {}): SiteDirectory["sites"] {
  const entries: [unknown, Record<string, unknown>][] = Array.isArray(raw)
    ? raw.flatMap((entry) => (Array.isArray(entry) ? [[entry[1] && (entry[1] as Record<string, unknown>).domain, entry[1] as Record<string, unknown>]] : entry && typeof entry === "object" ? [[(entry as Record<string, unknown>).domain, entry as Record<string, unknown>]] : []) as [unknown, Record<string, unknown>][])
    : raw && typeof raw === "object" ? Object.entries(raw as Record<string, Record<string, unknown>>).map(([domain, info]) => [info?.domain ?? domain, info] as [unknown, Record<string, unknown>]) : [];
  for (const [domain, info] of entries.slice(0, 20_000)) {
    if (!info || typeof info !== "object") continue;
    let flags = 0;
    if (info.passwordless && info.passwordless !== "unsupported") flags |= SITE_FLAGS.passkeySignIn;
    if (info.mfa && info.mfa !== "unsupported") flags |= SITE_FLAGS.passkeyTwoStep;
    add(sites, domain, flags, docUrl(info.documentation));
  }
  return sites;
}

export function lookupSite(directory: SiteDirectory | null, url: string | null | undefined): { flags: number; docs?: string } | null {
  if (!directory) return null;
  const host = hostnameOf(url ?? "");
  if (!host) return null;
  const hit = directory.sites[host] ?? directory.sites[splitDomain(host).domain];
  return hit ? { flags: hit[0], docs: hit[1] } : null;
}

function hasStoredTwoStep(item: VaultItem) {
  return Object.entries(item.payload.fields ?? {}).some(([key, value]) => /totp|otp|2fa|mfa|authenticator/iu.test(key) && Boolean(value?.trim()));
}

export type UpgradeSuggestion = {
  itemId: string;
  title: string;
  domain: string;
  /** The site offers an authenticator app / security key and no 2FA code is stored. */
  twoStep: boolean;
  /** The site supports passkey sign-in and there is no passkey for it in the vault. */
  passkey: boolean;
  docs?: string;
};

export function upgradeSuggestions(items: VaultItem[], directory: SiteDirectory | null): UpgradeSuggestion[] {
  if (!directory) return [];
  const active = items.filter((item) => !item.deletedAt && !item.payload.archived);
  const passkeyDomains = new Set(active.filter((item) => item.contentType === "passkey")
    .map((item) => hostnameOf(item.payload.url ?? "")).filter((host): host is string => Boolean(host)).map((host) => splitDomain(host).domain));
  const result: UpgradeSuggestion[] = [];
  const seen = new Set<string>();
  for (const item of active) {
    if (item.contentType !== "login" || !item.payload.url) continue;
    const host = hostnameOf(item.payload.url);
    if (!host) continue;
    const hit = lookupSite(directory, item.payload.url);
    if (!hit) continue;
    const domain = splitDomain(host).domain;
    const twoStep = (hit.flags & (SITE_FLAGS.totp | SITE_FLAGS.securityKey)) !== 0 && !hasStoredTwoStep(item);
    const passkey = (hit.flags & SITE_FLAGS.passkeySignIn) !== 0 && !passkeyDomains.has(domain);
    if ((twoStep || passkey) && !seen.has(`${domain}:${item.payload.username ?? ""}`)) {
      seen.add(`${domain}:${item.payload.username ?? ""}`);
      result.push({ itemId: item.id, title: item.payload.title, domain, twoStep, passkey, docs: hit.docs });
    }
  }
  return result.sort((a, b) => Number(b.passkey) - Number(a.passkey) || a.title.localeCompare(b.title));
}
