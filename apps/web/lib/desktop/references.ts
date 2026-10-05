// Secret references for the `pkx` command-line tool: px://<item>/<field> or px://<vault>/<item>/<field>.
// Items are matched by name (case-insensitive) or id; fields are password, username, url, notes,
// totp, or the name of a custom field. A request is answered all-or-nothing.

import type { VaultItem } from "@/lib/vault/items";
import { findTotpField, parseTotp, totpCode } from "@/lib/vault/totp";

export type Reference = { vault: string | null; item: string; field: string };
export type ReferenceSource = { vaultName: string; items: VaultItem[] };
export type ResolveResult = { values: Record<string, string> } | { error: "not_found" | "ambiguous" | "invalid_reference"; reference?: string };

export function parseReference(value: string): Reference | null {
  if (typeof value !== "string" || value.length > 300 || !value.startsWith("px://")) return null;
  const parts = value.slice(5).split("/");
  if (parts.length < 2 || parts.length > 3 || parts.some((part) => !part.trim())) return null;
  let decoded: string[];
  try { decoded = parts.map((part) => decodeURIComponent(part).trim()); } catch { return null; }
  return decoded.length === 3 ? { vault: decoded[0], item: decoded[1], field: decoded[2] } : { vault: null, item: decoded[0], field: decoded[1] };
}

const same = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "accent" }) === 0;

function findItems(reference: Reference, sources: ReferenceSource[]): VaultItem[] {
  const pool = sources.filter((source) => !reference.vault || same(source.vaultName, reference.vault));
  const live = pool.flatMap((source) => source.items.filter((item) => !item.deletedAt));
  const byId = live.filter((item) => item.id === reference.item);
  return byId.length ? byId : live.filter((item) => same(item.payload.title.trim(), reference.item));
}

async function fieldValue(item: VaultItem, field: string, nowMs: number): Promise<string | null> {
  const name = field.toLowerCase();
  const payload = item.payload;
  if (name === "password" || name === "secret") return payload.secret ?? null;
  if (name === "username") return payload.username ?? null;
  if (name === "url") return payload.url ?? null;
  if (name === "notes") return payload.notes ?? null;
  if (name === "totp" || name === "otp") {
    const config = parseTotp(findTotpField(payload.fields)?.[1]);
    return config ? totpCode(config, nowMs) : null;
  }
  const custom = Object.entries(payload.fields ?? {}).find(([key]) => same(key, field));
  return custom ? custom[1] : null;
}

export async function resolveReferences(refs: string[], sources: ReferenceSource[], nowMs = Date.now()): Promise<ResolveResult> {
  const values: Record<string, string> = {};
  for (const ref of refs) {
    const reference = parseReference(ref);
    if (!reference) return { error: "invalid_reference", reference: ref };
    const matches = findItems(reference, sources);
    if (matches.length > 1) return { error: "ambiguous", reference: ref };
    const value = matches[0] ? await fieldValue(matches[0], reference.field, nowMs) : null;
    if (value === null) return { error: "not_found", reference: ref };
    values[ref] = value;
  }
  return { values };
}

/** The items a request touches (for the approval dialog), without reading any secret. */
export function describeReferences(refs: string[], sources: ReferenceSource[]): { reference: string; label: string; found: boolean }[] {
  return refs.map((ref) => {
    const reference = parseReference(ref);
    if (!reference) return { reference: ref, label: ref, found: false };
    const matches = findItems(reference, sources);
    return { reference: ref, label: matches.length === 1 ? `${matches[0].payload.title} · ${reference.field}` : ref, found: matches.length === 1 };
  });
}

/** A reference for an item in a vault, quoted for URLs ("/" and "%" are encoded). */
export function referenceFor(vaultName: string, title: string, field: string) {
  const part = (value: string) => encodeURIComponent(value.trim()).replace(/%20/gu, " ");
  return `px://${part(vaultName)}/${part(title)}/${part(field)}`;
}
