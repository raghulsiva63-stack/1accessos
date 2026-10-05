// Auto-type (desktop app): the shortcut remembers the window in front, the vault chooses a login
// for it, and the app types it there. Pure logic only — choosing the login and building the keys.
//
// Choosing is deliberately careful, because any program can give its window any title:
// * a login is typed without asking only when the person said "always use this login here"
//   (a remembered choice on this computer) or the item has an "Auto-type window" rule, and
//   exactly one login matches;
// * matches by name are only suggestions in the picker;
// * in browsers the picker always opens with a warning: a page title proves nothing about the
//   site, so the browser extension (which checks the real address) is the safer way there.

import type { VaultItem } from "@/lib/vault/items";
import { findTotpField, parseTotp, totpCode } from "@/lib/vault/totp";
import type { AutoTypeStep, AutoTypeTarget } from "@/lib/desktop/bridge";

export const DEFAULT_SEQUENCE = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
export const WINDOW_FIELD = "Auto-type window";
export const SEQUENCE_FIELD = "Auto-type sequence";
export const APPROVALS_RECORD = "px-autotype-approvals";
const MAX_APPROVALS = 200;

const TYPABLE: ReadonlySet<VaultItem["contentType"]> = new Set(["login", "database", "wifi", "custom-secret", "api-key", "software-license"]);
const BROWSERS = /^(chrome|google chrome|msedge|microsoft edge|firefox|safari|brave|brave browser|opera|vivaldi|arc|chromium|chromium-browser|librewolf|waterfox|tor browser|zen)(\.exe)?$/iu;

/** A remembered "always use this login in this window" choice (kept only on this computer). */
export type Approval = { app: string; title: string; itemId: string; at: string };

export type Candidate = { item: VaultItem; reason: "rule" | "remembered" | "name" | "other" };
export type AutoTypePlan = {
  /** Typed without asking. */
  automatic: VaultItem | null;
  candidates: Candidate[];
  browser: boolean;
};

export function isBrowser(app: string) {
  return BROWSERS.test(app.trim().split(/[\\/]/u).pop() ?? "");
}

/** "*" and "?" wildcards, case-insensitive, whole title. */
export function wildcardMatch(pattern: string, text: string) {
  const trimmed = pattern.trim();
  if (!trimmed || trimmed.length > 300) return false;
  const source = trimmed.replace(/[.+^${}()|[\]\\]/gu, "\\$&").replace(/\*/gu, ".*").replace(/\?/gu, ".");
  return new RegExp(`^${source}$`, "iu").test(text.trim());
}

function windowRules(item: VaultItem): string[] {
  const fields = item.payload.fields ?? {};
  const entry = Object.entries(fields).find(([name]) => name.trim().toLowerCase() === WINDOW_FIELD.toLowerCase());
  return entry ? entry[1].split(/[\n;]/u).map((rule) => rule.trim()).filter(Boolean).slice(0, 20) : [];
}

const normalizeTitle = (title: string) => title.trim().replace(/\s+/gu, " ").toLowerCase();
const normalizeApp = (app: string) => (app.trim().split(/[\\/]/u).pop() ?? "").replace(/\.exe$/iu, "").toLowerCase();

export function sameWindow(approval: Pick<Approval, "app" | "title">, target: Pick<AutoTypeTarget, "app" | "title">) {
  return normalizeApp(approval.app) === normalizeApp(target.app) && normalizeTitle(approval.title) === normalizeTitle(target.title);
}

/** Words of an item that may appear in a window title ("GitHub", "github.com" → "github"). */
function nameHints(item: VaultItem): string[] {
  const hints = new Set<string>();
  const title = item.payload.title.trim().toLowerCase();
  if (title.length >= 3) hints.add(title);
  const url = item.payload.url?.trim();
  if (url) {
    try {
      const host = new URL(/^[a-z][a-z0-9+.-]*:\/\//iu.test(url) ? url : `https://${url}`).hostname.replace(/^www\./u, "");
      const label = host.split(".").filter(Boolean).slice(-2, -1)[0] ?? host;
      if (label.length >= 3) hints.add(label.toLowerCase());
      if (host.includes(".")) hints.add(host.toLowerCase());
    } catch { /* not a URL */ }
  }
  return [...hints];
}

function mentions(title: string, hint: string) {
  const escaped = hint.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}($|[^\\p{L}\\p{N}])`, "iu").test(title);
}

export function typable(item: VaultItem) {
  return TYPABLE.has(item.contentType) && !item.deletedAt && !item.payload.archived && Boolean(item.payload.secret || item.payload.username);
}

export function planAutoType(items: VaultItem[], target: Pick<AutoTypeTarget, "app" | "title">, approvals: Approval[] = []): AutoTypePlan {
  const browser = isBrowser(target.app);
  const pool = items.filter(typable);
  const ruled = pool.filter((item) => windowRules(item).some((rule) => wildcardMatch(rule, target.title)));
  const rememberedIds = new Set(approvals.filter((approval) => sameWindow(approval, target)).map((approval) => approval.itemId));
  const remembered = pool.filter((item) => rememberedIds.has(item.id) && !ruled.includes(item));
  const strong = new Set([...ruled, ...remembered]);
  const named = pool.filter((item) => !strong.has(item) && nameHints(item).some((hint) => mentions(target.title, hint)));
  const candidates: Candidate[] = [
    ...ruled.map((item) => ({ item, reason: "rule" as const })),
    ...remembered.map((item) => ({ item, reason: "remembered" as const })),
    ...named.map((item) => ({ item, reason: "name" as const })),
  ];
  const automatic = !browser && strong.size === 1 ? [...strong][0] : null;
  return { automatic, candidates, browser };
}

/** Adds (or moves to the front) a remembered choice; one login per window. */
export function rememberApproval(approvals: Approval[], target: Pick<AutoTypeTarget, "app" | "title">, itemId: string, now = new Date()): Approval[] {
  const rest = approvals.filter((approval) => !sameWindow(approval, target));
  return [{ app: normalizeApp(target.app), title: target.title.trim().slice(0, 300), itemId, at: now.toISOString() }, ...rest].slice(0, MAX_APPROVALS);
}

export function parseApprovals(text: string | null): Approval[] {
  try {
    const value = JSON.parse(text ?? "[]") as unknown;
    if (!Array.isArray(value)) return [];
    return value.filter((entry): entry is Approval => Boolean(entry) && typeof entry.app === "string" && typeof entry.title === "string" && typeof entry.itemId === "string" && typeof entry.at === "string").slice(0, MAX_APPROVALS);
  } catch { return []; }
}

// ---------------------------------------------------------------------------
// Sequences: {USERNAME}{TAB}{PASSWORD}{ENTER}, {TOTP}, {URL}, {DELAY 500}, {S:Field name}
// ---------------------------------------------------------------------------

export type SequenceToken =
  | { kind: "text"; value: string }
  | { kind: "username" | "password" | "totp" | "url" | "tab" | "enter" }
  | { kind: "delay"; ms: number }
  | { kind: "field"; name: string };

export function parseSequence(sequence: string): SequenceToken[] | null {
  const tokens: SequenceToken[] = [];
  let index = 0;
  while (index < sequence.length) {
    const open = sequence.indexOf("{", index);
    if (open === -1) { tokens.push({ kind: "text", value: sequence.slice(index) }); break; }
    if (open > index) tokens.push({ kind: "text", value: sequence.slice(index, open) });
    const close = sequence.indexOf("}", open);
    if (close === -1) return null;
    const body = sequence.slice(open + 1, close).trim();
    const upper = body.toUpperCase();
    const delay = /^DELAY\s*[ =]\s*(\d{1,4})$/iu.exec(body);
    if (upper === "USERNAME" || upper === "USER") tokens.push({ kind: "username" });
    else if (upper === "PASSWORD") tokens.push({ kind: "password" });
    else if (upper === "TOTP" || upper === "OTP") tokens.push({ kind: "totp" });
    else if (upper === "URL") tokens.push({ kind: "url" });
    else if (upper === "TAB") tokens.push({ kind: "tab" });
    else if (upper === "ENTER") tokens.push({ kind: "enter" });
    else if (delay) tokens.push({ kind: "delay", ms: Math.min(5000, Number(delay[1])) });
    else if (/^S:/iu.test(body) && body.length > 2) tokens.push({ kind: "field", name: body.slice(2).trim() });
    else return null;
    index = close + 1;
  }
  return tokens.length && tokens.length <= 40 ? tokens : null;
}

export function itemSequence(item: VaultItem): string {
  const fields = item.payload.fields ?? {};
  const custom = Object.entries(fields).find(([name]) => name.trim().toLowerCase() === SEQUENCE_FIELD.toLowerCase())?.[1];
  if (custom && parseSequence(custom)) return custom;
  return item.payload.username ? DEFAULT_SEQUENCE : "{PASSWORD}{ENTER}";
}

export class AutoTypeError extends Error {}

function clean(value: string) {
  // Line breaks would press Enter; other control characters are not typable.
  return value.replace(/[\u0000-\u001f\u007f]/gu, "");
}

/** The keys to send. Throws AutoTypeError when the sequence uses something the item lacks. */
export async function buildSteps(item: VaultItem, sequence = itemSequence(item), nowMs = Date.now()): Promise<AutoTypeStep[]> {
  const tokens = parseSequence(sequence);
  if (!tokens) throw new AutoTypeError("The auto-type sequence isn't valid.");
  const steps: AutoTypeStep[] = [];
  const text = (value: string) => {
    const cleaned = clean(value);
    if (!cleaned) return;
    const last = steps[steps.length - 1];
    if (last?.type === "text" && last.value.length + cleaned.length <= 4096) last.value += cleaned;
    else steps.push({ type: "text", value: cleaned.slice(0, 4096) });
  };
  for (const token of tokens) {
    switch (token.kind) {
      case "text": text(token.value); break;
      case "username": text(item.payload.username ?? ""); break;
      case "password":
        if (!item.payload.secret) throw new AutoTypeError("This item has no password.");
        text(item.payload.secret); break;
      case "url": text(item.payload.url ?? ""); break;
      case "totp": {
        const seed = findTotpField(item.payload.fields)?.[1];
        const config = parseTotp(seed);
        if (!config) throw new AutoTypeError("This item has no authenticator code.");
        text(await totpCode(config, nowMs)); break;
      }
      case "field": {
        const value = Object.entries(item.payload.fields ?? {}).find(([name]) => name.toLowerCase() === token.name.toLowerCase())?.[1];
        if (value === undefined) throw new AutoTypeError(`This item has no field “${token.name}”.`);
        text(value); break;
      }
      case "tab": steps.push({ type: "key", key: "tab" }); break;
      case "enter": steps.push({ type: "key", key: "enter" }); break;
      case "delay": steps.push({ type: "delay", ms: token.ms }); break;
    }
  }
  if (!steps.length) throw new AutoTypeError("There is nothing to type.");
  return steps.slice(0, 40);
}

/** Wipes typed text from memory once it was sent (best effort; strings are immutable in JS). */
export function forgetSteps(steps: AutoTypeStep[]) {
  for (const step of steps) if (step.type === "text") step.value = "";
  steps.length = 0;
}

export function autoTypeErrorMessage(code: string): string {
  switch (code) {
    case "target_changed": return "Typing stopped because another window came to the front.";
    case "expired": return "The auto-type request expired. Press the shortcut again.";
    case "no_window": return "No window was in front when you pressed the shortcut.";
    case "accessibility": case "accessibility_required": return "Allow Passkey-X in System Settings › Privacy & Security › Accessibility, then try again.";
    case "xdotool": case "xdotool_required": return "Install xdotool to use auto-type on Linux (for example: sudo apt install xdotool).";
    case "wayland": case "wayland_unsupported": return "Auto-type works in X11 sessions only. On Wayland, use copy and paste instead.";
    case "typing_blocked": return "The system blocked typing into that window (it may run as administrator).";
    case "disabled": return "Auto-type is turned off in Settings › This computer.";
    default: return "Auto-type didn't work. Try again, or copy and paste instead.";
  }
}
