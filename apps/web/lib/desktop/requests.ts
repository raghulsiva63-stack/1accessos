// Requests from the desktop app's native side that need the unlocked vault: the auto-type
// shortcut, SSH signature approvals and `pkx` requests. They are listened for from start-up so a
// request that arrives while the vault is locked waits (in memory) until it is unlocked.

import { desktop, isDesktopApp, type AutoTypeTarget, type CliRequest, type SshRequest } from "@/lib/desktop/bridge";

export type AutoTypeEvent = (AutoTypeTarget & { error?: undefined }) | { error: string; token?: undefined; title?: undefined; app?: undefined };
type Stamped<T> = T & { receivedAt: number };

export const LIFETIME = { autoType: 115_000, ssh: 88_000, cli: 118_000 };

let autoType: Stamped<AutoTypeEvent> | null = null;
let ssh: Stamped<SshRequest>[] = [];
let cli: Stamped<CliRequest>[] = [];
let version = 0;
let installed = false;
let vaultOpen = false;
const listeners = new Set<() => void>();

export const requestsVersion = () => version;
export function subscribeRequests(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
const notify = () => { version += 1; listeners.forEach((listener) => listener()); };
const fresh = <T extends { receivedAt: number }>(entry: T | null, lifetime: number, now: number) => entry !== null && now - entry.receivedAt < lifetime;

export function pendingAutoType(now = Date.now()): Stamped<AutoTypeEvent> | null { return autoType && fresh(autoType, LIFETIME.autoType, now) ? autoType : null; }
export function pendingSsh(now = Date.now()): Stamped<SshRequest> | null { return ssh.find((entry) => fresh(entry, LIFETIME.ssh, now)) ?? null; }
export function pendingCli(now = Date.now()): Stamped<CliRequest> | null { return cli.find((entry) => fresh(entry, LIFETIME.cli, now)) ?? null; }

export function finishAutoType() { autoType = null; notify(); }
export function finishSsh(id: string) { ssh = ssh.filter((entry) => entry.id !== id); notify(); }
export function finishCli(id: string) { cli = cli.filter((entry) => entry.id !== id); notify(); }
/** The unlocked vault pages are showing (requests are handled there). */
export function setVaultOpen(open: boolean) { vaultOpen = open; }
export const isVaultOpen = () => vaultOpen;

export function clearRequests() { autoType = null; ssh = []; cli = []; notify(); }

const text = (value: unknown, limit: number) => typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]/gu, "").slice(0, limit) : "";

/** Validates and stores one native event (exported for tests). */
export function receive(type: "auto-type" | "ssh" | "cli", detail: unknown, now = Date.now()) {
  if (!detail || typeof detail !== "object") return;
  const value = detail as Record<string, unknown>;
  if (type === "auto-type") {
    autoType = typeof value.error === "string" ? { error: text(value.error, 40), receivedAt: now }
      : /^[0-9a-f]{24}$/u.test(String(value.token)) ? { token: String(value.token), title: text(value.title, 300), app: text(value.app, 200), receivedAt: now } : null;
  } else if (type === "ssh") {
    if (!/^[0-9a-f]{24}$/u.test(String(value.id))) return;
    ssh = [...ssh.filter((entry) => fresh(entry, LIFETIME.ssh, now)), {
      id: String(value.id), keyId: text(value.keyId, 100), keyName: text(value.keyName, 200), fingerprint: text(value.fingerprint, 80),
      client: text(value.client, 100), locked: value.locked === true, receivedAt: now,
    }].slice(-10);
  } else {
    if (!/^[0-9a-f]{24}$/u.test(String(value.id)) || !Array.isArray(value.refs)) return;
    cli = [...cli.filter((entry) => fresh(entry, LIFETIME.cli, now)), {
      id: String(value.id), refs: value.refs.filter((ref): ref is string => typeof ref === "string").slice(0, 50).map((ref) => text(ref, 300)),
      command: text(value.command, 500), cwd: text(value.cwd, 500), client: text(value.client, 100), receivedAt: now,
    }].slice(-10);
  }
  notify();
}

/** Starts listening (once, desktop app only). */
export function installDesktopRequests() {
  if (installed || typeof window === "undefined" || !isDesktopApp()) return;
  installed = true;
  window.addEventListener("passkey-x:auto-type", (event) => {
    receive("auto-type", (event as CustomEvent).detail);
    // Locked: show the app so the person can unlock; the request waits.
    if (!vaultOpen && pendingAutoType()) void desktop.autoType.present().catch(() => undefined);
  });
  window.addEventListener("passkey-x:ssh-request", (event) => receive("ssh", (event as CustomEvent).detail));
  window.addEventListener("passkey-x:cli-request", (event) => receive("cli", (event as CustomEvent).detail));
}
