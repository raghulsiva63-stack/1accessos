import type { BrowserProtection, Posture, Program } from "@/lib/security/endpoint-guard";

/**
 * Bridge to the Passkey-X desktop app (Tauri). Every call goes to a fixed list of native
 * commands that the app only exposes to its own bundled pages; websites cannot reach them.
 * In a normal browser `isDesktopApp()` is false and nothing here is used.
 */

type TauriInternals = { invoke: <T>(command: string, args?: Record<string, unknown>) => Promise<T> };

export type DesktopInfo = {
  version: string;
  os: "macos" | "windows" | "linux";
  /** Fingerprint/face unlock available on this computer. */
  biometric: "touch-id" | "windows-hello" | null;
  /** Session is kept in the system keychain (otherwise only in memory). */
  secureStorage: boolean;
  hotkey: string | null;
  hotkeyActive: boolean;
  updater: boolean;
  contentProtection: boolean;
  /** Settings are enforced by the organization's IT on this computer. */
  managed: boolean;
  organizationName: string | null;
};

/** Settings an organization enforces on this computer (empty when it is not managed). */
export type DesktopPolicy = {
  managed: boolean;
  source: string | null;
  organizationName: string | null;
  supportUrl: string | null;
  allowedEmailDomains: string[];
  lockOnBlur: boolean | null;
  lockOnHide: boolean | null;
  hotkeyEnabled: boolean | null;
  maxClipboardSeconds: number | null;
  idleLockMinutes: number | null;
  disableBiometric: boolean;
  disableUpdates: boolean;
  autoStart: boolean | null;
  offlineAccess: boolean | null;
  browserIntegration: boolean | null;
  extensionIds: string[];
  autoType: boolean | null;
  sshAgent: boolean | null;
  commandLine: boolean | null;
  downloadProtection: boolean | null;
};

export const UNMANAGED_POLICY: DesktopPolicy = {
  managed: false, source: null, organizationName: null, supportUrl: null, allowedEmailDomains: [], lockOnBlur: null, lockOnHide: null,
  hotkeyEnabled: null, maxClipboardSeconds: null, idleLockMinutes: null, disableBiometric: false, disableUpdates: false, autoStart: null,
  offlineAccess: null, browserIntegration: null, extensionIds: [], autoType: null, sshAgent: null, commandLine: null, downloadProtection: null,
};

/** True when this email may sign in on a computer with this policy. */
export function policyAllowsEmail(policy: Pick<DesktopPolicy, "allowedEmailDomains">, email: string | null | undefined) {
  if (!policy.allowedEmailDomains.length) return true;
  const domain = (email ?? "").split("@").pop()?.trim().toLowerCase() ?? "";
  return Boolean(email?.includes("@")) && policy.allowedEmailDomains.includes(domain);
}

export type DesktopSettings = {
  lockOnBlur: boolean;
  lockOnHide: boolean;
  hotkeyEnabled: boolean;
  clipboardSeconds: number;
  /** Start hidden in the tray when signing in to the computer. */
  autoStart: boolean;
  /** Keep an encrypted copy of the vault for use without internet. */
  offlineAccess: boolean;
  /** Let the Passkey-X browser extension pair with this app. */
  browserIntegration: boolean;
  /** Auto-type shortcut: type a login into any program. */
  autoType: boolean;
  /** Serve the vault's SSH keys through the Passkey-X SSH agent. */
  sshAgent: boolean;
  /** Answer the `pkx` command-line tool (each request is approved). */
  commandLine: boolean;
  /** Check new files in the Downloads folder. */
  downloadProtection: boolean;
  /** Hide passwords automatically while the screen is shared or recorded. */
  presentationAuto: boolean;
};

export const DEFAULT_DESKTOP_SETTINGS: DesktopSettings = {
  lockOnBlur: false, lockOnHide: false, hotkeyEnabled: true, clipboardSeconds: 30, autoStart: false, offlineAccess: true, browserIntegration: false,
  autoType: true, sshAgent: false, commandLine: false, downloadProtection: true, presentationAuto: true,
};

/** One auto-type step; text is typed as characters, keys are Tab and Enter only. */
export type AutoTypeStep = { type: "text"; value: string } | { type: "key"; key: "tab" | "enter" } | { type: "delay"; ms: number };
export type AutoTypeTarget = { token: string; title: string; app: string };
export type AutoTypeInfo = { enabled: boolean; active: boolean; shortcut: string; requirement: "" | "accessibility" | "xdotool" | "wayland" };
export type SshKeyStatus = { id: string; name: string; publicKey: string; fingerprint: string; unlocked: boolean };
export type SshAgentStatus = { enabled: boolean; running: boolean; endpoint: string | null; keys: SshKeyStatus[] };
export type SshLoadResult = { id: string; ok: boolean; publicKey?: string; fingerprint?: string; error?: string };
export type SshRequest = { id: string; keyId: string; keyName: string; fingerprint: string; client: string; locked: boolean };
export type CliRequest = { id: string; refs: string[]; command: string; cwd: string; client: string };
export type CliInfo = { enabled: boolean; endpoint: boolean; path: string | null; installed: boolean; onPath: boolean };
export type DownloadFile = { path: string; name: string; size: number; modifiedMs: number; sha256: string | null; sourceUrl: string | null; referrerUrl: string | null };
export type Presentation = { sharing: boolean; reasons: string[] };
export type SprawlFinding = { path: string; line: number; rule: string; label: string; severity: "critical" | "high" | "medium" | "low"; preview: string };
export type SprawlReport = { findings: SprawlFinding[]; filesScanned: number; roots: string[]; truncated: boolean };

function internals(): TauriInternals | null {
  if (typeof window === "undefined") return null;
  const value = (window as unknown as { __TAURI_INTERNALS__?: TauriInternals }).__TAURI_INTERNALS__;
  return value && typeof value.invoke === "function" ? value : null;
}

/** True only inside the bundled desktop app (its own local origin), never on passkey-x.com. */
export function isDesktopApp() {
  if (typeof window === "undefined" || !internals()) return false;
  return window.location.protocol === "tauri:" || window.location.hostname === "tauri.localhost";
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const bridge = internals();
  if (!bridge || !isDesktopApp()) throw new Error("desktop_unavailable");
  return bridge.invoke<T>(command, args);
}

export const WEB_ORIGIN = "https://passkey-x.com";

/** Origin for links people share (invites, Secure Send, referrals). The desktop app's own origin is local. */
export function shareOrigin() {
  return isDesktopApp() ? WEB_ORIGIN : window.location.origin;
}

/** Absolute URL for passkey-x.com routes (the desktop app's own origin is local). */
export function webUrl(path: string) {
  return isDesktopApp() ? `${WEB_ORIGIN}${path}` : path;
}

export type GuardAlert = { level: "dangerous" | "suspicious"; title: string; detail: string; site: string };

export const desktop = {
  info: () => call<DesktopInfo>("desktop_info"),
  policy: () => call<DesktopPolicy>("desktop_policy"),
  settings: () => call<DesktopSettings>("desktop_settings_get"),
  saveSettings: (settings: DesktopSettings) => call<DesktopSettings>("desktop_settings_set", { settings }),
  copy: (text: string, clearSeconds: number) => call<void>("clipboard_copy", { text, clearSeconds }),
  clearClipboard: () => call<void>("clipboard_clear"),
  hideQuickAccess: () => call<void>("quick_hide"),
  /** Starts the one-shot 127.0.0.1 listener for the browser sign-in; returns its port. */
  listenForSignIn: (state: string) => call<number>("sign_in_listen", { stateToken: state }),
  checkForUpdates: () => call<"none" | "declined" | "unavailable" | "managed">("update_check"),
  /** Replies to the browser extension on a relay connection. */
  browserLinkSend: (connection: number, message: Record<string, unknown>) => call<void>("browser_link_send", { connection, message }),
  /** App records kept in the encrypted session store (keys start with "px-"). */
  record: {
    get: (key: string) => call<string | null>("secure_get", { key }),
    set: (key: string, value: string) => call<void>("secure_set", { key, value }),
    remove: (key: string) => call<void>("secure_remove", { key }),
  },
  /** Endpoint Guard: facts about this computer (the software list never leaves it). */
  endpoint: {
    programs: () => call<Program[]>("endpoint_inventory"),
    posture: () => call<Posture>("endpoint_posture"),
    browsers: () => call<BrowserProtection[]>("endpoint_browsers"),
    /** Shows the always-on-top emergency alert window. */
    alert: (alert: GuardAlert) => call<void>("guard_alert", { alert }),
  },
  /** Only from the alert window. */
  alertWindow: {
    dismiss: () => call<void>("alert_dismiss"),
    openMain: () => call<void>("alert_open_main"),
  },
  autoType: {
    info: () => call<AutoTypeInfo>("auto_type_info"),
    /** Shows the compact picker on top of other windows. */
    present: () => call<void>("auto_type_present"),
    perform: (token: string, steps: AutoTypeStep[]) => call<void>("auto_type_perform", { token, steps }),
  },
  ssh: {
    load: (keys: { id: string; name: string; privateKey: string }[]) => call<SshLoadResult[]>("ssh_agent_load", { keys }),
    status: () => call<SshAgentStatus>("ssh_agent_status"),
    reply: (id: string, allow: boolean, rememberMinutes: number) => call<void>("ssh_agent_reply", { id, allow, rememberMinutes }),
    forget: () => call<void>("ssh_agent_forget"),
    generate: (seed: string, comment: string) => call<{ privateKey: string; publicKey: string; fingerprint: string }>("ssh_key_generate", { seed, comment }),
    inspect: (privateKey: string) => call<{ publicKey: string; fingerprint: string; comment: string }>("ssh_key_inspect", { privateKey }),
  },
  cli: {
    info: () => call<CliInfo>("cli_info"),
    reply: (id: string, answer: { values: Record<string, string> } | { error: string }) => call<void>("cli_reply", { id, answer }),
    installPath: () => call<void>("cli_install_path"),
  },
  downloads: {
    recent: (sinceMs: number) => call<DownloadFile[]>("downloads_recent", { sinceMs }),
    quarantine: (path: string) => call<string>("download_quarantine", { path }),
  },
  presentation: () => call<Presentation>("presentation_check"),
  sprawl: {
    scan: (roots?: string[]) => call<SprawlReport>("sprawl_scan", { roots: roots ?? null }),
    extract: (path: string, line: number, rule: string) => call<string>("sprawl_extract", { path, line, rule }),
    readExport: (path: string) => call<string>("sprawl_read_export", { path }),
    trash: (path: string) => call<void>("sprawl_trash", { path }),
  },
  /** Shows a file in Finder / Explorer (files in the home folder only). */
  revealPath: (path: string) => call<void>("reveal_path", { path }),
  biometric: {
    enrolled: (account: string, fingerprint: string) => call<boolean>("biometric_enrolled", { account, fingerprint }),
    enroll: (account: string, secret: string, fingerprint: string) => call<void>("biometric_enroll", { account, secret, fingerprint }),
    unlock: (account: string, fingerprint: string) => call<string | null>("biometric_unlock", { account, fingerprint }),
    remove: (account: string) => call<void>("biometric_remove", { account }),
  },
};

let policyRequest: Promise<DesktopPolicy> | null = null;
/** The organization policy for this computer (cached; unmanaged outside the desktop app). */
export function desktopPolicy(): Promise<DesktopPolicy> {
  if (!isDesktopApp()) return Promise.resolve(UNMANAGED_POLICY);
  policyRequest ??= desktop.policy().catch(() => UNMANAGED_POLICY);
  return policyRequest;
}

/**
 * Supabase auth storage backed by the system keychain (macOS Keychain, Windows Credential
 * Manager, Linux Secret Service) through the app. Keys are limited to Supabase's own names.
 * If the keychain is unavailable the session lives in memory and ends when the app quits.
 */
export function desktopAuthStorage() {
  const memory = new Map<string, string>();
  const allowed = (key: string) => /^sb-[a-z0-9-]{1,80}$/u.test(key);
  return {
    async getItem(key: string) {
      if (!allowed(key)) return null;
      try { return (await call<string | null>("secure_get", { key })) ?? memory.get(key) ?? null; }
      catch { return memory.get(key) ?? null; }
    },
    async setItem(key: string, value: string) {
      if (!allowed(key)) return;
      memory.set(key, value);
      try { await call<void>("secure_set", { key, value }); } catch { /* memory only */ }
    },
    async removeItem(key: string) {
      memory.delete(key);
      if (!allowed(key)) return;
      try { await call<void>("secure_remove", { key }); } catch { /* nothing stored */ }
    },
  };
}

/** A stable fingerprint of the wrapped vault key, so biometric unlock stops working after the vault password changes. */
export async function profileFingerprint(wrappedRoot: string, salt: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`passkey-x:desktop-unlock:v1:${salt}:${wrappedRoot}`));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function biometricLabel(kind: DesktopInfo["biometric"]) {
  return kind === "touch-id" ? "Touch ID" : kind === "windows-hello" ? "Windows Hello" : "";
}
