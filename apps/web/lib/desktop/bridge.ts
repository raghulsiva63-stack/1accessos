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
};

export type DesktopSettings = {
  lockOnBlur: boolean;
  lockOnHide: boolean;
  hotkeyEnabled: boolean;
  clipboardSeconds: number;
};

export const DEFAULT_DESKTOP_SETTINGS: DesktopSettings = { lockOnBlur: false, lockOnHide: false, hotkeyEnabled: true, clipboardSeconds: 30 };

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

export const desktop = {
  info: () => call<DesktopInfo>("desktop_info"),
  settings: () => call<DesktopSettings>("desktop_settings_get"),
  saveSettings: (settings: DesktopSettings) => call<DesktopSettings>("desktop_settings_set", { settings }),
  copy: (text: string, clearSeconds: number) => call<void>("clipboard_copy", { text, clearSeconds }),
  clearClipboard: () => call<void>("clipboard_clear"),
  hideQuickAccess: () => call<void>("quick_hide"),
  /** Starts the one-shot 127.0.0.1 listener for the browser sign-in; returns its port. */
  listenForSignIn: (state: string) => call<number>("sign_in_listen", { stateToken: state }),
  checkForUpdates: () => call<"none" | "declined" | "unavailable">("update_check"),
  biometric: {
    enrolled: (account: string, fingerprint: string) => call<boolean>("biometric_enrolled", { account, fingerprint }),
    enroll: (account: string, secret: string, fingerprint: string) => call<void>("biometric_enroll", { account, secret, fingerprint }),
    unlock: (account: string, fingerprint: string) => call<string | null>("biometric_unlock", { account, fingerprint }),
    remove: (account: string) => call<void>("biometric_remove", { account }),
  },
};

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
