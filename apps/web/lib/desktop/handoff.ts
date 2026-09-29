/**
 * Desktop sign-in handoff helpers (pure, no network). Shared by the desktop app, the
 * browser approval page (/desktop-link) and tests.
 *
 * Flow (OAuth-style, RFC 7636 PKCE + RFC 8252 loopback redirect):
 * 1. The app creates a random verifier (kept in memory) and a state, and starts a one-shot
 *    listener on 127.0.0.1:<port>.
 * 2. It opens /desktop-link?challenge=SHA256(verifier)&state=…&port=…&platform=… in the
 *    person's browser. They sign in and choose Allow.
 * 3. The browser is sent to http://127.0.0.1:<port>/callback?code=…&state=… — which only
 *    reaches the app on this same computer — so the code is never shown or copied.
 * 4. The app sends code + verifier to the desktop-session function, which checks them once.
 */

const B64URL = /^[A-Za-z0-9_-]+$/u;
export const CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
export const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
export const STATE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/u;
export const PENDING_LINK_KEY = "px-desktop-link";
const PENDING_TTL_MS = 10 * 60_000;

export type DesktopPlatform = "macos" | "windows" | "linux";
/** Fixed labels only: the approval page never shows text chosen by whoever made the link. */
export const PLATFORM_LABELS: Record<DesktopPlatform, string> = {
  macos: "Passkey-X for Mac",
  windows: "Passkey-X for Windows",
  linux: "Passkey-X for Linux",
};

export function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

export function randomToken(bytes = 32) {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** RFC 7636 S256 challenge. */
export async function challengeFor(verifier: string) {
  if (!B64URL.test(verifier) || verifier.length < 43 || verifier.length > 128) throw new Error("invalid verifier");
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

export type LinkRequest = { challenge: string; state: string; port: number; platform: DesktopPlatform };

function validPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1024 && value <= 65535;
}

function validPlatform(value: unknown): value is DesktopPlatform {
  return value === "macos" || value === "windows" || value === "linux";
}

/** Validates the query string of /desktop-link. */
export function parseLinkRequest(search: string): LinkRequest | null {
  const params = new URLSearchParams(search);
  const challenge = params.get("challenge") ?? "";
  const state = params.get("state") ?? "";
  const portText = params.get("port") ?? "";
  const port = /^\d{4,5}$/u.test(portText) ? Number(portText) : NaN;
  const platform = params.get("platform");
  if (!CHALLENGE_PATTERN.test(challenge) || !STATE_PATTERN.test(state) || !validPort(port) || !validPlatform(platform)) return null;
  return { challenge, state, port, platform };
}

export function signInUrl(origin: string, request: LinkRequest) {
  const params = new URLSearchParams({ challenge: request.challenge, state: request.state, port: String(request.port), platform: request.platform });
  return `${origin.replace(/\/+$/u, "")}/desktop-link/?${params.toString()}`;
}

/** Where the browser sends the approved code: the app's one-shot listener on this computer. */
export function returnUrl(port: number, code: string, state: string) {
  if (!validPort(port) || !CODE_PATTERN.test(code) || !STATE_PATTERN.test(state)) throw new Error("invalid handoff");
  return `http://127.0.0.1:${port}/callback?code=${code}&state=${state}`;
}

/** Fallback when the browser could not reach the app: the person pastes the code. */
export function parsePastedCode(value: string): string | null {
  const text = value.trim();
  return CODE_PATTERN.test(text) ? text : null;
}

/** Remembers an approval request across an SSO redirect in the same browser tab. */
export function pendingLinkValue(request: LinkRequest, now = Date.now()) {
  return JSON.stringify({ ...request, at: now });
}

export function parsePendingLink(raw: string | null, now = Date.now()): LinkRequest | null {
  try {
    const value = JSON.parse(raw ?? "null") as (LinkRequest & { at?: number }) | null;
    if (!value || typeof value.at !== "number" || now - value.at > PENDING_TTL_MS || value.at > now) return null;
    if (!CHALLENGE_PATTERN.test(value.challenge) || !STATE_PATTERN.test(value.state) || !validPort(value.port) || !validPlatform(value.platform)) return null;
    return { challenge: value.challenge, state: value.state, port: value.port, platform: value.platform };
  } catch { return null; }
}
