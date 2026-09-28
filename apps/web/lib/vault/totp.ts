/** RFC 6238 TOTP, computed locally with WebCrypto. Secrets never leave the device. */

export type TotpConfig = {
  secret: Uint8Array;
  digits: number;
  period: number;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  issuer?: string;
  account?: string;
};

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s-]/gu, "").replace(/=+$/u, "");
  if (!clean || /[^A-Z2-7]/u.test(clean)) throw new Error("Invalid base32 secret.");
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    buffer = (buffer << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

function algorithmFrom(value: string | null): TotpConfig["algorithm"] {
  const normalized = (value ?? "SHA1").toUpperCase().replace("-", "");
  if (normalized === "SHA256") return "SHA-256";
  if (normalized === "SHA512") return "SHA-512";
  return "SHA-1";
}

/** Accepts an otpauth://totp/... URI or a bare base32 secret. Returns null when not a usable TOTP seed. */
export function parseTotp(value: string | undefined | null): TotpConfig | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  try {
    if (/^otpauth:\/\//iu.test(trimmed)) {
      const url = new URL(trimmed);
      if (url.hostname.toLowerCase() !== "totp") return null;
      const secret = url.searchParams.get("secret");
      if (!secret) return null;
      const digits = Number(url.searchParams.get("digits") ?? 6);
      const period = Number(url.searchParams.get("period") ?? 30);
      const label = decodeURIComponent(url.pathname.replace(/^\//u, ""));
      const [labelIssuer, account] = label.includes(":") ? label.split(":", 2) : [undefined, label];
      return {
        secret: decodeBase32(secret),
        digits: digits >= 6 && digits <= 8 ? digits : 6,
        period: period >= 10 && period <= 120 ? period : 30,
        algorithm: algorithmFrom(url.searchParams.get("algorithm")),
        issuer: url.searchParams.get("issuer") ?? labelIssuer,
        account: account || undefined,
      };
    }
    const secret = decodeBase32(trimmed);
    if (secret.length < 10) return null;
    return { secret, digits: 6, period: 30, algorithm: "SHA-1" };
  } catch {
    return null;
  }
}

export async function totpCode(config: TotpConfig, nowMs: number): Promise<string> {
  const counter = Math.floor(nowMs / 1000 / config.period);
  const message = new Uint8Array(8);
  let value = counter;
  for (let index = 7; index >= 0; index -= 1) {
    message[index] = value & 0xff;
    value = Math.floor(value / 256);
  }
  const key = await crypto.subtle.importKey("raw", config.secret as BufferSource, { name: "HMAC", hash: config.algorithm }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message as BufferSource));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** config.digits).padStart(config.digits, "0");
}

export function secondsRemaining(config: Pick<TotpConfig, "period">, nowMs: number) {
  return config.period - (Math.floor(nowMs / 1000) % config.period);
}

/** Field names importers and users commonly use for TOTP seeds. */
export function findTotpField(fields: Record<string, string> | undefined): [string, string] | null {
  if (!fields) return null;
  for (const [name, value] of Object.entries(fields)) {
    if (/^(totp|otp|2fa|one[- ]?time|authenticator)/iu.test(name) && parseTotp(value)) return [name, value];
  }
  return null;
}
