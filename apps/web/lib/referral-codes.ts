/** Pure helpers for referral codes (no network), shared by the app and tests. */

/** Invite codes avoid look-alike characters (no 0, O, 1 or I). */
const CODE = /^[A-HJ-NP-Z2-9]{8}$/u;
export const REFERRAL_STORAGE_KEY = "px-referral";
const KEEP_DAYS = 30;

export type ReferralSummary = {
  code: string;
  joined: number;
  paid: number;
  rewarded: number;
  credits: Partial<Record<"inr" | "usd", number>>;
  referred: boolean;
};

export type ClaimStatus = "claimed" | "invalid_code" | "self" | "already_referred" | "too_late" | "already_paying";

export function normalizeReferralCode(value: string | null | undefined): string | null {
  const code = (value ?? "").trim().toUpperCase();
  return CODE.test(code) ? code : null;
}

export function referralLink(origin: string, code: string) {
  return `${origin.replace(/\/+$/u, "")}/?ref=${encodeURIComponent(code)}`;
}

/** Stored as {code, at}; ignored after 30 days so an old visit does not claim much later. */
export function parseStoredReferral(raw: string | null, now = Date.now()): string | null {
  try {
    const parsed = JSON.parse(raw ?? "null") as { code?: unknown; at?: unknown } | null;
    if (!parsed || typeof parsed.at !== "number" || now - parsed.at > KEEP_DAYS * 86_400_000) return null;
    return normalizeReferralCode(typeof parsed.code === "string" ? parsed.code : null);
  } catch { return null; }
}

export function storedReferralValue(code: string, now = Date.now()) {
  return JSON.stringify({ code, at: now });
}

export function claimMessage(status: ClaimStatus): string | null {
  switch (status) {
    case "claimed": return "Your friend's invitation is applied: your first paid plan starts with a 30-day free trial.";
    case "already_paying": return "Invitation codes are for new accounts that have not paid for a plan yet.";
    case "too_late": return "Invitation codes must be used within 14 days of creating your account.";
    default: return null;
  }
}
