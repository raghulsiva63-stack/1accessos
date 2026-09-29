"use client";

import { useEffect } from "react";
import { normalizeReferralCode, REFERRAL_STORAGE_KEY, storedReferralValue } from "@/lib/referral-codes";

/** Remembers an invite code from a ?ref= link until the visitor signs in and opens their vault. */
export function ReferralCapture() {
  useEffect(() => {
    const code = normalizeReferralCode(new URLSearchParams(window.location.search).get("ref"));
    if (!code) return;
    try { window.localStorage.setItem(REFERRAL_STORAGE_KEY, storedReferralValue(code)); } catch { /* storage blocked: the code is simply not remembered */ }
  }, []);
  return null;
}
