"use client";

import { useEffect, useState } from "react";
import { Copy, Gift, Share2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { formatPrice } from "@/lib/billing/nudges";
import {
  claimMessage, parseStoredReferral, REFERRAL_STORAGE_KEY, referralLink, type ReferralSummary,
} from "@/lib/referral-codes";
import { claimReferral, loadReferralSummary } from "@/lib/referrals";

/**
 * Home card: "Give a month, get a month". First applies an invite code this person arrived
 * with (remembered by ReferralCapture), then shows their own invite link and progress.
 */
export function ReferralCard() {
  const [summary, setSummary] = useState<ReferralSummary | null>(null);
  const [notice, setNotice] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    async function run() {
      let pending: string | null = null;
      try { pending = parseStoredReferral(window.localStorage.getItem(REFERRAL_STORAGE_KEY)); } catch { pending = null; }
      if (pending) {
        try {
          const status = await claimReferral(pending);
          try { window.localStorage.removeItem(REFERRAL_STORAGE_KEY); } catch { /* ignore */ }
          const text = claimMessage(status);
          if (active && text) setNotice(text);
        } catch { /* network problem: keep the code and try again next time */ }
      }
      try { const next = await loadReferralSummary(); if (active) setSummary(next); } catch { /* card stays hidden */ }
    }
    void run();
    return () => { active = false; };
  }, []);

  if (!summary) return notice ? <section className="referral-card"><span className="referral-icon"><Gift /></span><div><h3>Invitation applied</h3><p>{notice}</p></div></section> : null;

  const link = referralLink(window.location.origin, summary.code);
  const credits = Object.entries(summary.credits).filter(([, amount]) => (amount ?? 0) > 0)
    .map(([currency, amount]) => formatPrice(amount ?? 0, currency as "inr" | "usd")).join(" + ");

  async function copy() {
    try { await navigator.clipboard.writeText(link); setCopied(true); window.setTimeout(() => setCopied(false), 2_500); }
    catch { setCopied(false); }
  }
  async function share() {
    try { await navigator.share({ title: "Passkey-X", text: "I use Passkey-X to keep my passwords safe. Join with my link and your first month is free.", url: link }); }
    catch { await copy(); }
  }

  return <section className="referral-card" aria-labelledby="referral-title">
    <span className="referral-icon"><Gift /></span>
    <div className="referral-body">
      <h3 id="referral-title">Give a month, get a month</h3>
      <p>Invite a friend. They get a 30-day free trial, and when they start paying you get one month of your plan free — added as credit to your next bill.</p>
      {notice && <p className="form-message" role="status">{notice}</p>}
      <div className="referral-link"><code>{link}</code><Button size="sm" variant="outline" onClick={() => void copy()}><Copy /> {copied ? "Copied" : "Copy link"}</Button>{typeof navigator !== "undefined" && "share" in navigator && <Button size="sm" variant="ghost" onClick={() => void share()}><Share2 /> Share</Button>}</div>
      <p className="referral-stats"><strong>{summary.joined}</strong> joined · <strong>{summary.paid}</strong> started paying · {credits ? <>you have earned <strong>{credits}</strong></> : summary.paid > summary.rewarded ? "your free month arrives on your next paid bill" : "no credit earned yet"}</p>
    </div>
  </section>;
}
