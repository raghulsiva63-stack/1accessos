"use client";

import { useState } from "react";
import { LoaderCircle, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { supabase } from "@/lib/supabase/client";
import { webUrl } from "@/lib/desktop/bridge";

/** Only these totals are sent. Titles, sites, usernames and passwords stay on this device. */
export type CoachMetrics = {
  score: number; logins: number; weak: number; reused: number; old: number;
  breached: number; insecure_sites: number; missing_two_step: number; passkeys: number;
};

export function AiSecurityCoach({ tenantId, metrics }: { tenantId: string | null; metrics: CoachMetrics }) {
  const [advice, setAdvice] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [showSent, setShowSent] = useState(false);

  async function ask() {
    if (!tenantId) return;
    setBusy(true); setMessage(""); setAdvice("");
    try {
      const { data } = await supabase!.auth.getSession();
      if (!data.session?.access_token) throw new Error("session_required");
      const response = await fetch(webUrl("/api/ai/security-advice"), {
        method: "POST",
        headers: { "Authorization": `Bearer ${data.session.access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId, useCase: "vault_health", metrics }),
      });
      const payload = await response.json().catch(() => ({})) as { advice?: string; error?: string };
      if (response.status === 429) { setMessage("You have used this month's AI credits for this vault, or asked many times in the last hour. Credits refill on the 1st of each month."); return; }
      if (!response.ok || !payload.advice) throw new Error(payload.error ?? "coach_unavailable");
      setAdvice(payload.advice);
    } catch {
      setMessage("The AI Security Coach is unavailable right now. Only vault totals are ever sent, and a failed request does not use a credit.");
    } finally { setBusy(false); }
  }

  return <section className="coach-card" aria-labelledby="coach-title">
    <div className="coach-head">
      <span className="coach-icon"><Sparkles /></span>
      <div>
        <h3 id="coach-title">AI Security Coach</h3>
        <p>Get a short, personal plan for what to fix first. Uses 1 AI credit from your plan.</p>
      </div>
      <Button onClick={() => void ask()} disabled={busy || !tenantId || metrics.logins === 0}>{busy ? <><LoaderCircle className="spin" /> Thinking…</> : advice ? "Ask again" : "Get my plan"}</Button>
    </div>
    {metrics.logins === 0 && <p className="field-hint">Add a few logins first — the coach works from your vault&apos;s health totals.</p>}
    {message && <p className="form-message" role="status">{message}</p>}
    {advice && <div className="coach-advice"><ShieldCheck /><p>{advice}</p></div>}
    <button type="button" className="coach-privacy" onClick={() => setShowSent((value) => !value)} aria-expanded={showSent}>What is sent?</button>
    {showSent && <div className="coach-sent">
      <p>Only these numbers leave your device — never titles, websites, usernames or passwords:</p>
      <dl>{Object.entries(metrics).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{value === -1 ? "not checked" : value}</dd></div>)}</dl>
    </div>}
  </section>;
}
