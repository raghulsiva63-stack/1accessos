"use client";

import { useState } from "react";
import { Bot, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { supabase } from "@/lib/supabase/client";
import { webUrl } from "@/lib/desktop/bridge";

const USE_CASE_LABELS: Record<string, string> = {
  security_posture: "Security posture",
  access_review: "Access review",
  spend_review: "SaaS and AI spend",
  incident_summary: "Incident readiness",
};

export function HostedAiAdvisor({ tenantId }: { tenantId: string }) {
  const [useCase, setUseCase] = useState("security_posture");
  const [advice, setAdvice] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function analyze() {
    setBusy(true); setMessage(""); setAdvice("");
    try {
      const { data } = await supabase!.auth.getSession();
      if (!data.session?.access_token) throw new Error("session_required");
      const response = await fetch(webUrl("/api/ai/security-advice"), {
        method: "POST",
        headers: { "Authorization": `Bearer ${data.session.access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId, useCase }),
      });
      const payload = await response.json() as { advice?: string; error?: string };
      if (!response.ok || !payload.advice) throw new Error(payload.error ?? "advisor_unavailable");
      setAdvice(payload.advice);
    } catch {
      setMessage("The hosted advisor is unavailable. No access change was made and no vault content was transmitted.");
    } finally { setBusy(false); }
  }

  return <Card className="hosted-ai-card"><CardHeader><div><CardTitle><Sparkles /> Hosted Security Advisor</CardTitle><CardDescription>Netlify AI Gateway analyzes approved aggregate counts only. Vault items, page content, credentials, names, IDs, and raw prompts are excluded.</CardDescription></div><span className="hosted-pill"><Bot /> Hosted AI</span></CardHeader><CardContent>
    <div className="hosted-ai-controls"><div><Label htmlFor="hosted-ai-use-case">Analysis</Label><select id="hosted-ai-use-case" value={useCase} onChange={(event) => setUseCase(event.target.value)}>{Object.entries(USE_CASE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div><Button disabled={busy} onClick={() => void analyze()}>{busy ? "Analyzing aggregate signals…" : "Generate advice"}</Button></div>
    {message && <p className="settings-message" role="status">{message}</p>}
    {advice ? <div className="hosted-ai-result"><ShieldCheck /><div><strong>{USE_CASE_LABELS[useCase]} guidance</strong><p>{advice}</p><small>Advisory only · no automatic or destructive actions</small></div></div> : <p className="field-hint">Choose an analysis to generate a privacy-minimized recommendation.</p>}
  </CardContent></Card>;
}
