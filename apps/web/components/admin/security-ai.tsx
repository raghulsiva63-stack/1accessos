"use client";

import { useState } from "react";
import { Check, LoaderCircle, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ALERT_GUIDANCE } from "@/lib/enterprise/alerts";
import { describePolicy, POLICY_DEFINITIONS, saveTenantPolicy, type PolicyType } from "@/lib/enterprise/policies";
import { aiErrorMessage, askSecurityAi } from "@/lib/security/client";
import type { PolicyRecommendation, TriageItem } from "@/lib/security/ai-output";
import { adminErrorMessage } from "@/components/admin/admin-console";

const PRIVACY = "The AI sees only alert types, counts and ages, never names, emails, passwords or vault content. Uses 1 AI credit.";

function kindLabel(kind: string) {
  return kind.replace(/[._]/gu, " ").replace(/^\w/u, (letter) => letter.toUpperCase());
}

/** Ranks open alerts and suggests the next step for each. */
export function AiAlertTriage({ tenantId }: { tenantId: string }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ summary: string; items: TriageItem[] } | null>(null);
  const [message, setMessage] = useState("");

  async function run() {
    setBusy(true); setMessage("");
    try {
      const answer = await askSecurityAi(tenantId, "alert_triage");
      if (answer.useCase === "alert_triage") setResult({ summary: answer.summary, items: answer.items });
    } catch (reason) { setMessage(aiErrorMessage(reason)); }
    finally { setBusy(false); }
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><Sparkles /> AI triage</CardTitle><CardDescription>Which open alerts to handle first, why, and what to do. {PRIVACY}</CardDescription></div>
        <Button size="sm" disabled={busy} onClick={() => void run()}>{busy ? <LoaderCircle className="spin" /> : <Sparkles />} {result ? "Triage again" : "Triage open alerts"}</Button></div>
    </CardHeader>
    {(message || result) && <CardContent className="si-ai">
      {message && <p className="form-message" role="alert">{message}</p>}
      {result && <>
        {result.summary && <div className="si-summary">{result.summary}</div>}
        {result.items.length === 0 ? <p className="field-hint">No open alerts need attention.</p> : result.items.map((item) => <div key={item.kind} className="si-ai-item">
          <span className={`si-priority p${item.priority}`} aria-label={`Priority ${item.priority}`}>{item.priority}</span>
          <div><strong>{kindLabel(item.kind)}</strong><p>{item.why}</p><p><strong>Next:</strong> {item.next_step}</p>{ALERT_GUIDANCE[item.kind] && <p>{ALERT_GUIDANCE[item.kind]}</p>}</div>
          <span />
        </div>)}
        <small className="field-hint">AI suggestions can be wrong. Check the audit log before acting on a person.</small>
      </>}
    </CardContent>}
  </Card>;
}

/** Recommends policies from the organization's posture; each one is applied only with a click. */
export function AiPolicyAdvisor({ tenantId, identityId, canEdit, onChanged }: { tenantId: string; identityId: string; canEdit: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState<{ summary: string; recommendations: PolicyRecommendation[] } | null>(null);
  const [applied, setApplied] = useState<string[]>([]);
  const [message, setMessage] = useState("");

  async function run() {
    setBusy("ai"); setMessage(""); setApplied([]);
    try {
      const answer = await askSecurityAi(tenantId, "policy_advisor");
      if (answer.useCase === "policy_advisor") setResult({ summary: answer.summary, recommendations: answer.recommendations });
    } catch (reason) { setMessage(aiErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  async function apply(recommendation: PolicyRecommendation) {
    const definition = POLICY_DEFINITIONS.find((entry) => entry.type === recommendation.policy_type);
    if (!definition || !window.confirm(`Enforce “${definition.title}: ${describePolicy(recommendation.policy_type as PolicyType, recommendation.configuration)}” for everyone in the organization?`)) return;
    setBusy(recommendation.policy_type); setMessage("");
    try {
      await saveTenantPolicy(tenantId, identityId, recommendation.policy_type as PolicyType, recommendation.configuration);
      setApplied((list) => [...list, recommendation.policy_type]);
      onChanged();
    } catch (reason) { setMessage(adminErrorMessage(reason, "The policy could not be applied.")); }
    finally { setBusy(""); }
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><Sparkles /> AI policy advisor</CardTitle><CardDescription>Suggests policies based on your organization&apos;s numbers (two-step coverage, breaches, reused passwords, alerts). Nothing changes until you apply a suggestion. Uses 1 AI credit; only counts and current policy settings are sent.</CardDescription></div>
        <Button size="sm" disabled={busy !== ""} onClick={() => void run()}>{busy === "ai" ? <LoaderCircle className="spin" /> : <Sparkles />} {result ? "Ask again" : "Get recommendations"}</Button></div>
    </CardHeader>
    {(message || result) && <CardContent className="si-ai">
      {message && <p className="form-message" role="alert">{message}</p>}
      {result && <>
        {result.summary && <div className="si-summary">{result.summary}</div>}
        {result.recommendations.length === 0 ? <p className="field-hint">No changes recommended — your policies already fit your posture.</p> :
          result.recommendations.map((recommendation, index) => {
            const definition = POLICY_DEFINITIONS.find((entry) => entry.type === recommendation.policy_type);
            const done = applied.includes(recommendation.policy_type);
            return <div key={recommendation.policy_type} className="si-ai-item">
              <span className={`si-priority p${Math.min(index + 1, 3)}`}>{index + 1}</span>
              <div><strong>{definition?.title ?? recommendation.policy_type}: {describePolicy(recommendation.policy_type as PolicyType, recommendation.configuration)}</strong><p>{recommendation.reason}</p></div>
              {canEdit ? <Button size="sm" variant={done ? "outline" : "default"} disabled={done || busy !== ""} onClick={() => void apply(recommendation)}>
                {busy === recommendation.policy_type ? <LoaderCircle className="spin" /> : done ? <Check /> : null} {done ? "Applied" : "Apply"}</Button> : <span className="si-tag">Business plan</span>}
            </div>;
          })}
      </>}
    </CardContent>}
  </Card>;
}
