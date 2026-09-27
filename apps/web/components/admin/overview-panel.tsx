"use client";

import { useMemo, useState } from "react";
import {
  TriangleAlert, BadgeCheck, CircleCheck, Fingerprint, Gauge, Link2, LoaderCircle, Repeat2, ShieldAlert,
  ShieldCheck, UserX, Users, Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adminErrorMessage, type AdminTab } from "@/components/admin/admin-console";
import { summarizeOrganization, type MemberOverview } from "@/lib/enterprise/admin";
import { verifyAuditChain, type ChainVerification } from "@/lib/enterprise/audit";
import {
  baselineCoverage, describePolicy, POLICY_DEFINITIONS, RECOMMENDED_BASELINE, saveTenantPolicy,
  type StoredPolicy,
} from "@/lib/enterprise/policies";
import type { WorkspaceVault } from "@/lib/vault/items";

function Kpi({ icon: Icon, label, value, detail, tone = "neutral", onClick }: {
  icon: typeof Users; label: string; value: string | number; detail: string;
  tone?: "neutral" | "good" | "warn" | "bad"; onClick?: () => void;
}) {
  return <button className={`kpi-card tone-${tone}`} onClick={onClick} disabled={!onClick}>
    <span className="kpi-icon"><Icon /></span>
    <span className="kpi-body"><small>{label}</small><strong>{value}</strong><span>{detail}</span></span>
  </button>;
}

export function AdminOverview({
  vault, members, policies, loading, onNavigate, onChanged, canEdit,
}: {
  vault: WorkspaceVault;
  members: MemberOverview[];
  policies: StoredPolicy[];
  loading: boolean;
  onNavigate: (tab: AdminTab) => void;
  onChanged: () => void;
  canEdit: boolean;
}) {
  const summary = useMemo(() => summarizeOrganization(members), [members]);
  const coverage = useMemo(() => baselineCoverage(policies), [policies]);
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const enforcedTypes = new Set(policies.filter((policy) => policy.enforced && policy.scope_type === "tenant").map((policy) => policy.policy_type));
  const missing = RECOMMENDED_BASELINE.filter((entry) => !enforcedTypes.has(entry.type));

  async function verify() {
    setBusy("verify"); setMessage("");
    try { setChain(await verifyAuditChain(vault.tenantId)); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The audit chain could not be verified.")); }
    finally { setBusy(""); }
  }

  async function applyBaseline() {
    if (!window.confirm(`Apply ${missing.length} recommended polic${missing.length === 1 ? "y" : "ies"} to the whole organization? Existing policies are not changed.`)) return;
    setBusy("baseline"); setMessage("");
    try {
      for (const entry of missing) await saveTenantPolicy(vault.tenantId, vault.identityId, entry.type, entry.configuration);
      setMessage("Recommended security baseline applied.");
      onChanged();
    } catch (reason) { setMessage(adminErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  if (loading && !members.length) return <div className="vault-loading"><div className="loading-ring" /><p>Loading organization posture…</p></div>;
  const score = summary.averageScore;
  const scoreTone = score === null ? "neutral" : score >= 80 ? "good" : score >= 60 ? "warn" : "bad";

  return <div className="admin-overview">
    {message && <p className="form-message" role="status">{message}</p>}
    <div className="kpi-grid">
      <Kpi icon={Gauge} label="Organization health" value={score === null ? "—" : `${score}/100`} detail={`${summary.active - summary.neverReported} of ${summary.active} members reporting`} tone={scoreTone} onClick={() => onNavigate("people")} />
      <Kpi icon={Users} label="Active members" value={summary.active} detail={`${summary.admins} with admin rights`} onClick={() => onNavigate("people")} />
      <Kpi icon={ShieldAlert} label="Members at risk" value={summary.atRisk} detail="score below 70 or breached passwords" tone={summary.atRisk ? "bad" : "good"} onClick={() => onNavigate("people")} />
      <Kpi icon={Fingerprint} label="Without 2-step sign-in" value={summary.withoutMfa} detail="no verified second factor" tone={summary.withoutMfa ? "warn" : "good"} onClick={() => onNavigate("people")} />
      <Kpi icon={UserX} label="Inactive 30+ days" value={summary.inactive30} detail="review for offboarding" tone={summary.inactive30 ? "warn" : "good"} onClick={() => onNavigate("people")} />
      <Kpi icon={BadgeCheck} label="Policy baseline" value={`${coverage.percent}%`} detail={`${coverage.met} of ${coverage.total} recommended controls`} tone={coverage.percent === 100 ? "good" : coverage.percent >= 50 ? "warn" : "bad"} onClick={() => onNavigate("policies")} />
    </div>

    <div className="admin-columns">
      <Card>
        <CardHeader><CardTitle>Credential risk across the organization</CardTitle><CardDescription>Totals reported by members&apos; own devices. Passwords, sites and usernames are never shared with admins.</CardDescription></CardHeader>
        <CardContent>
          <div className="risk-bars">
            {[
              { icon: Zap, label: "Breached passwords", value: summary.breached, tone: "bad" },
              { icon: Repeat2, label: "Reused passwords", value: summary.reused, tone: "bad" },
              { icon: TriangleAlert, label: "Weak passwords", value: summary.weak, tone: "warn" },
            ].map((row) => { const Icon = row.icon; const max = Math.max(1, summary.breached, summary.reused, summary.weak); return <div key={row.label} className={`risk-bar tone-${row.value ? row.tone : "good"}`}>
              <span><Icon /> {row.label}</span><div><i style={{ width: `${(row.value / max) * 100}%` }} /></div><strong>{row.value}</strong>
            </div>; })}
          </div>
          {summary.neverReported > 0 && <p className="field-hint">{summary.neverReported} member{summary.neverReported === 1 ? " has" : "s have"} not opened Security on a current client yet.</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Security baseline</CardTitle><CardDescription>Recommended controls for SOC 2 and ISO 27001 aligned organizations.</CardDescription></CardHeader>
        <CardContent>
          <ul className="baseline-list">{RECOMMENDED_BASELINE.map((entry) => {
            const definition = POLICY_DEFINITIONS.find((item) => item.type === entry.type)!;
            const stored = policies.find((policy) => policy.policy_type === entry.type && policy.scope_type === "tenant");
            const on = Boolean(stored?.enforced);
            return <li key={entry.type} className={on ? "on" : ""}>{on ? <CircleCheck /> : <span className="baseline-dot" />}<div><strong>{definition.title}</strong><small>{on ? describePolicy(entry.type, stored!.configuration) : `Recommended: ${describePolicy(entry.type, entry.configuration)}`}</small></div></li>;
          })}</ul>
          <div className="inline-actions">
            {missing.length > 0 && canEdit && <Button onClick={() => void applyBaseline()} disabled={busy !== ""}>{busy === "baseline" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Apply recommended baseline</Button>}
            <Button variant="outline" onClick={() => onNavigate("policies")}>Customize policies</Button>
          </div>
        </CardContent>
      </Card>
    </div>

    <Card>
      <CardHeader><CardTitle><Link2 /> Tamper-evident audit trail</CardTitle><CardDescription>Each event includes the SHA-256 hash of the event before it, so any edit or deletion breaks the chain.</CardDescription></CardHeader>
      <CardContent className="chain-card">
        {chain ? <div className={`chain-result ${chain.first_invalid_sequence ? "bad" : "good"}`}>
          {chain.first_invalid_sequence ? <ShieldAlert /> : <ShieldCheck />}
          <div>
            <strong>{chain.first_invalid_sequence ? `Integrity problem at event #${chain.first_invalid_sequence}` : "Audit chain verified"}</strong>
            <p>{chain.checked_events.toLocaleString()} events checked ({chain.v2_events.toLocaleString()} fully recomputed){chain.first_invalid_reason ? ` · ${chain.first_invalid_reason}` : ""}.</p>
            {chain.head_hash && <code title="Latest chain hash">head #{chain.head_sequence} · {chain.head_hash.slice(0, 16)}…</code>}
          </div>
        </div> : <p className="field-hint">Run a verification before an audit, or on a schedule, and keep the head hash as evidence.</p>}
        <div className="inline-actions"><Button variant="outline" onClick={() => void verify()} disabled={busy !== ""}>{busy === "verify" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Verify integrity</Button><Button variant="ghost" onClick={() => onNavigate("audit")}>Open audit log</Button></div>
      </CardContent>
    </Card>
  </div>;
}
