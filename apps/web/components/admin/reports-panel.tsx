"use client";

import { useEffect, useState } from "react";
import { CircleCheck, CircleDashed, CircleX, Download, FileCheck2, LoaderCircle, Printer, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { downloadBlob } from "@/lib/browser/download";
import { verifyAuditChain } from "@/lib/enterprise/audit";
import {
  complianceCsv, evaluateControls, listComplianceHistory, loadComplianceSnapshot,
  type ComplianceSnapshot, type ControlResult,
} from "@/lib/enterprise/compliance";
import type { WorkspaceVault } from "@/lib/vault/items";
import { WeeklyReportCard } from "@/components/admin/security-panels";

const STATUS_ICON = { pass: CircleCheck, partial: CircleDashed, fail: CircleX };
const STATUS_LABEL = { pass: "Meets", partial: "Partially meets", fail: "Gap" };

export function ReportsPanel({ vault, organizationName }: { vault: WorkspaceVault; organizationName: string }) {
  const [snapshot, setSnapshot] = useState<ComplianceSnapshot | null>(null);
  const [history, setHistory] = useState<{ period: string; snapshot: ComplianceSnapshot }[]>([]);
  const [chain, setChain] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) setLoading(true); })
      .then(() => Promise.allSettled([loadComplianceSnapshot(vault.tenantId), listComplianceHistory(vault.tenantId)]))
      .then(([current, past]) => {
        if (!active) return;
        if (current.status === "fulfilled") { setSnapshot(current.value); setMessage(""); }
        else setMessage(adminErrorMessage(current.reason, "The compliance report could not be generated."));
        if (past.status === "fulfilled") setHistory(past.value);
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function verify() {
    setVerifying(true);
    try { const result = await verifyAuditChain(vault.tenantId); setChain(result.first_invalid_sequence === null); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The audit chain could not be verified.")); }
    finally { setVerifying(false); }
  }

  const controls: ControlResult[] = snapshot ? evaluateControls(snapshot, chain) : [];
  const met = controls.filter((control) => control.status === "pass").length;
  const stamp = snapshot ? snapshot.generated_at.slice(0, 10) : "";

  return <div className="reports-panel">
    <WeeklyReportCard vault={vault} organizationName={organizationName} />
    <Card className="report-sheet">
      <CardHeader>
        <div className="panel-heading"><div><CardTitle><FileCheck2 /> Security & compliance report</CardTitle>
          <CardDescription>{organizationName} · generated {snapshot ? new Date(snapshot.generated_at).toLocaleString() : "…"}. Built from metadata only — Passkey-X never sees vault contents.</CardDescription></div>
          <div className="inline-actions report-actions">
            <Button variant="ghost" size="icon-sm" aria-label="Regenerate" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
            <Button size="sm" variant="outline" disabled={verifying || !snapshot} onClick={() => void verify()}>{verifying ? <LoaderCircle className="spin" /> : <FileCheck2 />} Verify audit chain</Button>
            <Button size="sm" variant="outline" disabled={!snapshot} onClick={() => snapshot && downloadBlob(new Blob([complianceCsv(controls, snapshot)], { type: "text/csv" }), `passkey-x-compliance-${stamp}.csv`)}><Download /> CSV</Button>
            <Button size="sm" variant="outline" disabled={!snapshot} onClick={() => snapshot && downloadBlob(new Blob([JSON.stringify({ product: "Passkey-X", tenant_id: vault.tenantId, controls, snapshot, audit_chain_verified: chain }, null, 2)], { type: "application/json" }), `passkey-x-compliance-${stamp}.json`)}><Download /> JSON</Button>
            <Button size="sm" disabled={!snapshot} onClick={() => window.print()}><Printer /> Print / PDF</Button>
          </div></div>
      </CardHeader>
      <CardContent>
        {message && <p className="form-message" role="alert">{message}</p>}
        {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : snapshot && <>
          <div className="report-summary">
            <div><strong>{met}/{controls.length}</strong><span>controls met</span></div>
            <div><strong>{snapshot.members.active}</strong><span>active members</span></div>
            <div><strong>{snapshot.members.active ? Math.round((snapshot.members.with_mfa / snapshot.members.active) * 100) : 0}%</strong><span>with two-step</span></div>
            <div><strong>{snapshot.vault_health?.avg_score ?? "—"}</strong><span>avg. vault health</span></div>
            <div><strong>{snapshot.alerts?.open ?? 0}</strong><span>open alerts</span></div>
          </div>
          <table className="report-table"><thead><tr><th>Control</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>{controls.map((control) => { const Icon = STATUS_ICON[control.status]; return <tr key={control.id}>
              <td><strong>{control.title}</strong><small>{control.frameworks}</small></td>
              <td><span className={`control-status ${control.status}`}><Icon /> {STATUS_LABEL[control.status]}</span></td>
              <td>{control.evidence}</td></tr>; })}</tbody></table>
          <p className="field-hint">This report supports SOC 2 and ISO 27001 evidence collection. It is not a certification. Verify the audit chain before exporting so the report records the result.</p>
        </>}
      </CardContent>
    </Card>
    {history.length > 0 && <Card className="report-history"><CardHeader><CardTitle>Monthly history</CardTitle><CardDescription>A snapshot is stored on the 1st of each month.</CardDescription></CardHeader>
      <CardContent><table className="report-table"><thead><tr><th>Month</th><th>Members</th><th>Two-step</th><th>Vault health</th><th>Alerts (30d)</th></tr></thead>
        <tbody>{history.map((entry) => <tr key={entry.period}><td>{entry.period}</td><td>{entry.snapshot.members.active}</td>
          <td>{entry.snapshot.members.active ? Math.round((entry.snapshot.members.with_mfa / entry.snapshot.members.active) * 100) : 0}%</td>
          <td>{entry.snapshot.vault_health?.avg_score ?? "—"}</td><td>{entry.snapshot.alerts?.last_30d ?? 0}</td></tr>)}</tbody></table></CardContent></Card>}
  </div>;
}
