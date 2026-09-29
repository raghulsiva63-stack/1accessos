"use client";

import { useEffect, useState } from "react";
import { BellRing, Check, CheckCheck, LoaderCircle, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { relativeTime, type MemberOverview } from "@/lib/enterprise/admin";
import {
  ALERT_GUIDANCE, listSecurityAlerts, SEVERITY_ORDER, updateSecurityAlert, type AlertStatus, type SecurityAlert,
} from "@/lib/enterprise/alerts";
import type { WorkspaceVault } from "@/lib/vault/items";
import { AiAlertTriage } from "@/components/admin/security-ai";

const FILTERS: { id: AlertStatus | "all"; label: string }[] = [
  { id: "open", label: "Open" }, { id: "acknowledged", label: "Acknowledged" }, { id: "resolved", label: "Resolved" }, { id: "all", label: "All" },
];

export function AlertsPanel({ vault, members }: { vault: WorkspaceVault; members: MemberOverview[] }) {
  const { isTenantAdmin, tenantRole } = useEnterprise();
  const [filter, setFilter] = useState<AlertStatus | "all">("open");
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);
  const [now] = useState(() => Date.now());
  const names = new Map(members.map((member) => [member.identity_id, member.display_name ?? member.email ?? "Member"]));

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) setLoading(true); })
      .then(() => listSecurityAlerts(vault.tenantId, filter))
      .then((rows) => { if (active) { setAlerts([...rows].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.created_at.localeCompare(a.created_at))); setMessage(""); } },
        (reason) => { if (active) setMessage(adminErrorMessage(reason, "Security alerts could not be loaded.")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [filter, vault.tenantId, version]);

  async function change(alert: SecurityAlert, status: AlertStatus) {
    setBusy(alert.id); setMessage("");
    try { await updateSecurityAlert(alert.id, status); setVersion((value) => value + 1); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The alert could not be updated.")); }
    finally { setBusy(""); }
  }

  return <div className="si-stack">
  {(isTenantAdmin || tenantRole === "auditor") && <AiAlertTriage tenantId={vault.tenantId} />}
  <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle>Security alerts</CardTitle><CardDescription>Risky events detected in your audit log every few minutes: emergency access, exports, new administrators, policy changes, unusual secret access and more. Metadata only.</CardDescription></div>
        <Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button></div>
      <div className="billing-segment" role="group" aria-label="Alert status">{FILTERS.map((entry) => <button key={entry.id} className={filter === entry.id ? "active" : ""} onClick={() => setFilter(entry.id)}>{entry.label}</button>)}</div>
    </CardHeader>
    <CardContent>
      {message && <p className="form-message" role="alert">{message}</p>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : alerts.length === 0 ?
        <div className="empty-state"><ShieldCheck /><p>{filter === "open" ? "No open alerts. Nice." : "No alerts here."}</p></div> :
        <ul className="alert-list">{alerts.map((alert) => <li key={alert.id} className={`severity-${alert.severity}`}>
          <span className={`alert-severity ${alert.severity}`}><BellRing /> {alert.severity}</span>
          <div className="alert-body"><strong>{alert.title}</strong>
            <small>{relativeTime(alert.created_at, now)}{alert.actor_identity_id ? ` · ${names.get(alert.actor_identity_id) ?? "a member"}` : ""}{alert.status !== "open" ? ` · ${alert.status}` : ""}</small>
            {ALERT_GUIDANCE[alert.kind] && <p>{ALERT_GUIDANCE[alert.kind]}</p>}</div>
          {isTenantAdmin && <div className="inline-actions">
            {alert.status === "open" && <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void change(alert, "acknowledged")}>{busy === alert.id ? <LoaderCircle className="spin" /> : <Check />} Acknowledge</Button>}
            {alert.status !== "resolved" && <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void change(alert, "resolved")}><CheckCheck /> Resolve</Button>}
            {alert.status !== "open" && <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void change(alert, "open")}><RotateCcw /> Reopen</Button>}
          </div>}
        </li>)}</ul>}
    </CardContent>
  </Card>
  </div>;
}
