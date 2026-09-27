"use client";

import { useEffect, useMemo, useState } from "react";
import { TriangleAlert, CalendarClock, Download, FolderLock, LoaderCircle, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { downloadBlob } from "@/lib/browser/download";
import {
  adminRevokeWorkspaceMember, groupAccessReview, loadAccessReview, relativeTime, setWorkspaceMemberExpiry,
  type AccessReviewRow,
} from "@/lib/enterprise/admin";
import type { WorkspaceVault } from "@/lib/vault/items";

const DAY = 86_400_000;

function staleAccess(row: AccessReviewRow, now: number) {
  return !row.last_activity_at || now - Date.parse(row.last_activity_at) > 60 * DAY;
}

function csvCell(value: unknown) {
  const text = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@\t\r]/u.test(text) ? `'${text}` : text;
  return /[",\n\r]/u.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function AccessReviewPanel({ vault, workspaceNames }: { vault: WorkspaceVault; workspaceNames: Map<string, string> }) {
  const [rows, setRows] = useState<AccessReviewRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [staleOnly, setStaleOnly] = useState(false);
  const [version, setVersion] = useState(0);
  const [now] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) setLoading(true); })
      .then(() => loadAccessReview(vault.tenantId))
      .then((result) => { if (active) { setRows(result); setMessage(""); } }, (reason) => { if (active) setMessage(adminErrorMessage(reason, "Access review could not be loaded.")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  const isStale = (row: AccessReviewRow) => staleAccess(row, now);
  const workspaces = useMemo(() => groupAccessReview(staleOnly ? rows.filter((row) => staleAccess(row, now)) : rows), [now, rows, staleOnly]);
  const staleCount = rows.filter(isStale).length;
  const nameOf = (id: string) => workspaceNames.get(id) ?? `Workspace ${id.slice(0, 8)}`;

  async function run(key: string, action: () => Promise<void>, success: string) {
    setBusy(key); setMessage("");
    try { await action(); setMessage(success); setVersion((value) => value + 1); }
    catch (reason) { setMessage(adminErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  function revoke(row: AccessReviewRow) {
    if (!window.confirm(`Remove ${row.display_name} from ${nameOf(row.workspace_id)}? Their key envelope is revoked and the workspace is flagged for key rotation.`)) return;
    void run(`${row.workspace_id}:${row.identity_id}`, () => adminRevokeWorkspaceMember(vault.tenantId, row.workspace_id, row.identity_id), "Access removed.");
  }

  function setExpiry(row: AccessReviewRow, days: number | null) {
    const expiresAt = days === null ? null : new Date(Date.now() + days * DAY).toISOString();
    void run(`${row.workspace_id}:${row.identity_id}`, () => setWorkspaceMemberExpiry(row.workspace_id, row.identity_id, expiresAt), days === null ? "Access is now permanent." : `Access will expire in ${days} days.`);
  }

  function exportCsv() {
    const header = ["workspace_id", "workspace", "suite", "member", "email", "role", "status", "expires_at", "member_since", "last_activity"];
    const lines = rows.map((row) => [row.workspace_id, nameOf(row.workspace_id), row.suite, row.display_name, row.email, row.role, row.membership_status, row.expires_at, row.member_since, row.last_activity_at].map(csvCell).join(","));
    downloadBlob(new Blob([[header.join(","), ...lines].join("\r\n")], { type: "text/csv" }), `passkey-x-access-review-${new Date().toISOString().slice(0, 10)}.csv`);
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle>Access review</CardTitle><CardDescription>Who can open which shared workspace. Certify access quarterly, set expiry dates for temporary access, and remove what is no longer needed.</CardDescription></div>
        <div className="inline-actions"><Button variant="outline" size="sm" onClick={exportCsv} disabled={!rows.length}><Download /> Export evidence</Button><Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button></div></div>
    </CardHeader>
    <CardContent>
      <div className="people-toolbar"><div className="chip-row"><button className={!staleOnly ? "active" : ""} onClick={() => setStaleOnly(false)}>All access<span>{rows.length}</span></button><button className={staleOnly ? "active" : ""} onClick={() => setStaleOnly(true)}>No activity 60d<span>{staleCount}</span></button></div></div>
      {message && <p className="form-message" role="status">{message}</p>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : workspaces.length === 0 ? <div className="empty-state"><ShieldCheck /><p>{staleOnly ? "No stale access found." : "No shared workspaces yet."}</p></div> :
        <div className="review-list">{workspaces.map((workspace) => <section key={workspace.id} className="review-workspace">
          <header><FolderLock /><div><strong>{nameOf(workspace.id)}</strong><small>{workspace.suite} · {workspace.members.length} member{workspace.members.length === 1 ? "" : "s"} · created {new Date(workspace.createdAt).toLocaleDateString()}</small></div>{workspace.keyRotationRequired && <span className="status-chip warn"><TriangleAlert /> Key rotation due</span>}</header>
          <ul>{workspace.members.map((row) => {
            const key = `${row.workspace_id}:${row.identity_id}`;
            const expiring = row.expires_at ? Date.parse(row.expires_at) : null;
            return <li key={key}>
              <span className="avatar">{row.display_name.slice(0, 2).toUpperCase()}</span>
              <div className="review-member"><strong>{row.display_name}</strong><small>{row.email ?? ""}</small></div>
              <span className="role-pill">{row.role}</span>
              <span className={`review-activity ${isStale(row) ? "stale" : ""}`}>{isStale(row) ? "Inactive · " : ""}{relativeTime(row.last_activity_at, now)}</span>
              <span className="review-expiry">{expiring ? <><CalendarClock /> {expiring > now ? `until ${new Date(expiring).toLocaleDateString()}` : "expired"}</> : <span className="muted-text">Permanent</span>}</span>
              <span className="review-actions">{busy === key ? <LoaderCircle className="spin" /> : row.role !== "owner" && <>
                <select aria-label={`Access duration for ${row.display_name}`} value="" onChange={(event) => { const value = event.target.value; if (value) setExpiry(row, value === "permanent" ? null : Number(value)); }}>
                  <option value="">Set expiry…</option><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option>{row.expires_at && <option value="permanent">Make permanent</option>}
                </select>
                <Button variant="ghost" size="icon-sm" aria-label={`Remove ${row.display_name}`} onClick={() => revoke(row)}><UserMinus /></Button>
              </>}</span>
            </li>;
          })}</ul>
        </section>)}</div>}
    </CardContent>
  </Card>;
}
