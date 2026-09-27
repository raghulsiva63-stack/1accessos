"use client";

import { useEffect, useState } from "react";
import { Braces, Download, FileSpreadsheet, LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { downloadBlob } from "@/lib/browser/download";
import type { MemberOverview } from "@/lib/enterprise/admin";
import {
  AUDIT_CATEGORIES, auditToCsv, collectAudit, describeAuditAction, searchAudit,
  type AuditEvent, type AuditQuery,
} from "@/lib/enterprise/audit";
import type { WorkspaceVault } from "@/lib/vault/items";

function toIsoStart(date: string) { return date ? new Date(`${date}T00:00:00`).toISOString() : null; }
function toIsoEnd(date: string) { return date ? new Date(new Date(`${date}T00:00:00`).getTime() + 86_400_000).toISOString() : null; }

function metadataSummary(event: AuditEvent) {
  const metadata = event.metadata ?? {};
  const parts: string[] = [];
  for (const key of ["content_type", "role", "status", "policy_type", "from", "to", "reveal_policy"]) {
    const value = metadata[key];
    if (typeof value === "string" && value) parts.push(`${key.replace("_", " ")}: ${value}`);
  }
  return parts.join(" · ");
}

export function AuditPanel({ vault, members }: { vault: WorkspaceVault; members: MemberOverview[] }) {
  const [category, setCategory] = useState("");
  const [actor, setActor] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [version, setVersion] = useState(0);

  const query: AuditQuery = { actionPrefix: category || null, actorIdentityId: actor || null, since: toIsoStart(since), until: toIsoEnd(until) };

  useEffect(() => {
    let current = true;
    void Promise.resolve().then(() => { if (current) { setLoading(true); setMessage(""); } })
      .then(() => searchAudit(vault.tenantId, { actionPrefix: category || null, actorIdentityId: actor || null, since: toIsoStart(since), until: toIsoEnd(until), limit: 100 }))
      .then((rows) => { if (current) { setEvents(rows); setMore(rows.length === 100); } },
        (reason) => { if (current) { setEvents([]); setMessage(adminErrorMessage(reason, "The audit log could not be loaded.")); } })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [actor, category, since, until, vault.tenantId, version]);

  async function loadMore() {
    const last = events[events.length - 1];
    if (!last) return;
    setBusy("more");
    try {
      const rows = await searchAudit(vault.tenantId, { ...query, beforeSequence: last.sequence, limit: 100 });
      setEvents([...events, ...rows]); setMore(rows.length === 100);
    } catch (reason) { setMessage(adminErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  async function exportAs(format: "csv" | "json") {
    setBusy(format); setMessage("");
    try {
      const rows = await collectAudit(vault.tenantId, query);
      const stamp = new Date().toISOString().replaceAll(":", "-").slice(0, 19);
      if (format === "csv") downloadBlob(new Blob([auditToCsv(rows)], { type: "text/csv" }), `passkey-x-audit-${stamp}.csv`);
      else downloadBlob(new Blob([JSON.stringify({ product: "Passkey-X", tenant_id: vault.tenantId, exported_at: new Date().toISOString(), filters: query, events: rows }, null, 2)], { type: "application/json" }), `passkey-x-audit-${stamp}.json`);
      setMessage(`${rows.length.toLocaleString()} events exported. Keep the file with your compliance evidence.`);
    } catch (reason) { setMessage(adminErrorMessage(reason, "The export could not be created.")); }
    finally { setBusy(""); }
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle>Audit log</CardTitle><CardDescription>Every admin action, policy change, share and secret access — metadata only, never vault content.</CardDescription></div>
        <div className="inline-actions">
          <Button variant="outline" size="sm" onClick={() => void exportAs("csv")} disabled={busy !== ""}>{busy === "csv" ? <LoaderCircle className="spin" /> : <FileSpreadsheet />} CSV</Button>
          <Button variant="outline" size="sm" onClick={() => void exportAs("json")} disabled={busy !== ""}>{busy === "json" ? <LoaderCircle className="spin" /> : <Braces />} JSON</Button>
          <Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
        </div></div>
    </CardHeader>
    <CardContent>
      <div className="audit-filters">
        <div><Label htmlFor="audit-category">Category</Label><select id="audit-category" value={category} onChange={(event) => setCategory(event.target.value)}>{AUDIT_CATEGORIES.map((entry) => <option key={entry.label} value={entry.prefix}>{entry.label}</option>)}</select></div>
        <div><Label htmlFor="audit-actor">Person</Label><select id="audit-actor" value={actor} onChange={(event) => setActor(event.target.value)}><option value="">Anyone</option>{members.map((member) => <option key={member.identity_id} value={member.identity_id}>{member.display_name}</option>)}</select></div>
        <div><Label htmlFor="audit-since">From</Label><Input id="audit-since" type="date" value={since} onChange={(event) => setSince(event.target.value)} /></div>
        <div><Label htmlFor="audit-until">To</Label><Input id="audit-until" type="date" value={until} onChange={(event) => setUntil(event.target.value)} /></div>
      </div>
      {message && <p className="form-message" role="status">{message}</p>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : events.length === 0 ? <div className="empty-state"><ShieldCheck /><p>No events match these filters.</p></div> :
        <ol className="audit-timeline">{events.map((event) => <li key={event.sequence}>
          <button onClick={() => setExpanded(expanded === event.sequence ? null : event.sequence)} aria-expanded={expanded === event.sequence}>
            <span className={`audit-dot ${event.action.startsWith("item.") ? "access" : event.action.includes("policy") || event.action.includes("admin") || event.action.includes("role") ? "admin" : ""}`} />
            <span className="audit-main"><strong>{describeAuditAction(event.action)}</strong><small>{event.actor_name} · {new Date(event.occurred_at).toLocaleString()}{metadataSummary(event) ? ` · ${metadataSummary(event)}` : ""}</small></span>
            <span className="audit-seq">#{event.sequence}</span>
          </button>
          {expanded === event.sequence && <dl className="audit-detail">
            <dt>Action</dt><dd><code>{event.action}</code></dd>
            <dt>Target</dt><dd><code>{event.target_type}{event.target_id ? ` · ${event.target_id}` : ""}</code></dd>
            <dt>Metadata</dt><dd><code>{JSON.stringify(event.metadata)}</code></dd>
            <dt>Event hash</dt><dd><code>{event.event_hash}</code> <em>v{event.hash_version}</em></dd>
          </dl>}
        </li>)}</ol>}
      {more && !loading && <div className="inline-actions center"><Button variant="outline" onClick={() => void loadMore()} disabled={busy !== ""}>{busy === "more" ? <LoaderCircle className="spin" /> : <Download />} Load older events</Button></div>}
    </CardContent>
  </Card>;
}
