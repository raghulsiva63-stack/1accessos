"use client";

import { useEffect, useState } from "react";
import { Check, Globe, HardDrive, Laptop, RefreshCw, RotateCcw, ShieldAlert, ShieldCheck, Smartphone, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { relativeTime } from "@/lib/enterprise/admin";
import {
  EMPTY_GUARD_POLICY, findingLabel, organizationGuardEndpoints, organizationGuardFindings, organizationGuardOverview, organizationThreatReports,
  parseGuardPolicy, reviewThreatReport, setGuardFindingStatus, setGuardPolicy,
  type GuardOverview, type GuardPolicyRecord, type OrganizationEndpoint, type OrganizationFinding, type ThreatReport,
} from "@/lib/security/guard-client";
import type { WorkspaceVault } from "@/lib/vault/items";

type View = "overview" | "findings" | "devices" | "reports" | "policy" | "deploy";
const VIEWS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "devices", label: "Devices" },
  { id: "reports", label: "Phishing reports" }, { id: "policy", label: "Policy" }, { id: "deploy", label: "Deploy" },
];
const CATEGORIES = [
  { id: null, label: "All" }, { id: "web", label: "Websites" }, { id: "software", label: "Software" }, { id: "device", label: "Devices" }, { id: "account", label: "Accounts" },
] as const;
const severityTag = (severity: string) => severity === "critical" || severity === "high" ? "bad" : severity === "medium" ? "warn" : "good";

/** Admin console › Threat Center: Passkey-X Guard across the organization. */
export function GuardPanel({ vault, canEdit }: { vault: WorkspaceVault; canEdit: boolean }) {
  const [view, setView] = useState<View>("overview");
  const [overview, setOverview] = useState<GuardOverview | null>(null);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);
  const now = useNow();

  useEffect(() => {
    let active = true;
    organizationGuardOverview(vault.tenantId).then((value) => { if (active) { setOverview(value); setMessage(""); } },
      (reason) => { if (active) setMessage(adminErrorMessage(reason, "Threat Center could not be loaded.")); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  const refresh = () => setVersion((value) => value + 1);
  return <div className="si-stack">
    <Card>
      <CardHeader>
        <div className="panel-heading"><div><CardTitle>Threat Center</CardTitle>
          <CardDescription>Passkey-X Guard checks every website your people open, the software on their computers and the security of their devices. Pages are checked on the device: you see threats that were found, never browsing history.</CardDescription></div>
          <Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={refresh}><RefreshCw /></Button></div>
        <div className="billing-segment" role="tablist" aria-label="Threat Center">{VIEWS.map((entry) => <button key={entry.id} role="tab" aria-selected={view === entry.id} className={view === entry.id ? "active" : ""} onClick={() => setView(entry.id)}>
          {entry.label}{entry.id === "reports" && overview?.pendingReports ? ` (${overview.pendingReports})` : ""}</button>)}</div>
      </CardHeader>
      <CardContent>
        {message && <p className="form-message" role="alert">{message}</p>}
        {view === "overview" && <OverviewView overview={overview} onNavigate={setView} />}
        {view === "findings" && <FindingsView tenantId={vault.tenantId} canEdit={canEdit} now={now} onChanged={refresh} />}
        {view === "devices" && <DevicesView tenantId={vault.tenantId} now={now} />}
        {view === "reports" && <ReportsView tenantId={vault.tenantId} canEdit={canEdit} onChanged={refresh} />}
        {view === "policy" && <PolicyView key={overview ? "loaded" : "empty"} tenantId={vault.tenantId} canEdit={canEdit} initial={overview?.policy ?? null} onSaved={refresh} />}
        {view === "deploy" && <DeployView />}
      </CardContent>
    </Card>
  </div>;
}

function useNow() {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 60_000); return () => clearInterval(timer); }, []);
  return now;
}

function OverviewView({ overview, onNavigate }: { overview: GuardOverview | null; onNavigate: (view: View) => void }) {
  if (!overview) return <div className="vault-loading"><div className="loading-ring" /></div>;
  const serious = overview.open.critical + overview.open.high;
  const protectedShare = overview.members ? Math.round((overview.coverage.any / overview.members) * 100) : 0;
  return <div className="si-stack">
    <div className="si-kpis">
      <button className="si-kpi" onClick={() => onNavigate("findings")}><small>Serious threats open</small><strong>{serious}</strong><span>{overview.open.medium} medium · {overview.open.low} low</span></button>
      <div className="si-kpi"><small>Dangerous sites, 7 days</small><strong>{overview.last7Days.blocked + overview.last7Days.warned}</strong><span>{overview.last7Days.blocked} blocked · {overview.last7Days.proceeded} continued anyway</span></div>
      <button className="si-kpi" onClick={() => onNavigate("devices")}><small>People protected</small><strong>{protectedShare}%</strong><span>{overview.coverage.any} of {overview.members} people</span></button>
      <button className="si-kpi" onClick={() => onNavigate("devices")}><small>Devices at risk</small><strong>{overview.devices.atRisk}</strong><span>of {overview.devices.total} computers and phones</span></button>
    </div>
    <div>
      <h4 className="guard-heading">Coverage</h4>
      {([["Browser extension", overview.coverage.extension, Globe], ["Desktop app", overview.coverage.desktop, Laptop], ["Mobile app", overview.coverage.mobile, Smartphone]] as const).map(([label, value, Icon]) =>
        <div key={label} className="guard-coverage"><Icon aria-hidden="true" /><span>{label}</span>
          <div className="si-bar" aria-hidden="true"><span style={{ width: `${overview.members ? Math.min(100, (value / overview.members) * 100) : 0}%` }} /></div>
          <strong>{value}/{overview.members}</strong></div>)}
      {overview.coverage.extension < overview.members && <p className="field-hint">People without the extension aren&apos;t warned about phishing in their browser. <button className="link-button" onClick={() => onNavigate("deploy")}>Install it for everyone</button>.</p>}
    </div>
    {overview.pendingReports > 0 && <p className="desktop-managed-note"><ShieldAlert aria-hidden="true" /><span>{overview.pendingReports} page{overview.pendingReports === 1 ? "" : "s"} reported as phishing by your people. <button className="link-button" onClick={() => onNavigate("reports")}>Review</button></span></p>}
  </div>;
}

function FindingsView({ tenantId, canEdit, now, onChanged }: { tenantId: string; canEdit: boolean; now: number; onChanged: () => void }) {
  const [status, setStatus] = useState<"open" | "resolved" | "dismissed">("open");
  const [category, setCategory] = useState<string | null>(null);
  const [rows, setRows] = useState<OrganizationFinding[] | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    organizationGuardFindings(tenantId, status, category).then((value) => { if (active) setRows(value); },
      (reason) => { if (active) setMessage(adminErrorMessage(reason, "Findings could not be loaded.")); });
    return () => { active = false; };
  }, [tenantId, status, category, version]);

  async function change(row: OrganizationFinding, next: "open" | "resolved" | "dismissed") {
    setBusy(row.id); setMessage("");
    try { await setGuardFindingStatus(tenantId, row.id, next); setVersion((value) => value + 1); onChanged(); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The finding could not be updated.")); }
    finally { setBusy(null); }
  }

  return <div className="si-stack">
    <div className="guard-filters">
      <div className="billing-segment" role="group" aria-label="Status">{(["open", "resolved", "dismissed"] as const).map((entry) => <button key={entry} className={status === entry ? "active" : ""} onClick={() => setStatus(entry)}>{entry[0].toUpperCase() + entry.slice(1)}</button>)}</div>
      <div className="billing-segment" role="group" aria-label="Type">{CATEGORIES.map((entry) => <button key={entry.label} className={category === entry.id ? "active" : ""} onClick={() => setCategory(entry.id)}>{entry.label}</button>)}</div>
    </div>
    {message && <p className="form-message" role="alert">{message}</p>}
    {!rows ? <div className="vault-loading"><div className="loading-ring" /></div> : rows.length === 0 ?
      <div className="empty-state"><ShieldCheck /><p>{status === "open" ? "No open threats. Nice." : "Nothing here."}</p></div> :
      <ul className="si-list">{rows.map((row) => <li key={row.id} className={`si-row ${severityTag(row.severity) === "bad" ? "danger" : severityTag(row.severity) === "warn" ? "warn" : ""}`}>
        {row.category === "web" ? <Globe aria-hidden="true" /> : row.category === "software" ? <HardDrive aria-hidden="true" /> : <ShieldAlert aria-hidden="true" />}
        <div className="si-main">
          <strong>{findingLabel(row.kind)}: {row.subject}</strong>
          <small>{row.member_name}{row.endpoint_label ? ` · ${row.endpoint_label}` : ""} · {row.action}{row.occurrences > 1 ? ` ${row.occurrences}×` : ""} · {relativeTime(row.last_seen_at, now)}{typeof row.detail.why === "string" ? ` · ${row.detail.why}` : ""}</small>
        </div>
        <span className={`si-tag ${severityTag(row.severity)}`}>{row.severity}</span>
        {canEdit && <div className="inline-actions">
          {row.status === "open" ? <>
            <Button size="sm" variant="outline" disabled={busy === row.id} onClick={() => void change(row, "resolved")}><Check /> Resolved</Button>
            <Button size="sm" variant="ghost" disabled={busy === row.id} onClick={() => void change(row, "dismissed")}><X /> Dismiss</Button>
          </> : <Button size="sm" variant="ghost" disabled={busy === row.id} onClick={() => void change(row, "open")}><RotateCcw /> Reopen</Button>}
        </div>}
      </li>)}</ul>}
  </div>;
}

const POSTURE_LABELS: [string, string][] = [
  ["disk_encrypted", "Encryption"], ["firewall", "Firewall"], ["antivirus", "Antivirus"], ["os_supported", "OS updates"],
  ["browser_protection", "Browser"], ["screen_lock", "Screen lock"],
];

function DevicesView({ tenantId, now }: { tenantId: string; now: number }) {
  const [rows, setRows] = useState<OrganizationEndpoint[] | null>(null);
  const [message, setMessage] = useState("");
  useEffect(() => {
    let active = true;
    organizationGuardEndpoints(tenantId).then((value) => { if (active) setRows(value); },
      (reason) => { if (active) setMessage(adminErrorMessage(reason, "Devices could not be loaded.")); });
    return () => { active = false; };
  }, [tenantId]);
  if (message) return <p className="form-message" role="alert">{message}</p>;
  if (!rows) return <div className="vault-loading"><div className="loading-ring" /></div>;
  if (!rows.length) return <div className="empty-state"><Laptop /><p>No protected devices yet. Install the desktop app, the mobile app or the browser extension.</p></div>;
  return <div className="table-scroll"><table className="si-table">
    <thead><tr><th>Person</th><th>Device</th><th>Security</th><th>Problems</th><th>Last seen</th></tr></thead>
    <tbody>{rows.map((row) => <tr key={row.id}>
      <td>{row.member_name}<br /><small>{row.member_email}</small></td>
      <td>{row.kind === "extension" ? "Browser extension" : row.kind === "mobile" ? "Phone" : "Computer"} · {row.label || row.platform}<br /><small>{row.os_version ?? ""}{row.app_version ? ` · app ${row.app_version}` : ""}{row.software_total ? ` · ${row.software_total} programs` : ""}</small></td>
      <td><div className="guard-badges">{POSTURE_LABELS.filter(([key]) => typeof row.posture[key] === "boolean").map(([key, label]) =>
        <span key={key} className={`si-tag ${row.posture[key] ? "good" : "bad"}`}>{label}</span>)}
        {row.posture.rooted === true && <span className="si-tag bad">Rooted</span>}</div></td>
      <td>{row.open_findings ? <span className="si-tag bad">{row.open_findings} open</span> : <span className="si-tag good">None</span>}</td>
      <td>{relativeTime(row.last_seen_at, now)}</td>
    </tr>)}</tbody>
  </table></div>;
}

function ReportsView({ tenantId, canEdit, onChanged }: { tenantId: string; canEdit: boolean; onChanged: () => void }) {
  const [rows, setRows] = useState<ThreatReport[] | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let active = true;
    organizationThreatReports(tenantId, "pending").then((value) => { if (active) setRows(value); },
      (reason) => { if (active) setMessage(adminErrorMessage(reason, "Reports could not be loaded.")); });
    return () => { active = false; };
  }, [tenantId, version]);
  async function review(row: ThreatReport, confirm: boolean) {
    setBusy(row.id); setMessage("");
    try { await reviewThreatReport(tenantId, row.id, confirm); setVersion((value) => value + 1); onChanged(); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The report could not be reviewed.")); }
    finally { setBusy(null); }
  }
  return <div className="si-stack">
    <p className="field-hint">Pages your people reported as phishing. Confirming blocks the page for everyone in your organization. When three organizations confirm the same page, Passkey-X blocks it for all customers for 30 days.</p>
    {message && <p className="form-message" role="alert">{message}</p>}
    {!rows ? <div className="vault-loading"><div className="loading-ring" /></div> : rows.length === 0 ?
      <div className="empty-state"><ShieldCheck /><p>No reports waiting for review.</p></div> :
      <ul className="si-list">{rows.map((row) => <li key={row.id} className="si-row warn">
        <Globe aria-hidden="true" />
        <div className="si-main"><strong className="guard-mono">{row.expression}</strong>
          <small>{row.member_email ?? "A member"} · {new Date(row.created_at).toLocaleString()}{row.note ? ` · “${row.note}”` : ""}{row.confirmed_elsewhere ? ` · confirmed by ${row.confirmed_elsewhere} other organization${row.confirmed_elsewhere === 1 ? "" : "s"}` : ""}</small></div>
        {canEdit && <div className="inline-actions">
          <Button size="sm" disabled={busy === row.id} onClick={() => void review(row, true)}><ShieldAlert /> Block</Button>
          <Button size="sm" variant="ghost" disabled={busy === row.id} onClick={() => void review(row, false)}>Not phishing</Button>
        </div>}
      </li>)}</ul>}
  </div>;
}

const lines = (value: string) => value.split(/[\n,]+/u).map((entry) => entry.trim()).filter(Boolean);

function PolicyView({ tenantId, canEdit, initial, onSaved }: { tenantId: string; canEdit: boolean; initial: Record<string, unknown> | null; onSaved: () => void }) {
  const [policy, setPolicy] = useState<GuardPolicyRecord>(() => initial && Object.keys(initial).length ? parseGuardPolicy(initial) : EMPTY_GUARD_POLICY);
  const [text, setText] = useState(() => ({
    blockDomains: policy.blockDomains.join("\n"), allowDomains: policy.allowDomains.join("\n"), protectedDomains: policy.protectedDomains.join("\n"),
    softwareBlock: policy.softwareBlock.join("\n"), softwareAllow: policy.softwareAllow.join("\n"),
  }));
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const update = (patch: Partial<GuardPolicyRecord>) => setPolicy((current) => ({ ...current, ...patch }));

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      await setGuardPolicy(tenantId, {
        ...policy, blockDomains: lines(text.blockDomains), allowDomains: lines(text.allowDomains), protectedDomains: lines(text.protectedDomains),
        softwareBlock: lines(text.softwareBlock), softwareAllow: lines(text.softwareAllow),
      });
      setMessage("Saved. Devices pick up the new policy within a few hours (or when they restart).");
      onSaved();
    } catch (reason) { setMessage(adminErrorMessage(reason, "The policy could not be saved.")); }
    finally { setBusy(false); }
  }

  const area = (key: keyof typeof text, label: string, hint: string) => <div className="guard-field">
    <Label htmlFor={`guard-${key}`}>{label}</Label>
    <textarea id={`guard-${key}`} rows={4} value={text[key]} disabled={!canEdit} onChange={(event) => setText((current) => ({ ...current, [key]: event.target.value }))} />
    <small className="field-hint">{hint}</small>
  </div>;

  return <form className="si-stack" onSubmit={save}>
    <fieldset className="guard-fieldset" disabled={!canEdit}>
      <legend>When a dangerous website is found</legend>
      {([["warn", "Warn", "Show a full-page warning. People can continue after confirming; you see that they did."],
        ["block", "Block", "Show the warning without a way to continue."],
        ["off", "Off", "Don't check websites (not recommended)."]] as const).map(([value, label, hint]) =>
        <label key={value} className="guard-choice"><input type="radio" name="web-mode" checked={policy.webMode === value} onChange={() => update({ webMode: value })} /><span><strong>{label}</strong><small>{hint}</small></span></label>)}
      <label className="guard-choice"><input type="checkbox" checked={policy.blockSuspicious} onChange={(event) => update({ blockSuspicious: event.target.checked })} />
        <span><strong>Also stop suspicious login pages</strong><small>For example a password form without encryption or on a site that resembles a known brand.</small></span></label>
      <label className="guard-choice"><input type="checkbox" checked={policy.communityIntel} onChange={(event) => update({ communityIntel: event.target.checked })} />
        <span><strong>Use Passkey-X community reports</strong><small>Block pages that three or more organizations confirmed as phishing.</small></span></label>
    </fieldset>
    <fieldset className="guard-fieldset" disabled={!canEdit}>
      <legend>Required protection</legend>
      <label className="guard-choice"><input type="checkbox" checked={policy.requireExtension} onChange={(event) => update({ requireExtension: event.target.checked })} />
        <span><strong>Browser extension is required</strong><small>Computers with an unprotected browser are reported as a high-risk finding.</small></span></label>
      <label className="guard-choice"><input type="checkbox" checked={policy.requireDesktop} onChange={(event) => update({ requireDesktop: event.target.checked })} />
        <span><strong>Desktop app is required</strong><small>Shown as missing coverage for people without it.</small></span></label>
      <div className="guard-field"><Label htmlFor="guard-org-name">Name shown on warnings</Label>
        <Input id="guard-org-name" maxLength={80} value={policy.organizationName ?? ""} placeholder="Acme Corp" onChange={(event) => update({ organizationName: event.target.value || null })} /></div>
    </fieldset>
    <div className="si-grid-2">
      {area("blockDomains", "Blocked websites", "One domain per line; subdomains are included.")}
      {area("allowDomains", "Always allowed websites", "Internal or partner sites that should never be flagged.")}
      {area("protectedDomains", "Your organization's domains", "Look-alikes of these (for example acme-login.com) are blocked.")}
      {area("softwareBlock", "Blocked software", "Program names (or part of them), one per line.")}
      {area("softwareAllow", "Approved software", "Remote-control or other tools your IT team uses on purpose.")}
    </div>
    {message && <p className="form-message" role="status">{message}</p>}
    {canEdit && <div className="inline-actions"><Button disabled={busy}>{busy ? "Saving…" : "Save policy"}</Button></div>}
  </form>;
}

function DeployView() {
  return <div className="si-stack guard-deploy">
    <p>Install Guard everywhere so every browser, computer and phone is protected. These settings can&apos;t be removed by the people who use the devices.</p>
    <h4 className="guard-heading">Browser extension (Chrome and Edge)</h4>
    <p className="field-hint">Force-install the extension with your management tool. Google Admin console: Devices › Chrome › Apps &amp; extensions › add by ID › &quot;Force install&quot;. Microsoft Intune / Group Policy: the browser&apos;s <code>ExtensionInstallForcelist</code> policy.</p>
    <pre className="guard-code">{`Windows registry (Chrome):
HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist
  1 = <Passkey-X extension ID>;https://clients2.google.com/service/update2/crx

Windows registry (Edge):
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist
  1 = <Passkey-X extension ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`}</pre>
    <h4 className="guard-heading">Desktop app</h4>
    <p className="field-hint">Deploy the MSI (Windows), PKG/DMG (macOS) or .deb (Linux) and turn on &quot;Start at sign-in&quot; with the Passkey-X policy templates. See the managed deployment guide on the Download page.</p>
    <h4 className="guard-heading">Phones</h4>
    <p className="field-hint">Publish the Passkey-X Android app through managed Google Play. People can share any suspicious link to Passkey-X to check it.</p>
  </div>;
}
