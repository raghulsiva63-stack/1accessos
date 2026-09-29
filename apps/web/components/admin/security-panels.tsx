"use client";

import { useEffect, useMemo, useState } from "react";
import {
  BellRing, CalendarClock, Check, Fingerprint, LoaderCircle, MailWarning, Plus, Printer, RefreshCw, Send, ShieldCheck, Sparkles, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import type { MemberOverview } from "@/lib/enterprise/admin";
import { analyzeVaultHealth } from "@/lib/security/score";
import {
  acknowledgeBreachExposure, aiErrorMessage, askSecurityAi, breachWatchEnabled, closeRotationCampaign, createRotationCampaign, generateSecurityReportNow,
  listBreachExposures, listWeeklyReports, organizationBreachWatch, organizationPasskeyAdoption, rotationCampaignSummary,
  sendPasskeyNudges, setBreachWatch, workspaceEditors,
  type BreachExposure, type MemberBreachSummary, type PasskeyAdoptionRow, type RotationCampaign, type StoredReport,
} from "@/lib/security/client";
import type { VaultItem, WorkspaceVault } from "@/lib/vault/items";

function day(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString();
}

function Kpi({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return <div className="si-kpi"><small>{label}</small><strong>{value}</strong>{detail && <span>{detail}</span>}</div>;
}

// ---------------------------------------------------------------------------
// Breach watch
// ---------------------------------------------------------------------------
export function BreachWatchPanel({ vault, canEdit }: { vault: WorkspaceVault; canEdit: boolean }) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [rows, setRows] = useState<MemberBreachSummary[]>([]);
  const [details, setDetails] = useState<BreachExposure[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void Promise.all([breachWatchEnabled(vault.tenantId), organizationBreachWatch(vault.tenantId), listBreachExposures(vault.tenantId)]).then(
      ([on, summary, exposures]) => { if (active) { setEnabled(on); setRows(summary); setDetails(exposures); setMessage(""); } },
      (reason) => { if (active) { setEnabled(false); setMessage(adminErrorMessage(reason, "Breach watch could not be loaded.")); } });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function toggle(next: boolean) {
    if (next && !window.confirm("Turn on Breach watch? Once a week, each member's work email address is checked against Have I Been Pwned. Only the email address is sent; members are told when their email appears in a new breach.")) return;
    setBusy(true); setMessage("");
    try { await setBreachWatch(vault.tenantId, next); setVersion((value) => value + 1); }
    catch (reason) { setMessage(adminErrorMessage(reason, "Breach watch could not be changed.")); }
    finally { setBusy(false); }
  }

  const checked = rows.filter((row) => row.last_checked_at).length;
  const exposed = rows.filter((row) => row.password_exposures > 0).length;
  const unacknowledged = rows.reduce((sum, row) => sum + row.unacknowledged, 0);

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><MailWarning /> Employee breach watch</CardTitle>
        <CardDescription>Checks every member&apos;s work email against Have I Been Pwned once a week and alerts you (and them) when it shows up in a new breach. Only email addresses are sent to Have I Been Pwned; only breach names, dates and data types are stored.</CardDescription></div>
        {enabled !== null && <Button size="sm" variant={enabled ? "outline" : "default"} disabled={busy || !canEdit} onClick={() => void toggle(!enabled)}>{busy ? <LoaderCircle className="spin" /> : enabled ? <X /> : <ShieldCheck />} {enabled ? "Turn off" : "Turn on"}</Button>}</div>
    </CardHeader>
    <CardContent className="si-stack">
      {message && <p className="form-message" role="alert">{message}</p>}
      {enabled === null ? <div className="loading-ring" /> : <>
        <div className="si-kpis">
          <Kpi label="Status" value={enabled ? "On" : "Off"} detail={enabled ? "weekly checks" : "no emails are checked"} />
          <Kpi label="Members checked" value={`${checked}/${rows.length}`} detail={enabled && checked < rows.length ? "first checks run over the next hours" : undefined} />
          <Kpi label="Passwords exposed" value={exposed} detail="members in a breach that included passwords" />
          <Kpi label="Not yet handled" value={unacknowledged} detail="breach listings members haven't confirmed" />
        </div>
        {rows.some((row) => row.exposures > 0) ? <div className="si-table-wrap"><table className="si-table">
          <thead><tr><th>Member</th><th className="num">Breaches</th><th className="num">With passwords</th><th>Latest breach</th><th>Last checked</th><th /></tr></thead>
          <tbody>{rows.filter((row) => row.exposures > 0).map((row) => <FragmentRow key={row.identity_id} row={row} open={open === row.identity_id}
            onToggle={() => setOpen(open === row.identity_id ? null : row.identity_id)} details={details.filter((entry) => entry.identity_id === row.identity_id)}
            onHandled={canEdit ? (entry) => void acknowledgeBreachExposure(vault.tenantId, entry.identity_id, entry.breach_name).then(() => setVersion((value) => value + 1), (reason) => setMessage(adminErrorMessage(reason, "Could not mark it handled."))) : undefined} />)}</tbody>
        </table></div> : <div className="empty-state"><ShieldCheck /><p>{enabled ? (checked ? "No member emails found in known breaches." : "Waiting for the first checks.") : "Turn on Breach watch to start weekly checks."}</p></div>}
        <p className="field-hint">Tip: when someone&apos;s email shows up in a breach that included passwords, start a rotation campaign for shared logins they know.</p>
      </>}
    </CardContent>
  </Card>;
}

function FragmentRow({ row, open, onToggle, details, onHandled }: { row: MemberBreachSummary; open: boolean; onToggle: () => void; details: BreachExposure[]; onHandled?: (entry: BreachExposure) => void }) {
  return <>
    <tr>
      <td><strong>{row.display_name}</strong><br /><small className="muted-text">{row.email}</small></td>
      <td className="num">{row.exposures}</td>
      <td className="num">{row.password_exposures > 0 ? <span className="si-tag bad">{row.password_exposures}</span> : 0}</td>
      <td>{day(row.latest_breach_date)}</td>
      <td>{day(row.last_checked_at)}</td>
      <td><Button size="sm" variant="ghost" onClick={onToggle}>{open ? "Hide" : "Details"}</Button></td>
    </tr>
    {open && <tr><td colSpan={6}><ul className="si-list">{details.map((entry) => <li key={entry.breach_name} className={`si-row ${entry.includes_passwords ? "danger" : ""}`}>
      <MailWarning /><div className="si-main"><strong>{entry.breach_title}</strong><small>{day(entry.breach_date)} · {entry.data_classes.slice(0, 6).join(", ")}</small></div>
      {entry.member_acknowledged_at && <span className="si-tag">Member says handled</span>}
      {entry.acknowledged_at ? <span className="si-tag good"><Check /> Handled</span> : onHandled ? <Button size="sm" variant="outline" onClick={() => onHandled(entry)}>Mark handled</Button> : <span className="si-tag warn">Open</span>}
    </li>)}</ul></td></tr>}
  </>;
}

// ---------------------------------------------------------------------------
// Passkey adoption
// ---------------------------------------------------------------------------
export function PasskeyAdoptionPanel({ vault, canEdit, onOpenPolicies }: { vault: WorkspaceVault; canEdit: boolean; onOpenPolicies: () => void }) {
  const [rows, setRows] = useState<PasskeyAdoptionRow[] | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void organizationPasskeyAdoption(vault.tenantId).then((data) => { if (active) { setRows(data); setSelected([]); } },
      (reason) => { if (active) { setRows([]); setMessage(adminErrorMessage(reason, "Passkey adoption could not be loaded.")); } });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  const list = rows ?? [];
  const withPasskey = list.filter((row) => row.account_passkeys > 0).length;
  const twoStep = list.filter((row) => row.account_passkeys > 0 || row.two_step_methods > 0).length;
  const ready = list.reduce((sum, row) => sum + row.passkey_ready_sites, 0);
  const vaultPasskeys = list.reduce((sum, row) => sum + row.vault_passkeys, 0);
  const pct = (value: number) => list.length ? Math.round((value / list.length) * 100) : 0;
  const nudgeable = list.filter((row) => row.account_passkeys === 0);

  async function nudge() {
    setBusy(true); setMessage("");
    try {
      const sent = await sendPasskeyNudges(vault.tenantId, selected);
      setMessage(sent ? `Reminder emailed to ${sent} member${sent === 1 ? "" : "s"}.` : "Nobody new to remind — reminders go at most once a week per person.");
      setVersion((value) => value + 1);
    } catch (reason) { setMessage(adminErrorMessage(reason, "Reminders could not be sent.")); }
    finally { setBusy(false); }
  }

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><Fingerprint /> Passkey adoption</CardTitle>
        <CardDescription>Passkeys can&apos;t be phished or reused. Track who signs in with one, how many of your team&apos;s saved sites already support passkeys, and send friendly reminders.</CardDescription></div>
        <div className="inline-actions"><Button size="sm" variant="outline" onClick={onOpenPolicies}>Require passkeys…</Button></div></div>
    </CardHeader>
    <CardContent className="si-stack">
      {message && <p className="form-message neutral-message" role="status">{message}</p>}
      {rows === null ? <div className="loading-ring" /> : <>
        <div className="si-kpis">
          <Kpi label="Account passkeys" value={`${pct(withPasskey)}%`} detail={`${withPasskey} of ${list.length} members`} />
          <Kpi label="Two-step coverage" value={`${pct(twoStep)}%`} detail="passkey or second factor" />
          <Kpi label="Passkey-ready sites" value={ready} detail="saved logins where a passkey is possible" />
          <Kpi label="Passkeys in vaults" value={vaultPasskeys} />
        </div>
        <div className="si-bar" aria-hidden><span style={{ width: `${pct(withPasskey)}%` }} /></div>
        <div className="si-table-wrap"><table className="si-table">
          <thead><tr><th><input type="checkbox" aria-label="Select everyone without a passkey" checked={nudgeable.length > 0 && selected.length === nudgeable.length} onChange={(event) => setSelected(event.target.checked ? nudgeable.map((row) => row.identity_id) : [])} /></th>
            <th>Member</th><th>Account passkey</th><th className="num">2-step methods</th><th className="num">Passkey-ready sites</th><th>Last reminded</th></tr></thead>
          <tbody>{list.map((row) => <tr key={row.identity_id}>
            <td>{row.account_passkeys === 0 && <input type="checkbox" aria-label={`Select ${row.display_name}`} checked={selected.includes(row.identity_id)} onChange={(event) => setSelected(event.target.checked ? [...selected, row.identity_id] : selected.filter((id) => id !== row.identity_id))} />}</td>
            <td><strong>{row.display_name}</strong><br /><small className="muted-text">{row.email}</small></td>
            <td>{row.account_passkeys > 0 ? <span className="si-tag good"><Check /> {row.account_passkeys}</span> : <span className="si-tag warn">None</span>}</td>
            <td className="num">{row.two_step_methods}</td>
            <td className="num">{row.passkey_ready_sites}</td>
            <td>{day(row.last_nudged_at)}</td>
          </tr>)}</tbody>
        </table></div>
        <div className="inline-actions"><Button disabled={!selected.length || busy || !canEdit} onClick={() => void nudge()}>{busy ? <LoaderCircle className="spin" /> : <Send />} Email a passkey reminder ({selected.length})</Button></div>
      </>}
    </CardContent>
  </Card>;
}

// ---------------------------------------------------------------------------
// Guided password rotation
// ---------------------------------------------------------------------------
export function RotationPanel({ vault, items, members, canEdit }: { vault: WorkspaceVault; items: VaultItem[]; members: MemberOverview[]; canEdit: boolean }) {
  const { identityId } = useEnterprise();
  const [campaigns, setCampaigns] = useState<RotationCampaign[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void rotationCampaignSummary(vault.tenantId).then((data) => { if (active) setCampaigns(data); },
      (reason) => { if (active) { setCampaigns([]); setMessage(adminErrorMessage(reason, "Rotation campaigns could not be loaded.")); } });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function close(campaign: RotationCampaign) {
    if (!window.confirm(`Close “${campaign.title}”? Open tasks stay in the report but members stop seeing them.`)) return;
    setBusy(campaign.id);
    try { await closeRotationCampaign(campaign.id); setVersion((value) => value + 1); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The campaign could not be closed.")); }
    finally { setBusy(""); }
  }

  return <div className="si-stack">
    <Card>
      <CardHeader>
        <div className="panel-heading"><div><CardTitle><CalendarClock /> Password rotation campaigns</CardTitle>
          <CardDescription>Ask people to change specific shared passwords by a deadline — after someone leaves, after a breach, or on a schedule. Tasks complete automatically when the item is saved with a change. Only item IDs are stored; titles stay encrypted.</CardDescription></div>
          <Button size="sm" disabled={!canEdit} onClick={() => setCreating(!creating)}>{creating ? <X /> : <Plus />} {creating ? "Cancel" : "New campaign"}</Button></div>
      </CardHeader>
      <CardContent className="si-stack">
        {message && <p className="form-message" role="alert">{message}</p>}
        {creating && <NewCampaign vault={vault} items={items} members={members} identityId={identityId} onCreated={() => { setCreating(false); setVersion((value) => value + 1); }} />}
        {campaigns === null ? <div className="loading-ring" /> : campaigns.length === 0 ? <div className="empty-state"><CalendarClock /><p>No campaigns yet.</p></div> :
          <ul className="si-list">{campaigns.map((campaign) => {
            const finished = campaign.done + campaign.skipped + campaign.cancelled;
            const pct = campaign.total ? Math.round((finished / campaign.total) * 100) : 0;
            return <li key={campaign.id} className={`si-row ${campaign.overdue ? "danger" : ""}`}>
              <CalendarClock />
              <div className="si-main"><strong>{campaign.title}{campaign.status === "closed" ? " · closed" : ""}</strong>
                <small>Due {day(campaign.due_at)} · {campaign.done} changed · {campaign.skipped} skipped · {campaign.pending} open{campaign.reason ? ` · ${campaign.reason}` : ""}</small>
                <div className="si-bar"><span style={{ width: `${pct}%` }} /></div></div>
              {campaign.overdue && <span className="si-tag bad">Overdue</span>}
              {campaign.status === "open" && canEdit && <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void close(campaign)}>{busy === campaign.id ? <LoaderCircle className="spin" /> : null} Close</Button>}
            </li>;
          })}</ul>}
      </CardContent>
    </Card>
  </div>;
}

function NewCampaign({ vault, items, members, identityId, onCreated }: { vault: WorkspaceVault; items: VaultItem[]; members: MemberOverview[]; identityId: string; onCreated: () => void }) {
  const defaultDue = new Date(Date.now() + 14 * 86_400_000).toISOString().slice(0, 10);
  const [title, setTitle] = useState("");
  const [reason, setReason] = useState("");
  const [due, setDue] = useState(defaultDue);
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [editors, setEditors] = useState<string[]>([]);
  const [assignee, setAssignee] = useState(identityId);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    void workspaceEditors(vault.tenantId, vault.workspaceId).then((ids) => { if (active) setEditors(ids); }, () => undefined);
    return () => { active = false; };
  }, [vault.tenantId, vault.workspaceId]);

  const candidates = useMemo(() => items.filter((item) => !item.deletedAt && !item.payload.archived && item.payload.secret), [items]);
  const flagged = useMemo(() => {
    const report = analyzeVaultHealth(candidates);
    return new Set([...report.weak, ...report.reused.flat(), ...report.old, ...report.breached]);
  }, [candidates]);
  const visible = candidates.filter((item) => !query || `${item.payload.title} ${item.payload.url ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  const names = new Map(members.map((member) => [member.identity_id, member.display_name]));

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!picked.length) { setMessage("Choose at least one item."); return; }
    setBusy(true); setMessage("");
    try {
      await createRotationCampaign(vault.tenantId, title.trim(), reason.trim(), new Date(`${due}T17:00:00`), picked.map((itemId) => ({ itemId, assigneeIdentityId: assignee })));
      onCreated();
    } catch (reason) {
      setMessage(/assignee cannot edit/iu.test(String((reason as { message?: string })?.message)) ? "That person can't edit this workspace. Give them edit access first or choose someone else."
        : /due date/iu.test(String((reason as { message?: string })?.message)) ? "Choose a due date between tomorrow and one year from now." : adminErrorMessage(reason, "The campaign could not be created."));
    } finally { setBusy(false); }
  }

  return <form className="si-form" onSubmit={submit}>
    <div className="si-grid-2">
      <label>Campaign name<input type="text" required minLength={3} maxLength={120} value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Contractor offboarding — Q4" /></label>
      <label>Due date<input type="date" required value={due} min={new Date(Date.now() + 86_400_000).toISOString().slice(0, 10)} onChange={(event) => setDue(event.target.value)} /></label>
    </div>
    <div className="si-grid-2">
      <label>Reason (shown to assignees)<input type="text" maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="A contractor with access left" /></label>
      <label>Assign to<select value={assignee} onChange={(event) => setAssignee(event.target.value)}>
        {[...new Set([identityId, ...editors])].filter((id) => editors.includes(id) || id === identityId).map((id) => <option key={id} value={id}>{id === identityId ? "Me" : names.get(id) ?? "Member"}</option>)}
      </select></label>
    </div>
    <label>Items in “{vault.name}” <small className="muted-text">(switch workspace to rotate items elsewhere)</small>
      <input type="text" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search" /></label>
    <div className="inline-actions">
      <Button type="button" size="sm" variant="outline" onClick={() => setPicked(candidates.filter((item) => flagged.has(item.id)).map((item) => item.id))}>Select weak, reused, old and breached ({flagged.size})</Button>
      <Button type="button" size="sm" variant="ghost" onClick={() => setPicked([])}>Clear</Button>
    </div>
    <div className="si-pick">{visible.slice(0, 300).map((item) => <label key={item.id}>
      <input type="checkbox" checked={picked.includes(item.id)} onChange={(event) => setPicked(event.target.checked ? [...picked, item.id] : picked.filter((id) => id !== item.id))} />
      <span>{item.payload.title}</span>{flagged.has(item.id) && <span className="si-tag warn">flagged</span>}<small>{item.payload.username ?? ""}</small>
    </label>)}</div>
    {message && <p className="form-message" role="alert">{message}</p>}
    <div className="inline-actions"><Button type="submit" disabled={busy || !picked.length}>{busy ? <LoaderCircle className="spin" /> : <BellRing />} Start campaign ({picked.length})</Button></div>
  </form>;
}

// ---------------------------------------------------------------------------
// Weekly security report
// ---------------------------------------------------------------------------
const RISK_TEXT: Record<string, string> = {
  critical_alerts: "open critical alerts", high_alerts: "open high-severity alerts", breached_passwords: "passwords found in known breaches",
  members_in_breaches: "people whose email is in a breach with passwords", exposed_secrets: "secrets kept in notes",
  members_without_two_step: "people without two-step verification", reused_passwords: "reused passwords",
  lookalike_sites: "saved logins for look-alike websites", weak_passwords: "weak passwords", rotation_overdue: "overdue password rotations",
  members_not_reporting: "people whose vault health isn't reported yet",
};

export function WeeklyReportCard({ vault, organizationName }: { vault: WorkspaceVault; organizationName: string }) {
  const [reports, setReports] = useState<StoredReport[] | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void listWeeklyReports(vault.tenantId).then((data) => { if (active) setReports(data); },
      (reason) => { if (active) { setReports([]); setMessage(adminErrorMessage(reason, "Weekly reports could not be loaded.")); } });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function refresh() {
    setBusy("refresh"); setMessage("");
    try { await generateSecurityReportNow(vault.tenantId); setVersion((value) => value + 1); }
    catch (reason) { setMessage(adminErrorMessage(reason, "The report could not be generated.")); }
    finally { setBusy(""); }
  }

  async function summarize() {
    setBusy("ai"); setMessage("");
    try { await generateSecurityReportNow(vault.tenantId); await askSecurityAi(vault.tenantId, "weekly_summary"); setVersion((value) => value + 1); }
    catch (reason) { setMessage(aiErrorMessage(reason)); }
    finally { setBusy(""); }
  }

  function print() {
    document.documentElement.classList.add("si-printing-weekly");
    const done = () => { document.documentElement.classList.remove("si-printing-weekly"); window.removeEventListener("afterprint", done); };
    window.addEventListener("afterprint", done);
    window.print();
    window.setTimeout(done, 2_000);
  }

  const latest = reports?.[0];
  const report = latest?.report;
  const trend = report && report.score !== null && report.score_week_ago !== null ? report.score - report.score_week_ago : null;

  return <Card className="si-print">
    <CardHeader>
      <div className="panel-heading"><div><CardTitle>Weekly security report</CardTitle>
        <CardDescription>{organizationName} · {latest ? `week of ${day(latest.week_start)}` : "not generated yet"}. Emailed to owners and security admins every Monday. Counts only.</CardDescription></div>
        <div className="inline-actions no-print">
          <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void refresh()}>{busy === "refresh" ? <LoaderCircle className="spin" /> : <RefreshCw />} Update now</Button>
          <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void summarize()}>{busy === "ai" ? <LoaderCircle className="spin" /> : <Sparkles />} AI summary</Button>
          <Button size="sm" disabled={!report} onClick={print}><Printer /> PDF</Button>
        </div></div>
    </CardHeader>
    <CardContent className="si-stack">
      {message && <p className="form-message" role="alert">{message}</p>}
      {reports === null ? <div className="loading-ring" /> : !report ? <p className="field-hint">Choose “Update now” to create this week&apos;s report.</p> : <>
        <div className="si-kpis">
          <Kpi label="Security score" value={report.score === null ? "—" : `${report.score}/100`} detail={trend === null ? "no earlier data" : `${trend >= 0 ? "+" : ""}${trend} since last week`} />
          <Kpi label="Two-step coverage" value={`${report.two_step_pct}%`} detail={`passkeys ${report.passkey_pct}%`} />
          <Kpi label="New alerts (7 days)" value={report.alerts_new_7d} detail={`${report.alerts_open.critical + report.alerts_open.high} critical/high open`} />
          <Kpi label="Members reporting" value={`${report.members_reporting}/${report.members}`} />
        </div>
        {latest?.ai_summary && <div className="si-summary"><strong>AI summary</strong><br />{latest.ai_summary}</div>}
        <div>
          <strong>Top risks</strong>
          {report.top_risks.length === 0 ? <p className="field-hint">No major risks this week.</p> :
            <ol>{report.top_risks.map((risk) => <li key={risk.key}>{risk.count.toLocaleString()} {RISK_TEXT[risk.key] ?? risk.key}</li>)}</ol>}
        </div>
        <div className="si-table-wrap"><table className="si-table"><tbody>
          <tr><td>Breached passwords</td><td className="num">{report.breached}</td><td>Reused passwords</td><td className="num">{report.reused}</td></tr>
          <tr><td>Weak passwords</td><td className="num">{report.weak}</td><td>Secrets in notes</td><td className="num">{report.exposed_secrets}</td></tr>
          <tr><td>Look-alike sites saved</td><td className="num">{report.lookalike_sites}</td><td>People in breaches (passwords)</td><td className="num">{report.members_in_breaches}</td></tr>
          <tr><td>Unfamiliar sign-ins (7 days)</td><td className="num">{report.unfamiliar_sign_ins_7d}</td><td>Rotation tasks open / overdue</td><td className="num">{report.rotation_pending} / {report.rotation_overdue}</td></tr>
          <tr><td>Policies enforced</td><td className="num">{report.policies_enforced}</td><td>Generated</td><td className="num">{new Date(report.generated_at).toLocaleString()}</td></tr>
        </tbody></table></div>
      </>}
    </CardContent>
  </Card>;
}
