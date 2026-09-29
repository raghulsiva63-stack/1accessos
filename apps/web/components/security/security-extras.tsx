"use client";

import { useEffect, useState } from "react";
import {
  CalendarClock, ChevronRight, ExternalLink, Fingerprint, FileWarning, KeyRound, LoaderCircle, MailWarning, ShieldAlert, SkipForward, Wand2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LOOKALIKE_EXPLANATIONS, type lookalikePairs } from "@/lib/security/phishing";
import { SECRET_LABELS, type SecretFinding } from "@/lib/security/secret-scan";
import type { SiteDirectory, UpgradeSuggestion } from "@/lib/security/site-directory";
import {
  acknowledgeBreachExposure, listBreachExposures, listMyRotationTasks, loadSiteDirectory, updateRotationTask,
  type BreachExposure, type RotationTask,
} from "@/lib/security/client";
import { changePasswordUrl } from "@/lib/vault/change-password";
import type { VaultItem } from "@/lib/vault/items";

export function useSiteDirectory() {
  const [directory, setDirectory] = useState<SiteDirectory | null>(null);
  useEffect(() => {
    let active = true;
    void loadSiteDirectory().then((value) => { if (active) setDirectory(value); });
    return () => { active = false; };
  }, []);
  return directory;
}

const TYPE_LABELS: Record<string, string> = { "api-key": "API key", "ssh-key": "SSH key", "payment-card": "Payment card" };

export function ExposedSecretsCard({ findings, onOpen }: { findings: SecretFinding[]; onOpen: (id: string) => void }) {
  if (!findings.length) return null;
  return <Card>
    <CardHeader><CardTitle><FileWarning /> Secrets stored in notes</CardTitle>
      <CardDescription>These look like keys or card numbers typed into notes or custom fields. Notes are shown in plain view (screen shares, over-the-shoulder) and aren&apos;t covered by rotation reminders. Move each one into its own item, then delete it from the note. Found on this device only.</CardDescription></CardHeader>
    <CardContent><ul className="si-list">{findings.slice(0, 50).map((finding, index) => <li key={`${finding.itemId}-${index}`} className="si-row warn">
      <KeyRound />
      <div className="si-main"><strong>{finding.title}</strong><small>{SECRET_LABELS[finding.kind]} <code>{finding.preview}</code> in {finding.location === "notes" ? "notes" : `field “${finding.location.slice(6)}”`} · move to a new {TYPE_LABELS[finding.suggestedType] ?? "secret"} item</small></div>
      <Button size="sm" variant="outline" onClick={() => onOpen(finding.itemId)}>Open <ChevronRight /></Button>
    </li>)}</ul></CardContent>
  </Card>;
}

export function LookalikeCard({ pairs, items, onOpen }: { pairs: ReturnType<typeof lookalikePairs>; items: VaultItem[]; onOpen: (id: string) => void }) {
  if (!pairs.length) return null;
  const titles = new Map(items.map((item) => [item.id, item.payload.title]));
  return <div className="si-banner" role="alert">
    <ShieldAlert />
    <div>
      <strong>{pairs.length === 1 ? "Two saved websites look alike" : `${pairs.length} pairs of saved websites look alike`}</strong>
      <p>One of each pair may be a phishing copy that you saved by mistake. Open both, check which address is really the company&apos;s, delete the fake one and change the password on the real site.</p>
      <ul className="si-list" style={{ marginTop: ".6rem" }}>{pairs.slice(0, 10).map((pair) => <li key={`${pair.itemId}-${pair.otherId}`} className="si-row danger">
        <div className="si-main"><strong>{pair.resembles} ↔ {pair.domain}</strong><small>One {LOOKALIKE_EXPLANATIONS[pair.reason]}.</small></div>
        <span className="inline-actions"><Button size="sm" variant="outline" onClick={() => onOpen(pair.otherId)}>{titles.get(pair.otherId) ?? "Open"}</Button><Button size="sm" variant="outline" onClick={() => onOpen(pair.itemId)}>{titles.get(pair.itemId) ?? "Open"}</Button></span>
      </li>)}</ul>
    </div>
  </div>;
}

export function UpgradeCard({ suggestions, onOpen, loading }: { suggestions: UpgradeSuggestion[]; onOpen: (id: string) => void; loading: boolean }) {
  const [expanded, setExpanded] = useState(false);
  if (loading || !suggestions.length) return null;
  const passkeys = suggestions.filter((entry) => entry.passkey).length;
  const twoStep = suggestions.filter((entry) => entry.twoStep).length;
  const shown = expanded ? suggestions : suggestions.slice(0, 6);
  return <Card>
    <CardHeader><CardTitle><Fingerprint /> Upgrade your logins</CardTitle>
      <CardDescription>{passkeys > 0 && `${passkeys} site${passkeys === 1 ? "" : "s"} you use support passkeys. `}{twoStep > 0 && `${twoStep} support two-step verification and no code is stored here. `}Matched on this device against the public 2fa.directory list — your sites are never sent anywhere.</CardDescription></CardHeader>
    <CardContent>
      <ul className="si-list">{shown.map((entry) => <li key={entry.itemId} className="si-row">
        <Fingerprint />
        <div className="si-main"><strong>{entry.title}</strong><small>{entry.domain}</small></div>
        <span className="inline-actions">
          {entry.passkey && <span className="si-tag good">Passkey available</span>}
          {entry.twoStep && <span className="si-tag warn">Turn on 2-step</span>}
          {entry.docs && <a className="help-link" href={entry.docs} target="_blank" rel="noopener noreferrer"><ExternalLink /> How</a>}
          <Button size="sm" variant="ghost" onClick={() => onOpen(entry.itemId)}>Open <ChevronRight /></Button>
        </span>
      </li>)}</ul>
      {suggestions.length > 6 && <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)}>{expanded ? "Show fewer" : `Show all ${suggestions.length}`}</Button>}
      <p className="field-hint">After turning on two-step verification at a site, save its setup key in a custom field named “TOTP” so Passkey-X can show the codes.</p>
    </CardContent>
  </Card>;
}

export function RotationTasksCard({ identityId, items, onRotate }: { identityId: string; items: VaultItem[]; onRotate: (id: string) => void }) {
  const [tasks, setTasks] = useState<RotationTask[]>([]);
  const [busy, setBusy] = useState("");
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let active = true;
    if (!identityId) return () => { active = false; };
    void listMyRotationTasks(identityId).then((rows) => { if (active) setTasks(rows); }, () => undefined);
    return () => { active = false; };
  }, [identityId, version]);
  const byId = new Map(items.map((item) => [item.id, item]));
  const visible = tasks.filter((task) => byId.has(task.item_id));
  if (!visible.length) return null;
  const hidden = tasks.length - visible.length;

  async function skip(task: RotationTask) {
    const note = window.prompt("Why skip this one? (for example: account closed)")?.trim();
    if (note === undefined) return;
    setBusy(task.id);
    try { await updateRotationTask(task.id, "skipped", note); setVersion((value) => value + 1); } finally { setBusy(""); }
  }

  return <Card>
    <CardHeader><CardTitle><CalendarClock /> Rotation tasks from your organization</CardTitle>
      <CardDescription>Change these passwords before the due date. Generate a new one, change it on the website, then save — the task completes automatically.{hidden > 0 ? ` ${hidden} more are in other workspaces; switch workspace to see them.` : ""}</CardDescription></CardHeader>
    <CardContent><ul className="si-list">{visible.map((task) => {
      const item = byId.get(task.item_id)!;
      const due = task.campaign ? new Date(task.campaign.due_at) : null;
      const overdue = due ? due.getTime() < Date.now() : false;
      const changeUrl = changePasswordUrl(item.payload.url);
      return <li key={task.id} className={`si-row ${overdue ? "danger" : ""}`}>
        <KeyRound />
        <div className="si-main"><strong>{item.payload.title}</strong><small>{task.campaign?.title}{due ? ` · due ${due.toLocaleDateString()}` : ""}{overdue ? " · overdue" : ""}</small></div>
        <span className="inline-actions">
          {changeUrl && <a className="help-link" href={changeUrl} target="_blank" rel="noopener noreferrer"><ExternalLink /> Site</a>}
          <Button size="sm" onClick={() => onRotate(item.id)}><Wand2 /> New password</Button>
          <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void skip(task)}>{busy === task.id ? <LoaderCircle className="spin" /> : <SkipForward />} Skip</Button>
        </span>
      </li>;
    })}</ul></CardContent>
  </Card>;
}

export function MyBreachesCard({ tenantId, identityId }: { tenantId: string | null; identityId: string }) {
  const [rows, setRows] = useState<BreachExposure[]>([]);
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let active = true;
    if (!tenantId || !identityId) return () => { active = false; };
    void listBreachExposures(tenantId, identityId).then((data) => { if (active) setRows(data.filter((row) => !row.member_acknowledged_at)); }, () => undefined);
    return () => { active = false; };
  }, [identityId, tenantId, version]);
  if (!tenantId || !rows.length) return null;
  return <Card>
    <CardHeader><CardTitle><MailWarning /> Your work email appeared in data breaches</CardTitle>
      <CardDescription>Found by your organization&apos;s Breach watch (Have I Been Pwned). If you ever used the same password as on these sites, change it everywhere — the fix list above shows reused passwords.</CardDescription></CardHeader>
    <CardContent><ul className="si-list">{rows.map((row) => <li key={row.breach_name} className={`si-row ${row.includes_passwords ? "danger" : "warn"}`}>
      <MailWarning />
      <div className="si-main"><strong>{row.breach_title}</strong><small>{row.breach_date ? new Date(row.breach_date).toLocaleDateString() : "Date unknown"}{row.data_classes.length ? ` · ${row.data_classes.slice(0, 5).join(", ")}` : ""}</small></div>
      {row.includes_passwords && <span className="si-tag bad">Passwords exposed</span>}
      <Button size="sm" variant="outline" onClick={() => void acknowledgeBreachExposure(tenantId, identityId, row.breach_name).then(() => setVersion((value) => value + 1))}>I&apos;ve dealt with it</Button>
    </li>)}</ul></CardContent>
  </Card>;
}
