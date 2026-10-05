"use client";

import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Keyboard, KeyRound, ShieldAlert, Terminal, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { desktop, isDesktopApp, type AutoTypeTarget, type CliRequest, type SshRequest } from "@/lib/desktop/bridge";
import {
  APPROVALS_RECORD, AutoTypeError, autoTypeErrorMessage, buildSteps, forgetSteps, parseApprovals, planAutoType, rememberApproval, typable, type Candidate,
} from "@/lib/desktop/autotype";
import { describeReferences, resolveReferences, type ReferenceSource } from "@/lib/desktop/references";
import {
  finishAutoType, finishCli, finishSsh, installDesktopRequests, LIFETIME, pendingAutoType, pendingCli, pendingSsh, requestsVersion, setVaultOpen, subscribeRequests,
} from "@/lib/desktop/requests";
import { agentKeyInputs } from "@/lib/desktop/ssh-keys";
import { startPresentationWatch } from "@/lib/desktop/presentation";
import { startDownloadGuard } from "@/lib/desktop/download-guard";
import { listVaultItemsWithStatus, type VaultItem, type WorkspaceVault } from "@/lib/vault/items";

const zero = () => 0;

/** Mounted once on the home page: listens for native requests and runs background checks. */
export function DesktopRequestsHost() {
  useEffect(() => {
    if (!isDesktopApp()) return;
    installDesktopRequests();
    const stopPresentation = startPresentationWatch();
    const stopDownloads = startDownloadGuard();
    return () => { stopPresentation(); stopDownloads(); };
  }, []);
  return null;
}

type Picker = { target: AutoTypeTarget; candidates: Candidate[]; browser: boolean };

/** Handles auto-type, SSH and `pkx` requests while the vault is unlocked (desktop app only). */
export function DesktopVaultRequests({ items, vault, workspaces, onNotice }: { items: VaultItem[]; vault: WorkspaceVault | null; workspaces: WorkspaceVault[]; onNotice: (text: string) => void }) {
  const version = useSyncExternalStore(subscribeRequests, requestsVersion, zero);
  const [picker, setPicker] = useState<Picker | null>(null);
  const others = useRef(new Map<string, VaultItem[]>());
  const agentLoad = useRef<Promise<void>>(Promise.resolve());

  useEffect(() => { setVaultOpen(true); return () => setVaultOpen(false); }, []);

  // Every workspace's items (the open one from memory, the others decrypted on demand).
  const sources = useMemo(() => async (): Promise<ReferenceSource[]> => {
    const list: ReferenceSource[] = [];
    for (const workspace of workspaces) {
      if (workspace.workspaceId === vault?.workspaceId) { list.push({ vaultName: workspace.name, items }); continue; }
      let loaded = others.current.get(workspace.workspaceId);
      if (!loaded) {
        loaded = await listVaultItemsWithStatus(workspace).then((result) => result.items).catch(() => []);
        others.current.set(workspace.workspaceId, loaded);
      }
      list.push({ vaultName: workspace.name, items: loaded });
    }
    return list;
  }, [items, vault?.workspaceId, workspaces]);

  // SSH agent: hand over the vault's Ed25519 keys whenever the vault changes.
  useEffect(() => {
    let active = true;
    agentLoad.current = (async () => {
      const settings = await desktop.settings();
      if (!settings.sshAgent || !active) return;
      const all = (await sources()).flatMap((source) => source.items);
      if (active) await desktop.ssh.load(agentKeyInputs(all));
    })().catch(() => undefined);
    return () => { active = false; };
  }, [sources]);

  // Auto-type: choose the login, then type it or open the picker.
  useEffect(() => {
    const event = pendingAutoType();
    if (!event) return;
    let active = true;
    (async () => {
      if (event.error !== undefined) {
        finishAutoType();
        onNotice(autoTypeErrorMessage(event.error));
        return;
      }
      const approvals = parseApprovals(await desktop.record.get(APPROVALS_RECORD).catch(() => null));
      const plan = planAutoType(items, event, approvals);
      if (!active) return;
      if (plan.automatic) {
        finishAutoType();
        await typeInto(event, plan.automatic).catch((reason) => onNotice(reason instanceof AutoTypeError ? reason.message : autoTypeErrorMessage(String(reason))));
        return;
      }
      finishAutoType();
      setPicker({ target: event, candidates: plan.candidates, browser: plan.browser });
      void desktop.autoType.present().catch(() => undefined);
    })().catch(() => undefined);
    return () => { active = false; };
  }, [version, items, onNotice]);

  const ssh = pendingSsh();
  const cli = pendingCli();
  return <>
    {picker && <AutoTypePicker picker={picker} items={items} onClose={() => setPicker(null)} onNotice={onNotice} />}
    {!picker && ssh && <SshApproval key={ssh.id} request={ssh} ready={() => agentLoad.current} />}
    {!picker && !ssh && cli && <CliApproval key={cli.id} request={cli} sources={sources} />}
  </>;
}

async function typeInto(target: AutoTypeTarget, item: VaultItem) {
  const steps = await buildSteps(item);
  try { await desktop.autoType.perform(target.token, steps); }
  finally { forgetSteps(steps); }
}

function AutoTypePicker({ picker, items, onClose, onNotice }: { picker: Picker; items: VaultItem[]; onClose: () => void; onNotice: (text: string) => void }) {
  const [query, setQuery] = useState("");
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const suggested = new Set(picker.candidates.map((candidate) => candidate.item.id));
  const normalized = query.trim().toLowerCase();
  const rest = items.filter((item) => typable(item) && !suggested.has(item.id) && (!normalized || [item.payload.title, item.payload.username, item.payload.url].some((value) => value?.toLowerCase().includes(normalized))));
  const list = [...picker.candidates.map((candidate) => candidate.item).filter((item) => !normalized || [item.payload.title, item.payload.username, item.payload.url].some((value) => value?.toLowerCase().includes(normalized))), ...rest].slice(0, 30);

  async function choose(item: VaultItem) {
    setBusy(true); setMessage("");
    try {
      if (remember && !picker.browser) {
        const approvals = parseApprovals(await desktop.record.get(APPROVALS_RECORD).catch(() => null));
        await desktop.record.set(APPROVALS_RECORD, JSON.stringify(rememberApproval(approvals, picker.target, item.id))).catch(() => undefined);
      }
      await typeInto(picker.target, item);
      onClose();
    } catch (reason) {
      const text = reason instanceof AutoTypeError ? reason.message : autoTypeErrorMessage(reason instanceof Error ? reason.message : String(reason));
      if (String(reason).includes("expired")) { onNotice(text); onClose(); } else setMessage(text);
    } finally { setBusy(false); }
  }

  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <Card className="item-editor autotype-picker" role="dialog" aria-modal="true" aria-labelledby="autotype-title">
      <CardHeader>
        <span className="feature-icon"><Keyboard /></span>
        <CardTitle id="autotype-title">Type a login into {picker.target.app || "this window"}</CardTitle>
        <CardDescription>{picker.target.title ? <>Window: “{picker.target.title}”</> : "The window you were using"}</CardDescription>
      </CardHeader>
      <CardContent className="form-stack">
        {picker.browser && <p className="autotype-warning" role="note"><TriangleAlert aria-hidden="true" /> This is a browser. A page title doesn&apos;t prove which site is open, so check the address bar first — or use the Passkey-X extension, which checks the real address.</p>}
        <input className="autotype-search" type="search" autoFocus placeholder="Search logins" aria-label="Search logins" value={query} onChange={(event) => setQuery(event.target.value)} />
        <ul className="autotype-list">
          {list.map((item) => <li key={item.id}>
            <button disabled={busy} onClick={() => void choose(item)}>
              <strong>{item.payload.title}</strong>
              <small>{item.payload.username || item.payload.url || ""}{suggested.has(item.id) ? " · suggested" : ""}</small>
            </button>
          </li>)}
          {!list.length && <li className="field-hint">No login matches.</li>}
        </ul>
        {!picker.browser && <label className="switch-row"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /> Always use the chosen login in this window (type without asking next time)</label>}
        <p className="field-hint">Passkey-X types the username, Tab, the password and Enter. Typing stops if another window comes to the front.</p>
        {message && <p className="form-message" role="alert">{message}</p>}
        <div className="inline-actions"><Button variant="outline" onClick={onClose}>Cancel</Button></div>
      </CardContent>
    </Card>
  </div>;
}

function useExpiry(receivedAt: number, lifetime: number, finish: () => void) {
  useEffect(() => {
    const timer = setTimeout(finish, Math.max(0, receivedAt + lifetime - Date.now()));
    return () => clearTimeout(timer);
  }, [receivedAt, lifetime, finish]);
}

function SshApproval({ request, ready }: { request: SshRequest & { receivedAt: number }; ready: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const finish = useMemo(() => () => finishSsh(request.id), [request.id]);
  useExpiry(request.receivedAt, LIFETIME.ssh, finish);
  async function answer(allow: boolean, minutes: number) {
    setBusy(true);
    try {
      if (allow) await ready();
      await desktop.ssh.reply(request.id, allow, minutes);
    } catch { /* the request expired */ }
    finally { finish(); }
  }
  return <div className="modal-backdrop" role="presentation">
    <Card className="item-editor desktop-approval" role="alertdialog" aria-modal="true" aria-labelledby="ssh-title" aria-describedby="ssh-description">
      <CardHeader>
        <span className="feature-icon"><KeyRound /></span>
        <CardTitle id="ssh-title">Use the SSH key “{request.keyName || "SSH key"}”?</CardTitle>
        <CardDescription id="ssh-description">{request.client ? <><strong>{request.client}</strong> wants</> : "A program wants"} to sign in with this key (for example to a server or Git host).</CardDescription>
      </CardHeader>
      <CardContent className="form-stack">
        <p className="field-hint">Key fingerprint <code>{request.fingerprint}</code></p>
        <p className="field-hint">Only allow if you just ran ssh, git or a similar command yourself.</p>
        <div className="inline-actions">
          <Button disabled={busy} onClick={() => void answer(true, 0)}><ShieldAlert /> Allow once</Button>
          <Button disabled={busy} variant="outline" onClick={() => void answer(true, 10)}>Allow for 10 minutes</Button>
          <Button disabled={busy} variant="ghost" onClick={() => void answer(false, 0)}>Deny</Button>
        </div>
      </CardContent>
    </Card>
  </div>;
}

function CliApproval({ request, sources }: { request: CliRequest & { receivedAt: number }; sources: () => Promise<ReferenceSource[]> }) {
  const [busy, setBusy] = useState(false);
  const [described, setDescribed] = useState<{ reference: string; label: string; found: boolean }[] | null>(null);
  const finish = useMemo(() => () => finishCli(request.id), [request.id]);
  useExpiry(request.receivedAt, LIFETIME.cli, finish);
  useEffect(() => {
    let active = true;
    void sources().then((list) => { if (active) setDescribed(describeReferences(request.refs, list)); }).catch(() => undefined);
    return () => { active = false; };
  }, [request.refs, sources]);

  async function answer(allow: boolean) {
    setBusy(true);
    try {
      if (!allow) { await desktop.cli.reply(request.id, { error: "denied" }); return; }
      const result = await resolveReferences(request.refs, await sources());
      await desktop.cli.reply(request.id, "values" in result ? { values: result.values } : { error: result.error });
    } catch { await desktop.cli.reply(request.id, { error: "unavailable" }).catch(() => undefined); }
    finally { finish(); }
  }
  return <div className="modal-backdrop" role="presentation">
    <Card className="item-editor desktop-approval" role="alertdialog" aria-modal="true" aria-labelledby="cli-title" aria-describedby="cli-description">
      <CardHeader>
        <span className="feature-icon"><Terminal /></span>
        <CardTitle id="cli-title">Give {request.refs.length === 1 ? "a secret" : `${request.refs.length} secrets`} to a command?</CardTitle>
        <CardDescription id="cli-description">{request.client || "pkx"} asked from a terminal{request.cwd ? <> in <code>{request.cwd}</code></> : null}.</CardDescription>
      </CardHeader>
      <CardContent className="form-stack">
        {request.command && <pre className="cli-command">{request.command}</pre>}
        <ul className="cli-refs">{(described ?? request.refs.map((reference) => ({ reference, label: reference, found: true }))).map((entry) => <li key={entry.reference} className={entry.found ? "" : "missing"}>{entry.label}{entry.found ? "" : " — not found"}</li>)}</ul>
        <p className="field-hint">The values go only to this command, for this run. Only allow if you started it yourself.</p>
        <div className="inline-actions">
          <Button disabled={busy} onClick={() => void answer(true)}><ShieldAlert /> Allow</Button>
          <Button disabled={busy} variant="ghost" onClick={() => void answer(false)}>Deny</Button>
        </div>
      </CardContent>
    </Card>
  </div>;
}
