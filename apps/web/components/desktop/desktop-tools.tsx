"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import {
  Ban, Copy, Download, FileSearch, FolderOpen, Keyboard, KeyRound, MonitorX, Plus, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck, Terminal, Trash2, TriangleAlert, Upload,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  desktop, type AutoTypeInfo, type CliInfo, type DesktopInfo, type DesktopSettings, type SprawlFinding, type SprawlReport, type SshAgentStatus,
} from "@/lib/desktop/bridge";
import { APPROVALS_RECORD, parseApprovals, type Approval } from "@/lib/desktop/autotype";
import { referenceFor } from "@/lib/desktop/references";
import { randomSeed, setupSnippets, sshErrorMessage, sshKeyPayload } from "@/lib/desktop/ssh-keys";
import { checkDownloads, checkedDownloads, downloadsVersion, quarantineDownload, subscribeDownloads } from "@/lib/desktop/download-guard";
import { presentationState, serverPresentationState, setManualPresentation, subscribePresentation } from "@/lib/desktop/presentation";
import { installId } from "@/lib/desktop/endpoint-scan";
import { hasSession, reportGuardFindings, resolveGuardFindings } from "@/lib/security/guard-client";
import { importFromText } from "@/lib/vault/importers";
import { createVaultItem, type VaultItem, type WorkspaceVault } from "@/lib/vault/items";

type Tab = "autotype" | "developer" | "downloads" | "secrets";
const TABS: { id: Tab; label: string; icon: typeof Keyboard }[] = [
  { id: "autotype", label: "Auto-type", icon: Keyboard },
  { id: "developer", label: "SSH & command line", icon: Terminal },
  { id: "downloads", label: "Downloads & screen sharing", icon: Download },
  { id: "secrets", label: "Secrets on this computer", icon: FileSearch },
];

type Props = { items: VaultItem[]; vault: WorkspaceVault; onSaved: () => Promise<void>; onOpenSettings: () => void };

/** "This computer" (desktop app only): auto-type, SSH agent and pkx, downloads, secret finder. */
export function DesktopToolsView(props: Props) {
  const [tab, setTab] = useState<Tab>("autotype");
  const [info, setInfo] = useState<DesktopInfo | null>(null);
  const [settings, setSettings] = useState<DesktopSettings | null>(null);
  useEffect(() => {
    let active = true;
    void Promise.all([desktop.info(), desktop.settings()]).then(([nextInfo, nextSettings]) => { if (active) { setInfo(nextInfo); setSettings(nextSettings); } }).catch(() => undefined);
    return () => { active = false; };
  }, [tab]);
  return <section className="desktop-tools" aria-label="This computer">
    <p className="field-hint">Tools that only the desktop app can offer. Everything here runs on this computer; turn features on or off in <button className="link-button" onClick={props.onOpenSettings}>Settings › This computer</button>.</p>
    <div className="desktop-tools-tabs" role="tablist">{TABS.map((entry) => { const Icon = entry.icon; return <button key={entry.id} role="tab" aria-selected={tab === entry.id} className={tab === entry.id ? "active" : ""} onClick={() => setTab(entry.id)}><Icon /> {entry.label}</button>; })}</div>
    <div role="tabpanel">
      {tab === "autotype" && <AutoTypeTab items={props.items} />}
      {tab === "developer" && info && settings && <DeveloperTab {...props} info={info} settings={settings} />}
      {tab === "downloads" && settings && <DownloadsTab settings={settings} />}
      {tab === "secrets" && <SecretsTab {...props} />}
    </div>
  </section>;
}

function Disabled({ what, onOpenSettings }: { what: string; onOpenSettings?: () => void }) {
  return <p className="desktop-tools-off">{what} is turned off. {onOpenSettings && <button className="link-button" onClick={onOpenSettings}>Turn it on in Settings</button>}</p>;
}

// ---------------------------------------------------------------------------

function AutoTypeTab({ items }: { items: VaultItem[] }) {
  const [info, setInfo] = useState<AutoTypeInfo | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  useEffect(() => {
    let active = true;
    void Promise.all([desktop.autoType.info(), desktop.record.get(APPROVALS_RECORD).catch(() => null)]).then(([nextInfo, record]) => {
      if (active) { setInfo(nextInfo); setApprovals(parseApprovals(record)); }
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);
  async function forget(approval: Approval) {
    const next = approvals.filter((entry) => entry !== approval);
    await desktop.record.set(APPROVALS_RECORD, JSON.stringify(next)).catch(() => undefined);
    setApprovals(next);
  }
  if (!info) return null;
  const titles = new Map(items.map((item) => [item.id, item.payload.title]));
  const requirement = info.requirement === "accessibility" ? "macOS needs permission: System Settings › Privacy & Security › Accessibility › Passkey-X."
    : info.requirement === "xdotool" ? "Install xdotool to type into other programs (for example: sudo apt install xdotool)."
    : info.requirement === "wayland" ? "Auto-type works in X11 sessions. Wayland doesn't let apps type into other windows; use copy and paste there." : "";
  return <div className="desktop-tool-card">
    <h3><Keyboard /> Type logins into any program</h3>
    {!info.enabled ? <Disabled what="Auto-type" /> : <>
      <p>Click into a sign-in box in any app — a VPN client, a remote desktop, a database tool — and press <kbd>{info.shortcut}</kbd>. Passkey-X picks the login for that window (or asks you), then types the username, Tab, the password and Enter.</p>
      {!info.active && <p className="desktop-tools-warn"><TriangleAlert /> Another app is using {info.shortcut}, so the shortcut isn&apos;t active.</p>}
      {requirement && <p className="desktop-tools-warn"><TriangleAlert /> {requirement}</p>}
      <ul className="desktop-tool-points">
        <li>Typing stops if another window comes to the front.</li>
        <li>In browsers Passkey-X always asks, because a page title doesn&apos;t prove which site is open.</li>
        <li>Custom order: add a field “Auto-type sequence” to an item, e.g. <code>{"{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}"}</code>. Also <code>{"{DELAY 500}"}</code>, <code>{"{URL}"}</code>, <code>{"{S:Field name}"}</code>.</li>
        <li>Window rules: a field “Auto-type window” with titles like <code>*Remote Desktop*</code> makes an item the automatic choice there.</li>
      </ul>
      <h4>Windows that type without asking</h4>
      {approvals.length ? <ul className="desktop-tool-list">{approvals.map((approval) => <li key={`${approval.app}:${approval.title}`}>
        <div><strong>{titles.get(approval.itemId) ?? "Deleted item"}</strong><small>{approval.app} · “{approval.title}”</small></div>
        <Button size="sm" variant="ghost" onClick={() => void forget(approval)}><Trash2 /> Forget</Button>
      </li>)}</ul> : <p className="field-hint">None yet. In the picker, tick “Always use the chosen login in this window”.</p>}
    </>}
  </div>;
}

// ---------------------------------------------------------------------------

function CopyLine({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="copy-line"><code>{value}</code><Button size="sm" variant="ghost" aria-label="Copy" onClick={() => void navigator.clipboard.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}>{copied ? "Copied" : <Copy />}</Button></div>;
}

function DeveloperTab({ items, vault, onSaved, onOpenSettings, info, settings }: Props & { info: DesktopInfo; settings: DesktopSettings }) {
  const [status, setStatus] = useState<SshAgentStatus | null>(null);
  const [cli, setCli] = useState<CliInfo | null>(null);
  const [name, setName] = useState("");
  const [pasted, setPasted] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [refItem, setRefItem] = useState("");
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let active = true;
    void Promise.all([desktop.ssh.status(), desktop.cli.info()]).then(([nextStatus, nextCli]) => { if (active) { setStatus(nextStatus); setCli(nextCli); } }).catch(() => undefined);
    return () => { active = false; };
  }, [version]);

  async function saveKey(title: string, privateKey: string, publicKey: string, fingerprint: string) {
    await createVaultItem(vault, "ssh-key", sshKeyPayload(title, privateKey, publicKey, fingerprint));
    await onSaved();
    // The vault requests host hands the updated keys to the agent when the list refreshes.
    setVersion((value) => value + 1);
  }

  async function generate() {
    setBusy(true); setMessage("");
    try {
      const title = name.trim() || `${info.os === "macos" ? "Mac" : info.os === "windows" ? "Windows" : "Linux"} SSH key`;
      const key = await desktop.ssh.generate(randomSeed(), title);
      await saveKey(title, key.privateKey, key.publicKey, key.fingerprint);
      setName("");
      setMessage(`Created “${title}”. Add its public key to GitHub, GitLab or the server: ${key.publicKey.slice(0, 40)}…`);
    } catch { setMessage("The key could not be created. Try again."); }
    finally { setBusy(false); }
  }

  async function importKey() {
    setBusy(true); setMessage("");
    try {
      const key = await desktop.ssh.inspect(pasted.trim());
      const title = name.trim() || key.comment || "Imported SSH key";
      await saveKey(title, `${pasted.trim()}\n`, key.publicKey, key.fingerprint);
      setPasted(""); setName("");
      setMessage(`Saved “${title}” in ${vault.name}. You can now delete the key file from this computer.`);
    } catch (reason) { setMessage(sshErrorMessage(String(reason))); }
    finally { setBusy(false); }
  }

  async function installPath() {
    setBusy(true);
    try { await desktop.cli.installPath(); setMessage("pkx was added to your PATH. Open a new terminal to use it."); setVersion((value) => value + 1); }
    catch { setMessage("PATH could not be changed. Add the folder shown below to PATH yourself."); }
    finally { setBusy(false); }
  }

  const snippets = status?.endpoint ? setupSnippets(status.endpoint, info.os) : null;
  const keyItems = items.filter((item) => item.contentType === "ssh-key" && !item.deletedAt);
  const loaded = new Map((status?.keys ?? []).map((key) => [key.id, key]));
  const referenceItems = items.filter((item) => !item.deletedAt && (item.payload.secret || item.payload.fields)).slice(0, 300);
  const chosen = referenceItems.find((item) => item.id === refItem) ?? null;
  const cliDir = cli?.path ? cli.path.replace(/[\\/][^\\/]+$/u, "") : null;
  return <>
    <div className="desktop-tool-card">
      <h3><KeyRound /> SSH agent</h3>
      {!settings.sshAgent ? <Disabled what="The SSH agent" onOpenSettings={onOpenSettings} /> : <>
        <p>Keep SSH keys in the vault instead of in <code>~/.ssh</code>. ssh, git, scp and IDEs ask Passkey-X for a signature and you approve each use. Private keys never leave the app; while the vault is locked, nothing can be signed.</p>
        <p className="field-hint">{status?.running ? <>Agent running at <code>{status.endpoint}</code></> : "The agent isn't running. Turn it off and on again in Settings."}</p>
        {snippets && <div className="desktop-tool-setup"><span>Point your tools at Passkey-X (once):</span><CopyLine value={snippets.shell} /><CopyLine value={snippets.config} /><small>{snippets.note}</small></div>}
        <h4>Keys in {vault.name}</h4>
        {keyItems.length ? <ul className="desktop-tool-list">{keyItems.map((item) => { const agentKey = loaded.get(item.id); return <li key={item.id}>
          <div><strong>{item.payload.title}</strong><small>{agentKey ? agentKey.fingerprint : (item.payload.secret ?? "").includes("OPENSSH") ? "Not loaded — only Ed25519 keys can be used" : "Stored only (not an OpenSSH key)"}</small></div>
          {item.payload.fields?.publicKey && <Button size="sm" variant="ghost" onClick={() => void navigator.clipboard.writeText(item.payload.fields!.publicKey)}><Copy /> Public key</Button>}
        </li>; })}</ul> : <p className="field-hint">No SSH keys yet.</p>}
        <div className="desktop-tool-form">
          <input aria-label="Key name" placeholder="Key name (e.g. Work laptop)" value={name} onChange={(event) => setName(event.target.value)} />
          <Button disabled={busy} onClick={() => void generate()}><Plus /> New Ed25519 key</Button>
        </div>
        <details><summary>Import an existing key</summary>
          <textarea rows={5} aria-label="Private key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={pasted} onChange={(event) => setPasted(event.target.value)} spellCheck={false} autoComplete="off" />
          <Button disabled={busy || !pasted.trim()} onClick={() => void importKey()}><Upload /> Save in vault</Button>
          <p className="field-hint">Keys with a passphrase must be unlocked first (<code>ssh-keygen -p -f ~/.ssh/id_ed25519</code>); the vault encrypts them instead.</p>
        </details>
      </>}
    </div>
    <div className="desktop-tool-card">
      <h3><Terminal /> Command-line tool (pkx)</h3>
      {!settings.commandLine ? <Disabled what="The command-line tool" onOpenSettings={onOpenSettings} /> : <>
        <p>Give secrets to scripts and developer tools without writing them into <code>.env</code> files. Each request shows the command and asks you first.</p>
        <CopyLine value="pkx run --env DATABASE_URL=px://Work/Production DB/password -- npm start" />
        <CopyLine value="pkx run --env-file .env.passkey -- docker compose up" />
        <CopyLine value='pkx read "px://Work/GitHub/token"' />
        {cli && <p className="field-hint">{cli.installed ? cli.onPath ? "pkx is ready in new terminals." : <>pkx is installed at <code>{cli.path}</code> but isn&apos;t on your PATH.</> : "pkx isn't included in this build."}</p>}
        {cli?.installed && !cli.onPath && (info.os === "windows"
          ? <Button variant="outline" disabled={busy} onClick={() => void installPath()}>Add pkx to PATH</Button>
          : <CopyLine value={info.os === "macos" ? `sudo ln -sf "${cli.path}" /usr/local/bin/pkx` : `mkdir -p ~/.local/bin && ln -sf "${cli.path}" ~/.local/bin/pkx`} />)}
        {cliDir && info.os === "windows" && !cli?.onPath && <small className="field-hint">Folder: {cliDir}</small>}
        <h4>Reference for an item</h4>
        <select aria-label="Item" value={refItem} onChange={(event) => setRefItem(event.target.value)}><option value="">Choose an item…</option>{referenceItems.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select>
        {chosen && <div className="desktop-tool-setup">
          {chosen.payload.secret && <CopyLine value={referenceFor(vault.name, chosen.payload.title, "password")} />}
          {chosen.payload.username && <CopyLine value={referenceFor(vault.name, chosen.payload.title, "username")} />}
          {Object.keys(chosen.payload.fields ?? {}).slice(0, 6).map((field) => <CopyLine key={field} value={referenceFor(vault.name, chosen.payload.title, field)} />)}
        </div>}
      </>}
    </div>
    {message && <p className="form-message" role="status">{message}</p>}
  </>;
}

// ---------------------------------------------------------------------------

const zero = () => 0;
function formatSize(bytes: number) {
  return bytes >= 1_048_576 ? `${(bytes / 1_048_576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function DownloadsTab({ settings }: { settings: DesktopSettings }) {
  useSyncExternalStore(subscribeDownloads, downloadsVersion, zero);
  const presentation = useSyncExternalStore(subscribePresentation, presentationState, serverPresentationState);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const list = checkedDownloads();
  async function block(path: string) {
    setMessage("");
    try { await quarantineDownload(path); setMessage("Blocked. The file was renamed so it can't be opened by mistake. Delete it when you're sure."); }
    catch { setMessage("The file could not be renamed. It may be open or already moved."); }
  }
  return <>
    <div className="desktop-tool-card">
      <h3><ShieldAlert /> Download protection</h3>
      {!settings.downloadProtection ? <Disabled what="Download protection" /> : <>
        <p>New files in your Downloads folder are checked against Guard: disguised names (like <code>invoice.pdf.exe</code>), the site they came from, and — for programs, installers and macro documents — known-malware fingerprints. Files are never uploaded.</p>
        <Button variant="outline" disabled={busy} onClick={() => { setBusy(true); void checkDownloads().finally(() => setBusy(false)); }}><RefreshCw /> Check now</Button>
        {list.length ? <ul className="desktop-tool-list">{list.map((file) => <li key={`${file.path}:${file.modifiedMs}`} className={`level-${file.assessment.level}`}>
          <span className="desktop-tool-level">{file.assessment.level === "safe" ? <ShieldCheck /> : <TriangleAlert />}</span>
          <div><strong>{file.name}</strong><small>{formatSize(file.size)}{file.sourceUrl ? ` · from ${safeHostLabel(file.sourceUrl)}` : ""}{file.quarantined ? " · blocked" : ""}</small>
            {file.assessment.reasons.map((reason) => <small key={reason} className="reason">{reason}</small>)}</div>
          {file.assessment.level !== "safe" && !file.quarantined && <Button size="sm" variant="destructive" onClick={() => void block(file.path)}><Ban /> Block</Button>}
          <Button size="sm" variant="ghost" aria-label="Show in folder" onClick={() => void desktop.revealPath(file.quarantined ?? file.path).catch(() => undefined)}><FolderOpen /></Button>
        </li>)}</ul> : <p className="field-hint">No new downloads since Passkey-X started checking.</p>}
        {message && <p className="form-message" role="status">{message}</p>}
      </>}
    </div>
    <div className="desktop-tool-card">
      <h3><MonitorX /> Screen sharing</h3>
      <p>While you share or record your screen, passwords can&apos;t be revealed in Passkey-X. {settings.presentationAuto ? "It switches on by itself when Zoom sharing, OBS and other recorders run;" : "Automatic detection is off;"} meetings in a browser can&apos;t be detected, so switch it on by hand (also from the tray menu).</p>
      <p className="field-hint">{presentation.active ? `On${presentation.reasons.length ? ` — ${presentation.reasons.join(", ")}` : ""}.` : "Off."}</p>
      <Button variant={presentation.manual ? "default" : "outline"} onClick={() => setManualPresentation(!presentation.manual)}>{presentation.manual ? "Turn off presentation mode" : "Turn on presentation mode"}</Button>
    </div>
  </>;
}

function safeHostLabel(url: string) {
  try { return new URL(url).hostname; } catch { return "unknown site"; }
}

// ---------------------------------------------------------------------------

const SPRAWL_KEY = "device:plaintext_secrets";
const ITEM_KIND: Record<string, "api-key" | "ssh-key" | "database" | "custom-secret"> = { private_key: "ssh-key", database_url: "database" };

function SecretsTab({ vault, onSaved }: Props) {
  const [report, setReport] = useState<SprawlReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [done, setDone] = useState<Record<string, string>>({});
  const id = (finding: SprawlFinding) => `${finding.path}:${finding.line}:${finding.rule}`;

  async function scan() {
    setBusy(true); setMessage(""); setDone({});
    try {
      const next = await desktop.sprawl.scan();
      setReport(next);
      await reportSprawl(next).catch(() => undefined);
    } catch { setMessage("The scan could not run. Try again."); }
    finally { setBusy(false); }
  }

  async function save(finding: SprawlFinding) {
    setMessage("");
    try {
      if (finding.rule === "password_export") {
        const text = await desktop.sprawl.readExport(finding.path);
        const result = importFromText(text, finding.path.split(/[\\/]/u).pop() ?? "export.csv");
        for (const entry of result.entries) await createVaultItem(vault, entry.kind, { version: 1, ...entry.payload, updatedAt: new Date().toISOString() });
        await onSaved();
        setDone((current) => ({ ...current, [id(finding)]: `Imported ${result.entries.length} logins` }));
        setMessage(`Imported ${result.entries.length} logins into ${vault.name}. Now move the export file to the trash.`);
        return;
      }
      const value = await desktop.sprawl.extract(finding.path, finding.line, finding.rule);
      const file = finding.path.split(/[\\/]/u).pop() ?? finding.path;
      const now = new Date().toISOString();
      await createVaultItem(vault, ITEM_KIND[finding.rule] ?? "api-key", {
        version: 1, title: `${finding.label} (${file})`, secret: value, notes: `Found in ${finding.path}${finding.line ? `, line ${finding.line}` : ""}.`,
        tags: ["found-on-computer"], updatedAt: now, passwordChangedAt: now,
      });
      await onSaved();
      setDone((current) => ({ ...current, [id(finding)]: "Saved in vault" }));
      setMessage("Saved. Replace it in the file with a pkx reference, then rotate the secret if the file was ever shared or committed.");
    } catch { setMessage("It could not be saved. The file may have changed — scan again."); }
  }

  async function trash(finding: SprawlFinding) {
    if (!window.confirm(`Move “${finding.path}” to the trash?`)) return;
    try { await desktop.sprawl.trash(finding.path); setDone((current) => ({ ...current, [id(finding)]: "Moved to trash" })); }
    catch { setMessage("The file could not be moved to the trash."); }
  }

  const findings = report?.findings ?? [];
  return <div className="desktop-tool-card">
    <h3><ScanSearch /> Secrets lying around on this computer</h3>
    <p>Finds passwords and keys stored in plain files: exported password lists, unprotected SSH keys, cloud and API tokens in config files, database passwords in connection strings. Only your Desktop, Documents, Downloads, code folders and tool settings are checked. Nothing is uploaded; your organization only sees how many were found.</p>
    <Button disabled={busy} onClick={() => void scan()}><ScanSearch /> {busy ? "Scanning…" : report ? "Scan again" : "Scan this computer"}</Button>
    {report && <p className="field-hint">{report.filesScanned.toLocaleString()} files checked{report.truncated ? " (stopped early — the folders are very large)" : ""}. {findings.length ? `${findings.length} found.` : "Nothing found."}</p>}
    {findings.length > 0 && <ul className="desktop-tool-list">{findings.map((finding) => <li key={id(finding)} className={`severity-${finding.severity}`}>
      <span className="desktop-tool-level"><TriangleAlert /></span>
      <div><strong>{finding.label}</strong><small>{finding.path}{finding.line ? `:${finding.line}` : ""} · {finding.preview}</small>{done[id(finding)] && <small className="reason">{done[id(finding)]}</small>}</div>
      {finding.rule !== "password_file" && !done[id(finding)] && <Button size="sm" variant="outline" onClick={() => void save(finding)}>{finding.rule === "password_export" ? "Import to vault" : "Save in vault"}</Button>}
      <Button size="sm" variant="ghost" aria-label="Show in folder" onClick={() => void desktop.revealPath(finding.path).catch(() => undefined)}><FolderOpen /></Button>
      {(finding.rule === "password_export" || finding.rule === "password_file" || finding.rule === "private_key") && <Button size="sm" variant="ghost" aria-label="Move to trash" onClick={() => void trash(finding)}><Trash2 /></Button>}
    </li>)}</ul>}
    {message && <p className="form-message" role="status">{message}</p>}
  </div>;
}

/** Reports only counts (never paths or values) as one finding for this computer. */
async function reportSprawl(report: SprawlReport) {
  if (!(await hasSession())) return;
  const id = await installId();
  const serious = report.findings.filter((finding) => finding.severity === "critical" || finding.severity === "high");
  if (!serious.length) { await resolveGuardFindings(id, [SPRAWL_KEY]); return; }
  const exports = serious.filter((finding) => finding.rule === "password_export").length;
  await reportGuardFindings(id, [{
    source: "desktop", category: "device", kind: "plaintext_secrets", severity: exports ? "critical" : "high", action: "detected", key: SPRAWL_KEY,
    subject: exports ? `${exports} unprotected password export${exports === 1 ? "" : "s"} on this computer` : `${serious.length} unprotected secret${serious.length === 1 ? "" : "s"} on this computer`,
    detail: { why: "Passwords or keys are stored in plain files. Move them into the vault with Passkey-X › This computer.", count: serious.length, exports },
  }]);
}
