"use client";

import { useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, CircleCheck, FileUp, FolderLock, LoaderCircle, RotateCcw, ShieldCheck, TriangleAlert, Upload, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { collectionTags, FORMAT_LABELS, findDuplicates, importFromFile, type ImportedEntry, type ImportFormat, type ImportResult } from "@/lib/vault/importers";
import { createVaultItem, type ItemKind, type VaultItem, type WorkspaceVault } from "@/lib/vault/items";

type SourceId = "1password" | "bitwarden" | "lastpass" | "dashlane" | "keeper" | "keepass" | "apple" | "chrome" | "firefox" | "other";

type Source = {
  id: SourceId;
  label: string;
  formats: string;
  accept: string;
  steps: string[];
  tip?: string;
  hint: (fileName: string) => ImportFormat | undefined;
};

const ext = (fileName: string) => fileName.toLowerCase().split(".").pop() ?? "";

const SOURCES: Source[] = [
  { id: "1password", label: "1Password", formats: ".1pux or .csv", accept: ".1pux,.csv",
    steps: ["1Password 8: File → Export → choose your account → 1PUX (recommended)", "Enter your 1Password account password when asked, then save the file."],
    tip: "1PUX keeps your vaults, card details and one-time codes. CSV only has logins.",
    hint: (name) => (ext(name) === "1pux" ? "1password-1pux" : "1password") },
  { id: "bitwarden", label: "Bitwarden", formats: ".json or .csv", accept: ".json,.csv",
    steps: ["Bitwarden: Tools → Export vault → .json", "Organization collections: Admin console → Export → .json"],
    tip: "Choose the plain .json format, not \"encrypted\". JSON keeps folders, collections, cards and identities.",
    hint: (name) => (ext(name) === "csv" ? "bitwarden-csv" : "bitwarden-json") },
  { id: "lastpass", label: "LastPass", formats: ".csv", accept: ".csv",
    steps: ["LastPass: Advanced options → Export", "Confirm with your master password; the browser downloads a .csv file."],
    tip: "Shared folders (\"Shared-…\") are detected automatically.",
    hint: () => "lastpass" },
  { id: "dashlane", label: "Dashlane", formats: ".csv", accept: ".csv",
    steps: ["Dashlane: Settings → Export data → CSV", "Unzip the download and choose credentials.csv."],
    hint: () => "dashlane" },
  { id: "keeper", label: "Keeper", formats: ".json or .csv", accept: ".json,.csv",
    steps: ["Keeper: Settings → Export → JSON", "Confirm with your master password and save the file."],
    tip: "JSON keeps folders, shared folders and one-time codes.",
    hint: (name) => (ext(name) === "csv" ? "keeper-csv" : "keeper-json") },
  { id: "keepass", label: "KeePass / KeePassXC", formats: ".xml or .csv", accept: ".xml,.csv",
    steps: ["KeePass: File → Export → KeePass XML (2.x)", "KeePassXC: Database → Export → CSV File"],
    tip: "Groups become folders. The Recycle Bin and entry history are left out.",
    hint: (name) => (ext(name) === "csv" ? "keepassxc-csv" : "keepass-xml") },
  { id: "apple", label: "Apple Passwords", formats: ".csv", accept: ".csv",
    steps: ["Apple Passwords (macOS): File → Export All Passwords", "Safari (older macOS): File → Export → Passwords"],
    hint: () => "apple-csv" },
  { id: "chrome", label: "Chrome / Edge / Brave", formats: ".csv", accept: ".csv",
    steps: ["Chrome: Settings → Passwords → Settings → Export passwords", "Edge: Settings → Passwords → ⋯ → Export passwords. Brave: Settings → Autofill and passwords → Password manager → Settings → Export"],
    hint: () => "chrome" },
  { id: "firefox", label: "Firefox", formats: ".csv", accept: ".csv",
    steps: ["Firefox: about:logins → ⋯ → Export Logins", "Confirm with your device password and save logins.csv."],
    hint: () => "firefox" },
  { id: "other", label: "Other CSV", formats: ".csv, .json or .xml", accept: ".csv,.json,.xml,.1pux",
    steps: ["Export a CSV with a header row: name or title, url, username, password (notes and totp are optional)."],
    hint: () => undefined },
];

const KIND_LABELS: Partial<Record<ItemKind, [string, string]>> = {
  login: ["login", "logins"], "secure-note": ["secure note", "secure notes"], "payment-card": ["card", "cards"], identity: ["identity", "identities"],
  wifi: ["Wi-Fi network", "Wi-Fi networks"], "api-key": ["API key", "API keys"], "ssh-key": ["SSH key", "SSH keys"], database: ["database", "databases"], "software-license": ["license", "licenses"],
};
const kindLabel = (kind: ItemKind, count: number) => { const label = KIND_LABELS[kind]; return label ? label[count === 1 ? 0 : 1] : kind; };
const countItems = (count: number) => `${count} item${count === 1 ? "" : "s"}`;

const STEPS = ["Source", "Export file", "Review", "Import", "Finish"] as const;
type Step = 0 | 1 | 2 | 3 | 4;
type Preview = ImportResult & { fileName: string; duplicates: number[] };

/** Applies the review choices: duplicate skipping and whether folders stay as tags. */
function prepare(preview: Preview, skipDuplicates: boolean, keepFolderTags: boolean): ImportedEntry[] {
  const skip = skipDuplicates ? new Set(preview.duplicates) : new Set<number>();
  return preview.entries.filter((_, index) => !skip.has(index)).map((entry) => {
    if (keepFolderTags || !entry.collection || !entry.payload.tags) return entry;
    const folderTags = new Set(collectionTags(entry.collection).map((tag) => tag.toLowerCase()));
    const tags = entry.payload.tags.filter((tag) => !folderTags.has(tag.toLowerCase()));
    return { ...entry, payload: { ...entry.payload, tags: tags.length ? tags : undefined } };
  });
}

export function SwitchWizard({ vault, items: existingItems, onImported, onOpenExtension }: { vault: WorkspaceVault; items: VaultItem[]; onImported: () => Promise<void> | void; onOpenExtension?: () => void }) {
  const { record, isTenantAdmin } = useEnterprise();
  const [step, setStep] = useState<Step>(0);
  const [sourceId, setSourceId] = useState<SourceId | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [reading, setReading] = useState(false);
  const [skipDuplicates, setSkipDuplicates] = useState(true);
  const [keepFolderTags, setKeepFolderTags] = useState(true);
  const [queue, setQueue] = useState<ImportedEntry[] | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [imported, setImported] = useState(0);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [checklist, setChecklist] = useState({ deleteFile: false, extension: false, autofill: false, security: false });

  const source = SOURCES.find((candidate) => candidate.id === sourceId) ?? null;
  const counts = useMemo(() => {
    if (!preview) return [] as [ItemKind, number][];
    const map = new Map<ItemKind, number>();
    for (const entry of preview.entries) map.set(entry.kind, (map.get(entry.kind) ?? 0) + 1);
    return [...map.entries()];
  }, [preview]);
  const sharedCollections = preview?.collections.filter((collection) => collection.shared).length ?? 0;
  const toImport = preview ? preview.entries.length - (skipDuplicates ? preview.duplicates.length : 0) : 0;

  function reset() {
    setStep(0); setSourceId(null); setPreview(null); setQueue(null); setProgress(null); setImported(0);
    setError(""); setNotice(""); setSkipDuplicates(true); setKeepFolderTags(true);
    setChecklist({ deleteFile: false, extension: false, autofill: false, security: false });
  }

  async function choose(file: File) {
    if (!source) return;
    setError(""); setPreview(null); setReading(true);
    try {
      const result = await importFromFile(file, source.hint(file.name));
      const existing = existingItems.filter((item) => !item.deletedAt).map((item) => ({ kind: item.contentType, payload: item.payload }));
      setPreview({ ...result, fileName: file.name, duplicates: findDuplicates(result.entries, existing) });
      setSkipDuplicates(true); setKeepFolderTags(true); setQueue(null);
      setStep(2);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "This file could not be read.");
    } finally { setReading(false); }
  }

  async function run() {
    if (!preview) return;
    const entries = queue ?? prepare(preview, skipDuplicates, keepFolderTags);
    if (!entries.length) { setStep(4); setNotice("Nothing new to import — everything in this file is already in your vault."); return; }
    setStep(3); setError(""); setNotice("");
    setProgress({ done: 0, total: entries.length });
    let done = 0;
    try {
      for (const entry of entries) {
        await createVaultItem(vault, entry.kind, { version: 1, ...entry.payload, updatedAt: new Date().toISOString() });
        done += 1;
        if (done % 5 === 0 || done === entries.length) setProgress({ done, total: entries.length });
      }
    } catch {
      // Keep only what is left so "Resume" continues instead of duplicating.
      setQueue(entries.slice(done));
      setImported((previous) => previous + done);
      setProgress(null);
      setError(`The import paused after ${done} of ${countItems(entries.length)}. Check your connection and press Resume to continue with the remaining ${entries.length - done}.`);
      if (done) { try { await onImported(); } catch { /* list refresh is best effort */ } }
      return;
    }
    record("vault.imported", null);
    setImported((previous) => previous + done);
    setQueue(null); setProgress(null); setPreview(null);
    setStep(4);
    try { await onImported(); } catch { setNotice("Lock and unlock the vault to see the imported items."); }
  }

  const resumable = Boolean(queue && queue.length && !progress);

  return <Card className="mig-wizard">
    <CardHeader>
      <CardTitle>Switch to Passkey-X</CardTitle>
      <CardDescription>Bring everything over from your old password manager or browser in a few minutes. Your export file is read on this device, and each item is encrypted before it is uploaded.</CardDescription>
    </CardHeader>
    <CardContent className="mig-body">
      <ol className="mig-steps" aria-label="Migration steps">
        {STEPS.map((label, index) => <li key={label} className={index < step ? "done" : index === step ? "current" : ""} aria-current={index === step ? "step" : undefined}>
          <span className="mig-step-dot" aria-hidden="true">{index < step ? <Check /> : index + 1}</span><span>{label}</span>
        </li>)}
      </ol>

      {step === 0 && <section className="mig-panel" aria-labelledby="mig-source-title">
        <h3 id="mig-source-title">Where are you coming from?</h3>
        <div className="mig-tiles" role="group" aria-label="Password manager">
          {SOURCES.map((candidate) => <button key={candidate.id} type="button" className={`mig-tile${candidate.id === sourceId ? " selected" : ""}`} aria-pressed={candidate.id === sourceId} onClick={() => { setSourceId(candidate.id); setError(""); }}>
            <strong>{candidate.label}</strong><small>{candidate.formats}</small>
          </button>)}
        </div>
        {source && <div className="mig-instructions" aria-live="polite">
          <h4>Export from {source.label}</h4>
          <ol>{source.steps.map((line) => <li key={line}>{line}</li>)}</ol>
          {source.tip && <p className="mig-tip">{source.tip}</p>}
          <p className="mig-local"><FolderLock aria-hidden="true" /> The file stays on this device. Passkey-X never uploads it — only encrypted items leave your browser.</p>
        </div>}
        <div className="mig-actions"><Button disabled={!source} onClick={() => setStep(1)}>Continue <ArrowRight /></Button></div>
      </section>}

      {step === 1 && source && <section className="mig-panel" aria-labelledby="mig-upload-title">
        <h3 id="mig-upload-title">Choose your {source.label} export</h3>
        <p className="mig-muted">Accepted: {source.formats}. {source.steps[0]}</p>
        <label className={`mig-drop${reading ? " busy" : ""}`}>
          {reading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Upload aria-hidden="true" />}
          <span>{reading ? "Reading on this device…" : "Choose export file"}</span>
          <small>{source.accept.split(",").join(" ")}</small>
          <input type="file" accept={source.accept} disabled={reading} aria-label={`${source.label} export file`} onChange={(event) => { const file = event.target.files?.[0]; if (file) void choose(file); event.target.value = ""; }} />
        </label>
        <p className="mig-local"><FolderLock aria-hidden="true" /> The file stays on this device.</p>
        <div className="mig-actions"><Button variant="ghost" onClick={() => { setStep(0); setError(""); }}><ArrowLeft /> Back</Button></div>
      </section>}

      {step === 2 && preview && <section className="mig-panel" aria-labelledby="mig-review-title">
        <h3 id="mig-review-title">Review before importing</h3>
        <div className="mig-file"><FileUp aria-hidden="true" /><div><strong>{FORMAT_LABELS[preview.format]} detected</strong><span>{preview.fileName}</span></div></div>
        <ul className="mig-counts">
          {counts.map(([kind, count]) => <li key={kind}><strong>{count}</strong> {kindLabel(kind, count)}</li>)}
          {preview.skipped > 0 && <li className="muted">{preview.skipped} empty or unsupported skipped</li>}
        </ul>
        {preview.collections.length > 0 && <div className="mig-collections">
          <h4>{preview.collections.length} folder{preview.collections.length === 1 ? "" : "s"} and collection{preview.collections.length === 1 ? "" : "s"}</h4>
          <ul>{preview.collections.slice(0, 60).map((collection) => <li key={collection.name}>
            <span className="mig-collection-name">{collection.name}</span>
            {collection.shared && <span className="mig-badge shared"><Users aria-hidden="true" /> shared</span>}
            <span className="mig-collection-count">{collection.count}</span>
          </li>)}</ul>
          {preview.collections.length > 60 && <p className="mig-muted">and {preview.collections.length - 60} more</p>}
        </div>}
        {preview.warnings.length > 0 && <ul className="mig-warnings" aria-label="Warnings">{preview.warnings.map((warning) => <li key={warning}><TriangleAlert aria-hidden="true" /> {warning}</li>)}</ul>}
        <div className="mig-options">
          {preview.duplicates.length > 0 && <label><input type="checkbox" checked={skipDuplicates} onChange={(event) => setSkipDuplicates(event.target.checked)} /><span><strong>Skip {preview.duplicates.length} duplicate{preview.duplicates.length === 1 ? "" : "s"}</strong><small>Same type, website, username and password as an item already in this vault or earlier in the file.</small></span></label>}
          <label><input type="checkbox" checked={keepFolderTags} onChange={(event) => setKeepFolderTags(event.target.checked)} /><span><strong>Keep folders as tags</strong><small>Folder and collection names become tags in “{vault.name}” so you can still filter by them.</small></span></label>
        </div>
        {(isTenantAdmin || sharedCollections > 0) && <p className="mig-hint"><Users aria-hidden="true" /> <span>{sharedCollections > 0 ? `${sharedCollections} shared folder${sharedCollections === 1 ? "" : "s"} will be imported into “${vault.name}”. ` : ""}Moving a whole team? Admins can use Admin console → Migration to turn shared folders into team workspaces.</span></p>}
        <div className="mig-actions">
          <Button onClick={() => void run()}><ShieldCheck /> {toImport ? `Encrypt and import ${countItems(toImport)}` : "Nothing new — finish"}</Button>
          <Button variant="ghost" onClick={() => { setPreview(null); setStep(1); }}><ArrowLeft /> Choose another file</Button>
        </div>
      </section>}

      {step === 3 && <section className="mig-panel" aria-labelledby="mig-import-title">
        <h3 id="mig-import-title">Importing</h3>
        {progress && <div className="mig-progress" role="status" aria-live="polite">
          <LoaderCircle className="spin" aria-hidden="true" />
          <div><strong>Encrypting {progress.done} of {progress.total}…</strong>
            <div className="mig-bar" role="progressbar" aria-valuemin={0} aria-valuemax={progress.total} aria-valuenow={progress.done} aria-label="Import progress"><i style={{ width: `${Math.round((progress.done / Math.max(1, progress.total)) * 100)}%` }} /></div>
            <small>Keep this tab open until the import finishes.</small></div>
        </div>}
        {resumable && <div className="mig-actions">
          <Button onClick={() => void run()}><RotateCcw /> Resume import ({queue!.length} left)</Button>
          <Button variant="ghost" onClick={reset}>Cancel</Button>
        </div>}
      </section>}

      {step === 4 && <section className="mig-panel" aria-labelledby="mig-finish-title">
        <div className="mig-success" role="status"><CircleCheck aria-hidden="true" /><div><h3 id="mig-finish-title">{imported ? `${countItems(imported)} encrypted and imported` : "You are all set"}</h3><p>Finish the switch with these steps.</p></div></div>
        <ul className="mig-checklist">
          <li className="emphasis"><label><input type="checkbox" checked={checklist.deleteFile} onChange={(event) => setChecklist({ ...checklist, deleteFile: event.target.checked })} /><span><strong>Delete the export file</strong><small>It contains your passwords in plain text. Delete it and empty the trash or recycle bin.</small></span></label></li>
          <li><label><input type="checkbox" checked={checklist.extension} onChange={(event) => setChecklist({ ...checklist, extension: event.target.checked })} /><span><strong>Install the browser extension</strong><small>{onOpenExtension ? <button type="button" className="mig-link" onClick={onOpenExtension}>Set up the extension</button> : <a className="mig-link" href="/download">Get the extension</a>} to fill passwords and passkeys automatically.</small></span></label></li>
          <li><label><input type="checkbox" checked={checklist.autofill} onChange={(event) => setChecklist({ ...checklist, autofill: event.target.checked })} /><span><strong>Turn off autofill in your old password manager or browser</strong><small>Two autofill prompts compete; keep only Passkey-X.</small></span></label></li>
          <li><label><input type="checkbox" checked={checklist.security} onChange={(event) => setChecklist({ ...checklist, security: event.target.checked })} /><span><strong>Run a Security check</strong><small>Find weak, reused and exposed passwords among what you just imported.</small></span></label></li>
        </ul>
        <div className="mig-actions"><Button variant="outline" onClick={reset}><Upload /> Import another file</Button></div>
      </section>}

      {notice && <p className="form-message neutral-message" role="status">{notice}</p>}
      {error && <p className="form-message" role="alert"><TriangleAlert /> {error}</p>}
    </CardContent>
  </Card>;
}
