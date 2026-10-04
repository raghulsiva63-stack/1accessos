"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft, ArrowRight, Building2, Check, CircleCheck, FileUp, FolderLock, FolderPlus, LoaderCircle, RotateCcw, ShieldCheck, TriangleAlert, Upload, UserPlus, Users, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import type { MemberOverview } from "@/lib/enterprise/admin";
import { loadSharingKeys } from "@/lib/enterprise/key-sharing";
import {
  defaultPlan, groupByCollection, releaseMigrationKeys, runTeamMigration, type CollectionPlan, type MigrationProgress,
} from "@/lib/enterprise/team-migration";
import { FORMAT_LABELS, importFromFile, type ImportFormat, type ImportResult } from "@/lib/vault/importers";
import type { WorkspaceVault } from "@/lib/vault/items";

type Role = CollectionPlan["members"][number]["role"];

type TeamSource = {
  id: string;
  label: string;
  formats: string;
  accept: string;
  steps: string[];
  tip?: string;
  hint: (fileName: string) => ImportFormat | undefined;
};

const ext = (fileName: string) => fileName.toLowerCase().split(".").pop() ?? "";

const SOURCES: TeamSource[] = [
  { id: "1password", label: "1Password Business", formats: ".1pux", accept: ".1pux",
    steps: [
      "Make sure your administrator account is a member of every shared vault you want to move (1Password.com → Vaults → Manage access).",
      "In the 1Password 8 desktop app: File → Export → choose the business account → 1PUX, then enter your account password.",
      "Each vault becomes a folder here. Your own Private vault can be skipped in the plan.",
    ],
    tip: "1PUX keeps cards, secure notes and one-time codes. Shared vaults are marked as shared automatically.",
    hint: () => "1password-1pux" },
  { id: "bitwarden", label: "Bitwarden organization", formats: ".json", accept: ".json",
    steps: [
      "Bitwarden web app → Admin Console → choose the organization → Export → Export vault.",
      "File format: .json (not “encrypted”). Confirm with your master password.",
      "Every collection of the organization is included and becomes a folder here.",
    ],
    tip: "An organization export contains only the organization's collections, not anyone's personal vault.",
    hint: () => "bitwarden-json" },
  { id: "lastpass", label: "LastPass Enterprise", formats: ".csv with shared folders", accept: ".csv",
    steps: [
      "Sign in as an admin who is a member of every shared folder you want to move (Admin Console → Shared folders → add yourself).",
      "Vault → Advanced options → Export → LastPass CSV file, and confirm with your master password.",
      "Shared folders (“Shared-…”) are detected automatically.",
    ],
    tip: "LastPass exports only folders you can open, so check shared folder membership first.",
    hint: () => "lastpass" },
  { id: "keeper", label: "Keeper", formats: ".json", accept: ".json,.csv",
    steps: [
      "Sign in to the Keeper Web Vault as an admin who is a member of the shared folders to move.",
      "Settings → Export → JSON, and confirm with your master password (Keeper Commander: export --format=json).",
      "Shared folders keep their names and are marked as shared.",
    ],
    hint: (name) => (ext(name) === "csv" ? "keeper-csv" : "keeper-json") },
  { id: "keepass", label: "KeePass", formats: ".xml", accept: ".xml,.csv",
    steps: [
      "KeePass 2: File → Export → KeePass XML (2.x). KeePassXC: Database → Export → CSV file.",
      "Groups become folders. The Recycle Bin and entry history are left out.",
    ],
    tip: "KeePass has no sharing, so choose who gets each folder in the plan.",
    hint: (name) => (ext(name) === "csv" ? "keepassxc-csv" : "keepass-xml") },
  { id: "dashlane", label: "Dashlane", formats: ".csv", accept: ".csv",
    steps: [
      "Dashlane: Settings → Export data → CSV. Unzip the download and choose credentials.csv.",
      "Dashlane exports items you can see, but not who they are shared with — choose people for each folder in the plan.",
    ],
    hint: () => "dashlane" },
  { id: "other", label: "Other CSV", formats: ".csv", accept: ".csv,.json,.xml,.1pux",
    steps: [
      "Export a CSV with a header row: name or title, url, username, password (notes and totp are optional).",
      "Add a folder column to group items — each folder can become a workspace.",
    ],
    hint: () => undefined },
];

const STEPS = ["Source", "Export file", "Plan", "Migrate", "Report"] as const;
type Step = 0 | 1 | 2 | 3 | 4;

const ROLE_OPTIONS: { value: Role; label: string }[] = [
  { value: "viewer", label: "Viewer" },
  { value: "editor", label: "Editor" },
  { value: "manager", label: "Manager" },
];

const PHASE_LABELS: Record<MigrationProgress["phase"], string> = {
  workspaces: "Creating workspaces",
  items: "Encrypting and uploading items",
  access: "Sharing keys with people",
  done: "Finishing",
};

const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const collectionLabel = (collection: string) => collection || "Items without a folder";

type Totals = { workspacesCreated: number; itemsImported: number; accessGranted: number; waiting: string[] };
const EMPTY_TOTALS: Totals = { workspacesCreated: 0, itemsImported: 0, accessGranted: 0, waiting: [] };

type Loaded = ImportResult & { fileName: string };

function MemberPicker({ labelledBy, value, people, disabled, onChange }: {
  labelledBy: string;
  value: CollectionPlan["members"];
  people: MemberOverview[];
  disabled: boolean;
  onChange: (next: CollectionPlan["members"]) => void;
}) {
  const chosen = new Set(value.map((member) => member.identityId));
  const remaining = people.filter((person) => !chosen.has(person.identity_id));
  const nameOf = (identityId: string) => people.find((person) => person.identity_id === identityId)?.display_name ?? "Former member";
  return <div className="tm-picker" role="group" aria-labelledby={labelledBy}>
    {value.length > 0 && <ul className="tm-chips" aria-label="People with access">{value.map((member) => <li key={member.identityId} className="tm-chip">
      <span>{nameOf(member.identityId)}</span>
      <select aria-label={`Role for ${nameOf(member.identityId)}`} disabled={disabled} value={member.role}
        onChange={(event) => onChange(value.map((entry) => entry.identityId === member.identityId ? { ...entry, role: event.target.value as Role } : entry))}>
        {ROLE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
      <button type="button" disabled={disabled} aria-label={`Remove ${nameOf(member.identityId)}`} onClick={() => onChange(value.filter((entry) => entry.identityId !== member.identityId))}><X aria-hidden="true" /></button>
    </li>)}</ul>}
    {remaining.length > 0 && <label className="tm-add-person"><UserPlus aria-hidden="true" /><span className="sr-only">Add a person</span>
      <select disabled={disabled} value="" onChange={(event) => {
        const selected = event.target.value;
        if (!selected) return;
        const additions = selected === "__everyone" ? remaining : remaining.filter((person) => person.identity_id === selected);
        onChange([...value, ...additions.map((person) => ({ identityId: person.identity_id, role: "editor" as Role }))]);
      }}>
        <option value="">{value.length ? "Add another person…" : "Add people…"}</option>
        {remaining.length > 1 && <option value="__everyone">Everyone listed ({remaining.length})</option>}
        {remaining.map((person) => <option key={person.identity_id} value={person.identity_id}>{person.display_name}{person.email ? ` (${person.email})` : ""}</option>)}
      </select>
    </label>}
    {!value.length && !remaining.length && <small className="tm-muted">No other active members yet.</small>}
  </div>;
}

export function TeamMigrationPanel({ vault, workspaces, rootKey, members, onWorkspacesChanged }: {
  vault: WorkspaceVault;
  workspaces: WorkspaceVault[];
  rootKey?: Uint8Array;
  members: MemberOverview[];
  onWorkspacesChanged?: () => Promise<void> | void;
}) {
  const { isTenantAdmin } = useEnterprise();
  const [step, setStep] = useState<Step>(0);
  const [sourceId, setSourceId] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [reading, setReading] = useState(false);
  const [plan, setPlan] = useState<CollectionPlan[]>([]);
  const [progress, setProgress] = useState<MigrationProgress | null>(null);
  const [skipCounts, setSkipCounts] = useState<Record<string, number>>({});
  const [accessDone, setAccessDone] = useState<string[]>([]);
  const [totals, setTotals] = useState<Totals>(EMPTY_TOTALS);
  const [paused, setPaused] = useState(false);
  const [error, setError] = useState("");
  const [deletedFile, setDeletedFile] = useState(false);
  const workspacesRef = useRef(workspaces);
  useEffect(() => { workspacesRef.current = workspaces; }, [workspaces]);

  const source = SOURCES.find((candidate) => candidate.id === sourceId) ?? null;
  const groups = useMemo(() => (loaded ? groupByCollection(loaded.entries) : new Map<string, ImportResult["entries"]>()), [loaded]);
  const sharedByCollection = useMemo(() => new Map((loaded?.collections ?? []).map((collection) => [collection.name, collection.shared])), [loaded]);
  const people = useMemo(() => members.filter((member) => member.membership_status === "active" && member.identity_id !== vault.identityId)
    .sort((a, b) => a.display_name.localeCompare(b.display_name)), [members, vault.identityId]);
  const targets = useMemo(() => workspaces.filter((entry) => entry.tenantId === vault.tenantId
    && (entry.role === "owner" || entry.role === "manager") && entry.kind !== "vault"), [workspaces, vault.tenantId]);
  const running = progress !== null && progress.phase !== "done";
  const active = plan.filter((entry) => entry.target !== "skip" && groups.has(entry.collection));
  const activeItems = active.reduce((sum, entry) => sum + (groups.get(entry.collection)?.length ?? 0), 0);
  const invalidNames = active.filter((entry) => entry.target === "new" && entry.name.trim().length < 2);
  const unfoldered = groups.get("")?.length ?? 0;

  // Leaving the page mid-run would stop the migration halfway.
  useEffect(() => {
    if (!running) return undefined;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [running]);

  function reset() {
    setStep(0); setSourceId(null); setLoaded(null); setPlan([]); setProgress(null); setSkipCounts({}); setAccessDone([]);
    setTotals(EMPTY_TOTALS); setPaused(false); setError(""); setDeletedFile(false);
  }

  async function choose(file: File) {
    if (!source) return;
    setError(""); setReading(true);
    try {
      const result = await importFromFile(file, source.hint(file.name));
      if (!result.entries.length) throw new Error("No items were found in this file. Check that you chose the export from the selected source.");
      setLoaded({ ...result, fileName: file.name });
      setPlan(defaultPlan(result.entries));
      setSkipCounts({}); setAccessDone([]); setTotals(EMPTY_TOTALS); setPaused(false);
      setStep(2);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "This file could not be read.");
    } finally { setReading(false); }
  }

  function updateStep(collection: string, change: Partial<CollectionPlan>) {
    setPlan((current) => current.map((entry) => entry.collection === collection ? { ...entry, ...change } : entry));
  }

  // Workspaces created by this panel stay unlocked in memory so Resume can reuse them before the
  // workspace list refreshes; their keys are wiped when the panel closes.
  const createdRef = useRef<WorkspaceVault[]>([]);
  useEffect(() => () => { releaseMigrationKeys({ createdWorkspaces: createdRef.current }); createdRef.current = []; }, []);

  async function refreshWorkspaces() {
    try { await onWorkspacesChanged?.(); } catch { /* the list refreshes on next unlock */ }
  }

  async function run() {
    if (!loaded || !rootKey || running) return;
    setStep(3); setError(""); setPaused(false);
    // runTeamMigration writes created workspace ids into step.target; keep them so a retry reuses the workspaces.
    const runPlan: CollectionPlan[] = plan.map((entry) => ({
      ...entry, name: entry.name.trim(),
      members: accessDone.includes(entry.collection) ? [] : entry.members.map((member) => ({ ...member })),
    }));
    const keepTargets = () => setPlan((current) => current.map((entry, index) => ({ ...entry, target: runPlan[index]?.target ?? entry.target })));
    const createdNow = () => runPlan.filter((entry, index) => plan[index]?.target === "new" && entry.target !== "new").length;
    setProgress({ phase: "workspaces", done: 0, total: active.length });
    try {
      const memberIds = [...new Set(runPlan.filter((entry) => entry.target !== "skip").flatMap((entry) => entry.members.map((member) => member.identityId)))];
      const sharingKeys = await loadSharingKeys(memberIds);
      const report = await runTeamMigration({
        tenantId: vault.tenantId, identityId: vault.identityId, rootKey, entries: loaded.entries, plan: runPlan,
        existing: [...workspacesRef.current, ...createdRef.current], sharingKeys, skipCounts, onProgress: setProgress,
      });
      createdRef.current.push(...report.createdWorkspaces);
      keepTargets();
      const nextSkips: Record<string, number> = { ...skipCounts };
      const nextAccess = new Set(accessDone);
      for (const entry of runPlan) {
        if (entry.target === "skip" || !groups.has(entry.collection)) continue;
        const size = groups.get(entry.collection)?.length ?? 0;
        const itemFailures = report.failures.filter((failure) => failure.collection === entry.collection && failure.remaining > 0);
        nextSkips[entry.collection] = size - Math.max(0, ...itemFailures.map((failure) => failure.remaining));
        if (!report.failures.some((failure) => failure.collection === entry.collection && failure.remaining === 0)) nextAccess.add(entry.collection);
      }
      setSkipCounts(nextSkips); setAccessDone([...nextAccess]);
      setTotals((current) => ({
        workspacesCreated: current.workspacesCreated + createdNow(),
        itemsImported: current.itemsImported + report.itemsImported,
        accessGranted: current.accessGranted + report.accessGranted,
        waiting: [...new Set([...current.waiting, ...report.waitingForMembers])],
      }));
      setProgress(null);
      await refreshWorkspaces();
      if (report.failures.length) {
        const itemsLeft = report.failures.reduce((sum, failure) => sum + failure.remaining, 0);
        const accessLeft = report.failures.filter((failure) => failure.remaining === 0).length;
        setPaused(true);
        setError(`The migration paused. ${itemsLeft ? `${plural(itemsLeft, "item")} still need to be imported. ` : ""}${accessLeft ? `Access for ${plural(accessLeft, "folder")} could not be shared yet. ` : ""}Check your connection and press Resume — nothing is imported twice.`);
        return;
      }
      setStep(4);
    } catch (reason) {
      keepTargets();
      setTotals((current) => ({ ...current, workspacesCreated: current.workspacesCreated + createdNow() }));
      setProgress(null); setPaused(true);
      await refreshWorkspaces();
      const detail = reason instanceof Error && /no longer available|at least 2 characters/u.test(reason.message) ? reason.message : "";
      setError(detail ? `${detail} Wait a moment for the workspace list to refresh, then press Resume.` : adminErrorMessage(reason, "The migration paused before it finished. Check your connection and press Resume — workspaces already created are reused."));
    }
  }

  if (!isTenantAdmin) {
    return <Card><CardHeader><CardTitle><Building2 /> Team migration</CardTitle><CardDescription>Only organization owners and admins can move a team&apos;s shared folders into Passkey-X. Each person can import their own items in Settings → Import.</CardDescription></CardHeader></Card>;
  }

  if (!rootKey) {
    return <Card><CardHeader><CardTitle><Building2 /> Team migration</CardTitle>
      <CardDescription>Team migration creates encrypted workspaces on this device, so it needs your vault to be unlocked here. Lock and unlock Passkey-X, then open Admin console → Migration again.</CardDescription></CardHeader></Card>;
  }

  const percent = progress ? Math.round((progress.done / Math.max(1, progress.total)) * 100) : 0;
  const waitingNames = totals.waiting.map((id) => members.find((member) => member.identity_id === id)?.display_name ?? "A member");

  return <Card className="tm-wizard">
    <CardHeader>
      <CardTitle><Building2 /> Move your team to Passkey-X</CardTitle>
      <CardDescription>Import your company&apos;s export, turn each shared folder or collection into an organization workspace, and give the right people access. The file is read on this device and every item is encrypted before upload — Passkey-X never sees the contents.</CardDescription>
    </CardHeader>
    <CardContent className="tm-body">
      <ol className="tm-steps" aria-label="Migration steps">
        {STEPS.map((label, index) => <li key={label} className={index < step ? "done" : index === step ? "current" : ""} aria-current={index === step ? "step" : undefined}>
          <span className="tm-step-dot" aria-hidden="true">{index < step ? <Check /> : index + 1}</span><span>{label}</span>
        </li>)}
      </ol>

      {step === 0 && <section className="tm-panel" aria-labelledby="tm-source-title">
        <h3 id="tm-source-title">Which password manager is your team using?</h3>
        <div className="tm-tiles" role="group" aria-label="Source password manager">
          {SOURCES.map((candidate) => <button key={candidate.id} type="button" className={`tm-tile${candidate.id === sourceId ? " selected" : ""}`} aria-pressed={candidate.id === sourceId} onClick={() => { setSourceId(candidate.id); setError(""); }}>
            <strong>{candidate.label}</strong><small>{candidate.formats}</small>
          </button>)}
        </div>
        {source && <div className="tm-instructions" aria-live="polite">
          <h4>Admin export from {source.label}</h4>
          <ol>{source.steps.map((line) => <li key={line}>{line}</li>)}</ol>
          {source.tip && <p className="tm-muted">{source.tip}</p>}
          <p className="tm-local"><FolderLock aria-hidden="true" /> The export contains passwords in plain text. Save it somewhere private and delete it when the migration is done.</p>
        </div>}
        <div className="tm-actions"><Button disabled={!source} onClick={() => setStep(1)}>Continue <ArrowRight /></Button></div>
      </section>}

      {step === 1 && source && <section className="tm-panel" aria-labelledby="tm-upload-title">
        <h3 id="tm-upload-title">Choose the {source.label} export</h3>
        <label className={`tm-drop${reading ? " busy" : ""}`}>
          {reading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Upload aria-hidden="true" />}
          <span>{reading ? "Reading on this device…" : "Choose export file"}</span>
          <small>{source.accept.split(",").join(" ")}</small>
          <input type="file" accept={source.accept} disabled={reading} aria-label={`${source.label} export file`} onChange={(event) => { const file = event.target.files?.[0]; if (file) void choose(file); event.target.value = ""; }} />
        </label>
        <p className="tm-local"><FolderLock aria-hidden="true" /> The file never leaves this device.</p>
        <div className="tm-actions"><Button variant="ghost" onClick={() => { setStep(0); setError(""); }}><ArrowLeft /> Back</Button></div>
      </section>}

      {step === 2 && loaded && <section className="tm-panel" aria-labelledby="tm-plan-title">
        <h3 id="tm-plan-title">Plan the workspaces</h3>
        <div className="tm-file"><FileUp aria-hidden="true" /><div><strong>{FORMAT_LABELS[loaded.format]} · {plural(loaded.entries.length, "item")} in {plural(groups.size, "folder")}</strong><span>{loaded.fileName}</span></div></div>
        {loaded.warnings.length > 0 && <ul className="tm-warnings" aria-label="Warnings">{loaded.warnings.map((warning) => <li key={warning}><TriangleAlert aria-hidden="true" /> {warning}</li>)}</ul>}
        <p className="tm-muted">For each folder, choose where its items go and who gets access. You become the owner of new workspaces.</p>
        <ul className="tm-plan">
          {plan.map((entry, index) => {
            const count = groups.get(entry.collection)?.length ?? 0;
            const shared = sharedByCollection.get(entry.collection) || (groups.get(entry.collection) ?? []).some((item) => item.shared);
            const rowId = `tm-row-${index}`;
            return <li key={entry.collection} className={entry.target === "skip" ? "skipped" : ""}>
              <div className="tm-plan-head">
                <strong className="tm-plan-name" title={collectionLabel(entry.collection)}>{collectionLabel(entry.collection)}</strong>
                {shared && <span className="tm-badge shared"><Users aria-hidden="true" /> shared</span>}
                <span className="tm-count">{plural(count, "item")}</span>
              </div>
              <div className="tm-plan-fields">
                <div><label htmlFor={`${rowId}-target`}>Destination</label>
                  <select id={`${rowId}-target`} className="tm-select" value={entry.target} onChange={(event) => updateStep(entry.collection, { target: event.target.value })}>
                    <option value="new">Create new workspace</option>
                    {targets.length > 0 && <optgroup label="Existing workspaces">{targets.map((target) => <option key={target.workspaceId} value={target.workspaceId}>{target.name}</option>)}</optgroup>}
                    <option value="skip">Skip</option>
                  </select></div>
                {entry.target === "new" && <div><label htmlFor={`${rowId}-name`}>Workspace name</label>
                  <Input id={`${rowId}-name`} value={entry.name} maxLength={80} required aria-invalid={entry.name.trim().length < 2 || undefined} onChange={(event) => updateStep(entry.collection, { name: event.target.value })} /></div>}
              </div>
              {entry.target !== "skip" && <div className="tm-access"><span className="tm-field-label" id={`${rowId}-people`}>Who gets access</span>
                <MemberPicker labelledBy={`${rowId}-people`} value={entry.members} people={people} disabled={false} onChange={(next) => updateStep(entry.collection, { members: next })} /></div>}
            </li>;
          })}
        </ul>
        {unfoldered > 0 && <p className="tm-hint"><Users aria-hidden="true" /> <span>{plural(unfoldered, "item")} without a folder {plan.find((entry) => entry.collection === "")?.target === "skip" ? "will be skipped" : "will be imported as chosen above"}. Personal items belong in each person&apos;s own vault — ask everyone to import theirs with Settings → Import.</span></p>}
        {invalidNames.length > 0 && <p className="form-message" role="alert">Give every new workspace a name with at least 2 characters.</p>}
        <div className="tm-actions">
          <Button disabled={!active.length || invalidNames.length > 0} onClick={() => void run()}><ShieldCheck /> {active.length ? `Encrypt ${plural(activeItems, "item")} into ${plural(active.length, "workspace")}` : "Choose at least one folder"}</Button>
          <Button variant="ghost" onClick={() => { setLoaded(null); setPlan([]); setStep(1); }}><ArrowLeft /> Choose another file</Button>
        </div>
      </section>}

      {step === 3 && <section className="tm-panel" aria-labelledby="tm-run-title">
        <h3 id="tm-run-title">Migrating</h3>
        <ol className="tm-phases" aria-label="Migration phases">
          {(["workspaces", "items", "access"] as const).map((phase, index) => {
            const order = progress ? ["workspaces", "items", "access", "done"].indexOf(progress.phase) : -1;
            return <li key={phase} className={order > index ? "done" : order === index ? "current" : ""}>{order > index ? <Check aria-hidden="true" /> : <span aria-hidden="true">{index + 1}</span>}{PHASE_LABELS[phase]}</li>;
          })}
        </ol>
        {progress && <div className="tm-progress" role="status" aria-live="polite">
          <LoaderCircle className="spin" aria-hidden="true" />
          <div><strong>{PHASE_LABELS[progress.phase]} — {progress.done} of {progress.total}</strong>
            <div className="tm-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} aria-label={PHASE_LABELS[progress.phase]}><i style={{ width: `${percent}%` }} /></div>
            <small>Keep this tab open until the migration finishes.</small></div>
        </div>}
        {paused && !progress && <div className="tm-actions">
          <Button onClick={() => void run()}><RotateCcw /> Resume migration</Button>
          <Button variant="ghost" onClick={() => setStep(4)}>Stop and see what was done</Button>
        </div>}
      </section>}

      {step === 4 && <section className="tm-panel" aria-labelledby="tm-report-title">
        <div className="tm-success" role="status"><CircleCheck aria-hidden="true" /><div><h3 id="tm-report-title">{paused ? "Migration stopped before the end" : "Your team's folders are in Passkey-X"}</h3><p>Everything was encrypted on this device before upload.</p></div></div>
        <dl className="tm-kpis">
          <div><dt>Workspaces created</dt><dd>{totals.workspacesCreated}</dd></div>
          <div><dt>Items imported</dt><dd>{totals.itemsImported}</dd></div>
          <div><dt>Access granted</dt><dd>{totals.accessGranted}</dd></div>
          <div><dt>People waiting</dt><dd>{waitingNames.length}</dd></div>
        </dl>
        {waitingNames.length > 0 && <div className="tm-waiting"><h4><FolderPlus aria-hidden="true" /> Waiting for keys</h4>
          <p>{waitingNames.join(", ")}</p>
          <small>These people haven&apos;t unlocked Passkey-X since joining, so their workspace keys can&apos;t be encrypted to them yet. Their access is delivered automatically after they next unlock Passkey-X and an admin opens the console.</small></div>}
        <ul className="tm-checklist"><li className="emphasis"><label><input type="checkbox" checked={deletedFile} onChange={(event) => setDeletedFile(event.target.checked)} /><span><strong>Delete the export file</strong><small>It contains your team&apos;s passwords in plain text. Delete it, empty the trash, and remove any copies (downloads folder, email, chat).</small></span></label></li>
          <li><span><strong>Tell people to import their personal items</strong><small>Each person can bring their own logins with Settings → Import.</small></span></li></ul>
        <div className="tm-actions"><Button variant="outline" onClick={reset}><Upload /> Start another migration</Button></div>
      </section>}

      {error && <p className="form-message" role="alert"><TriangleAlert /> {error}</p>}
    </CardContent>
  </Card>;
}
