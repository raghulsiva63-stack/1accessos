"use client";

import { useState } from "react";
import { FileUp, LoaderCircle, ShieldCheck, TriangleAlert, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { FORMAT_LABELS, importFromText, type ImportResult } from "@/lib/vault/importers";
import { createVaultItem, type ItemKind, type WorkspaceVault } from "@/lib/vault/items";

const KIND_LABELS: Partial<Record<ItemKind, string>> = { login: "logins", "secure-note": "secure notes", "payment-card": "cards", identity: "identities" };

export function ImportCard({ vault, onImported }: { vault: WorkspaceVault; onImported: () => Promise<void> | void }) {
  const { record } = useEnterprise();
  const [preview, setPreview] = useState<(ImportResult & { fileName: string }) | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function choose(file: File) {
    setError(""); setMessage(""); setPreview(null);
    try {
      const text = await file.text();
      setPreview({ ...importFromText(text, file.name), fileName: file.name });
    } catch (reason) { setError(reason instanceof Error ? reason.message : "This file could not be read."); }
  }

  async function run() {
    if (!preview) return;
    const entries = preview.entries;
    setProgress({ done: 0, total: entries.length }); setError("");
    let done = 0;
    try {
      for (const entry of entries) {
        await createVaultItem(vault, entry.kind, { version: 1, ...entry.payload, updatedAt: new Date().toISOString() });
        done += 1;
        if (done % 5 === 0 || done === entries.length) setProgress({ done, total: entries.length });
      }
      record("vault.imported", null);
      setMessage(`${done} item${done === 1 ? "" : "s"} encrypted and imported. Delete the export file from your computer now — it contains your passwords in plain text.`);
      setPreview(null);
      await onImported();
    } catch {
      setError(`The import stopped after ${done} item${done === 1 ? "" : "s"}. Check your connection and import the file again; already imported items will be duplicated.`);
    } finally { setProgress(null); }
  }

  const counts = preview ? Object.entries(preview.entries.reduce<Record<string, number>>((acc, entry) => ({ ...acc, [entry.kind]: (acc[entry.kind] ?? 0) + 1 }), {})) : [];

  return <Card className="import-card">
    <CardHeader><CardTitle>Import from another password manager</CardTitle><CardDescription>1Password, Bitwarden, LastPass, Dashlane, Chrome, Edge, Firefox or any CSV. The file is read on this device and each item is encrypted before upload.</CardDescription></CardHeader>
    <CardContent>
      {!preview && !progress && <label className="file-action"><Upload /><span>Choose export file (.csv or .json)</span><input type="file" accept=".csv,.json,text/csv,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void choose(file); event.target.value = ""; }} /></label>}
      {preview && !progress && <div className="import-preview">
        <div className="import-summary"><FileUp /><div><strong>{FORMAT_LABELS[preview.format]} detected</strong><span>{preview.fileName}</span></div></div>
        <ul>{counts.map(([kind, count]) => <li key={kind}><strong>{count}</strong> {KIND_LABELS[kind as ItemKind] ?? kind}</li>)}{preview.skipped > 0 && <li className="muted-text">{preview.skipped} empty or unsupported rows skipped</li>}</ul>
        <div className="inline-actions"><Button onClick={() => void run()}><ShieldCheck /> Encrypt and import {preview.entries.length} items</Button><Button variant="ghost" onClick={() => setPreview(null)}>Cancel</Button></div>
      </div>}
      {progress && <div className="import-progress" role="status"><LoaderCircle className="spin" /><div><strong>Encrypting {progress.done} of {progress.total}…</strong><div className="import-bar"><i style={{ width: `${Math.round((progress.done / Math.max(1, progress.total)) * 100)}%` }} /></div></div></div>}
      {message && <p className="form-message neutral-message" role="status">{message}</p>}
      {error && <p className="form-message" role="alert"><TriangleAlert /> {error}</p>}
    </CardContent>
  </Card>;
}
