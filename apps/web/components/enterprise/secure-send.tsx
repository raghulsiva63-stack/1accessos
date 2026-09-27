"use client";

import { useEffect, useState } from "react";
import { Ban, Check, Copy, FileUp, Link2, LoaderCircle, LockKeyhole, Send, TimerOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import {
  createSecureSend, fileToPayload, listMySends, revokeSecureSend, SEND_MAX_TEXT_CHARS, sendStatus,
  type SentSummary,
} from "@/lib/enterprise/send";
import type { WorkspaceVault } from "@/lib/vault/items";

const EXPIRY_OPTIONS = [
  { hours: 1, label: "1 hour" }, { hours: 24, label: "1 day" }, { hours: 72, label: "3 days" },
  { hours: 168, label: "7 days" }, { hours: 720, label: "30 days" },
];

function sendError(reason: unknown) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : String(reason ?? "");
  if (/restricted by organization policy/iu.test(detail)) return "Your organization only allows owners and admins to create Secure Send links.";
  if (/daily secure send limit/iu.test(detail)) return "You've reached today's Secure Send limit.";
  if (/PGRST202|42883/iu.test(detail)) return "Secure Send is being enabled for your account. Try again shortly.";
  if (reason instanceof Error && !("code" in reason)) return reason.message;
  return "The Secure Send link could not be created.";
}

export function SecureSendView({ vault }: { vault: WorkspaceVault }) {
  const { policy, isTenantAdmin } = useEnterprise();
  const [mode, setMode] = useState<"text" | "file">("text");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [maxViews, setMaxViews] = useState(1);
  const [expiry, setExpiry] = useState(24);
  const [passphrase, setPassphrase] = useState("");
  const [showSender, setShowSender] = useState(true);
  const [link, setLink] = useState("");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [sends, setSends] = useState<SentSummary[]>([]);
  const [version, setVersion] = useState(0);
  const [now] = useState(() => Date.now());
  const blockedByPolicy = policy.sharingMode !== "open" && !isTenantAdmin;

  useEffect(() => {
    let active = true;
    listMySends(vault.identityId).then((rows) => { if (active) setSends(rows); }, () => undefined);
    return () => { active = false; };
  }, [vault.identityId, version]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setMessage(""); setLink(""); setCopied(false);
    try {
      const payload = mode === "text" ? { v: 1 as const, kind: "text" as const, text } : file ? await fileToPayload(file) : null;
      if (!payload) throw new Error("Choose a file to send.");
      const created = await createSecureSend(vault.tenantId, payload, { maxViews, expiresInHours: expiry, passphrase: passphrase || undefined, showSender }, window.location.origin);
      setLink(created); setText(""); setFile(null); setPassphrase("");
      setVersion((value) => value + 1);
    } catch (reason) { setMessage(sendError(reason)); }
    finally { setBusy(false); }
  }

  async function revoke(send: SentSummary) {
    if (!window.confirm("Revoke this link? The encrypted content is deleted immediately.")) return;
    try { await revokeSecureSend(send.id); setVersion((value) => value + 1); }
    catch (reason) { setMessage(sendError(reason)); }
  }

  return <div className="feature-page secure-send">
    <section className="feature-intro"><span className="status-pill"><LockKeyhole /> End-to-end encrypted</span><h2>Secure Send</h2><p>Share a password, note or file with anyone — even people without Passkey-X. It is encrypted in this browser, the key travels only inside the link, and the content is destroyed after the last view or when it expires.</p></section>
    {blockedByPolicy ? <Card><CardContent className="soft-card-body"><Ban /><div><strong>Restricted by your organization</strong><p>Your organization&apos;s sharing policy only allows owners and admins to create external links. Use a shared workspace or request access instead.</p></div></CardContent></Card> :
    <div className="send-layout">
      <Card>
        <CardHeader><CardTitle>New secure link</CardTitle><CardDescription>Nothing you type here is readable by Vlightsoft.</CardDescription></CardHeader>
        <CardContent>
          <form className="form-stack" onSubmit={submit}>
            <div className="chip-row" role="radiogroup" aria-label="Content type">
              <button type="button" role="radio" aria-checked={mode === "text"} className={mode === "text" ? "active" : ""} onClick={() => setMode("text")}>Text</button>
              <button type="button" role="radio" aria-checked={mode === "file"} className={mode === "file" ? "active" : ""} onClick={() => setMode("file")}>File (up to 5 MB)</button>
            </div>
            {mode === "text" ? <div><Label htmlFor="send-text">Secret</Label><textarea id="send-text" className="send-textarea" required maxLength={SEND_MAX_TEXT_CHARS} rows={6} value={text} onChange={(event) => setText(event.target.value)} placeholder="Password, recovery code, note…" autoComplete="off" spellCheck={false} /></div>
              : <label className="file-action"><FileUp /><span>{file ? `${file.name} · ${(file.size / 1024).toFixed(0)} KB` : "Choose a file"}</span><input type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>}
            <div className="inline-fields">
              <div><Label htmlFor="send-views">Views allowed</Label><select id="send-views" value={maxViews} onChange={(event) => setMaxViews(Number(event.target.value))}>{[1, 2, 3, 5, 10, 25].map((value) => <option key={value} value={value}>{value === 1 ? "1 (burn after reading)" : value}</option>)}</select></div>
              <div><Label htmlFor="send-expiry">Expires after</Label><select id="send-expiry" value={expiry} onChange={(event) => setExpiry(Number(event.target.value))}>{EXPIRY_OPTIONS.map((option) => <option key={option.hours} value={option.hours}>{option.label}</option>)}</select></div>
            </div>
            <div><Label htmlFor="send-passphrase-new">Passphrase (optional)</Label><Input id="send-passphrase-new" type="password" autoComplete="new-password" minLength={8} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Share it through a different channel" /></div>
            <label className="check-row"><input type="checkbox" checked={showSender} onChange={(event) => setShowSender(event.target.checked)} /> Show my email to the recipient</label>
            <Button disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <Send />} Create secure link</Button>
          </form>
          {link && <div className="send-result"><Link2 /><code>{link}</code><Button size="sm" onClick={async () => { await navigator.clipboard.writeText(link); setCopied(true); }}>{copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy link"}</Button><small className="field-hint">This link is shown once. Anyone with it can open the content{passphrase ? " (with the passphrase)" : ""}.</small></div>}
          {message && <p className="form-message" role="alert">{message}</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Your links</CardTitle><CardDescription>Revoke a link to delete its encrypted content immediately.</CardDescription></CardHeader>
        <CardContent>
          {sends.length === 0 ? <div className="empty-state"><TimerOff /><p>No secure links yet.</p></div> : <ul className="send-list">{sends.map((send) => {
            const status = sendStatus(send, now);
            return <li key={send.id}><span className={`send-status ${status.toLowerCase()}`}>{status}</span><div><strong>{send.kind === "file" ? "File" : "Text"}{send.requires_passphrase ? " · passphrase" : ""}</strong><small>{send.view_count}/{send.max_views} views · expires {new Date(send.expires_at).toLocaleString()}</small></div>{status === "Active" && <Button variant="ghost" size="sm" onClick={() => void revoke(send)}>Revoke</Button>}</li>;
          })}</ul>}
        </CardContent>
      </Card>
    </div>}
  </div>;
}
