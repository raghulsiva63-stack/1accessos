"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { Download, Eye, FileText, KeyRound, LoaderCircle, LockKeyhole, ShieldCheck, TimerOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { downloadBlob } from "@/lib/browser/download";
import {
  openSecureSend, parseSendLink, payloadToBlob, peekSecureSend,
  type SendLink, type SendPayload, type SendPreview,
} from "@/lib/enterprise/send";

type State =
  | { stage: "loading" }
  | { stage: "invalid"; reason: string }
  | { stage: "ready"; link: SendLink; preview: SendPreview }
  | { stage: "opened"; payload: SendPayload; viewsLeft: number };

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function SecureSendPage() {
  const [state, setState] = useState<State>({ stage: "loading" });
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [shown, setShown] = useState(false);

  useEffect(() => {
    let active = true;
    const link = parseSendLink(window.location.hash);
    // Keep the key out of history, referrers and screenshots of the address bar.
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
    if (!link) { void Promise.resolve().then(() => { if (active) setState({ stage: "invalid", reason: "This link is incomplete. Ask the sender to share it again." }); }); return () => { active = false; }; }
    peekSecureSend(link.id).then((preview) => {
      if (!active) return;
      if (!preview || !preview.available) setState({ stage: "invalid", reason: "This link has expired, was revoked, or has already been viewed." });
      else setState({ stage: "ready", link, preview });
    }, () => { if (active) setState({ stage: "invalid", reason: "This link could not be checked. Try again shortly." }); });
    return () => { active = false; };
  }, []);

  async function reveal(event: React.FormEvent) {
    event.preventDefault();
    if (state.stage !== "ready") return;
    setBusy(true); setMessage("");
    try {
      const result = await openSecureSend(state.link, state.preview, passphrase);
      state.link.key.fill(0);
      setPassphrase("");
      setState({ stage: "opened", payload: result.payload, viewsLeft: result.viewsLeft });
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "This link could not be opened.");
    } finally { setBusy(false); }
  }

  return <main className="center-screen setup-bg send-page">
    <Card className="auth-card send-card">
      <CardHeader>
        <div className="brand"><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={230} height={52} priority /></div>
        <div className="step-pill"><LockKeyhole /> Secure Send</div>
        <CardTitle>{state.stage === "opened" ? "Here’s what was shared with you" : "Someone sent you something private"}</CardTitle>
        <CardDescription>End-to-end encrypted. The key is only in your link — Passkey-X cannot read this content.</CardDescription>
      </CardHeader>
      <CardContent>
        {state.stage === "loading" && <div className="loading-ring" aria-label="Checking link" />}
        {state.stage === "invalid" && <div className="send-empty"><TimerOff /><p>{state.reason}</p></div>}
        {state.stage === "ready" && <form className="form-stack" onSubmit={reveal}>
          <ul className="send-facts">
            <li>{state.preview.kind === "file" ? <FileText /> : <KeyRound />} {state.preview.kind === "file" ? `Encrypted file · ${formatBytes(state.preview.byte_size)}` : "Encrypted text"}</li>
            <li><Eye /> {state.preview.views_left} view{state.preview.views_left === 1 ? "" : "s"} remaining</li>
            <li><TimerOff /> Expires {new Date(state.preview.expires_at).toLocaleString()}</li>
            {state.preview.sender && <li><ShieldCheck /> From {state.preview.sender}</li>}
          </ul>
          {state.preview.requires_passphrase && <div><Label htmlFor="send-passphrase">Passphrase</Label><Input id="send-passphrase" type="password" autoComplete="off" required value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /><small className="field-hint">The sender should give you this separately.</small></div>}
          <Button size="lg" disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <Eye />} {state.preview.views_left === 1 ? "Reveal (this link will then stop working)" : "Reveal"}</Button>
        </form>}
        {state.stage === "opened" && (state.payload.kind === "text" ? <div className="form-stack">
          <div className="send-secret">{shown ? <pre>{state.payload.text}</pre> : <button type="button" onClick={() => setShown(true)}>Click to show</button>}</div>
          <div className="inline-actions"><Button variant="outline" onClick={async () => { if (state.stage === "opened" && state.payload.kind === "text") { await navigator.clipboard.writeText(state.payload.text); setMessage("Copied. Clear your clipboard when you're done."); } }}>Copy</Button></div>
          <p className="field-hint">{state.viewsLeft > 0 ? `${state.viewsLeft} view${state.viewsLeft === 1 ? "" : "s"} left on this link.` : "This link is now burned — it cannot be opened again."} Save anything you need now.</p>
        </div> : <div className="form-stack">
          <p><strong>{state.payload.name}</strong></p>
          <Button onClick={() => { if (state.stage === "opened" && state.payload.kind === "file") downloadBlob(payloadToBlob(state.payload), state.payload.name.replace(/[\\/\0]/gu, "_") || "download"); }}><Download /> Download file</Button>
          <p className="field-hint">{state.viewsLeft > 0 ? `${state.viewsLeft} download${state.viewsLeft === 1 ? "" : "s"} left.` : "This link is now burned."}</p>
        </div>)}
        {message && <p className="form-message neutral-message" role="status">{message}</p>}
        <div className="privacy-note"><ShieldCheck /><span>Shared with Passkey-X Secure Send by Vlightsoft. Content is decrypted only in this browser.</span></div>
      </CardContent>
    </Card>
  </main>;
}
