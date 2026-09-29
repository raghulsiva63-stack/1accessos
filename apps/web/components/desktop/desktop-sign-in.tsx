"use client";

import { useEffect, useRef, useState } from "react";
import { ExternalLink, Globe, Laptop, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Brand } from "@/components/app/shell/shared";
import { challengeFor, parsePastedCode, randomToken, signInUrl, STATE_PATTERN, CODE_PATTERN } from "@/lib/desktop/handoff";
import { desktop, WEB_ORIGIN } from "@/lib/desktop/bridge";
import { functionErrorCode } from "@/lib/supabase/function-error";
import { supabase } from "@/lib/supabase/client";

type Pending = { verifier: string; state: string };

/**
 * Desktop sign-in. The app never asks for the account password: the person signs in in their
 * browser (security check, passkeys, SSO), approves this computer, and the browser hands a
 * one-time code back. The secret that makes the code usable never leaves this app.
 */
export function DesktopSignIn() {
  const pending = useRef<Pending | null>(null);
  const [waiting, setWaiting] = useState(false);
  const [pasted, setPasted] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function finish(code: string) {
    const current = pending.current;
    if (!current || !supabase) { setMessage("Start again: choose Sign in with your browser."); return; }
    pending.current = null;
    setBusy(true); setMessage("");
    try {
      const { data, error } = await supabase.functions.invoke<{ tokenHash?: string }>("desktop-session", { body: { code, verifier: current.verifier } });
      if (error || !data?.tokenHash) throw error ?? new Error("no_token");
      const { error: otpError } = await supabase.auth.verifyOtp({ token_hash: data.tokenHash, type: "magiclink" });
      if (otpError) throw otpError;
      // The root page takes over (two-step verification, then vault unlock).
    } catch (reason) {
      const code = await functionErrorCode(reason);
      setMessage(code === "invalid_or_expired_code"
        ? "That code has expired or was already used. Choose Sign in with your browser to get a new one."
        : "Sign-in could not be completed. Check your internet connection and try again.");
      setWaiting(false);
    } finally { setBusy(false); }
  }

  useEffect(() => {
    function handoff(event: Event) {
      const detail = (event as CustomEvent<{ code?: string; state?: string }>).detail;
      const current = pending.current;
      if (!current || !detail || detail.state !== current.state || !CODE_PATTERN.test(detail.code ?? "")) return;
      void finish(detail.code!);
    }
    window.addEventListener("passkey-x:handoff", handoff);
    return () => window.removeEventListener("passkey-x:handoff", handoff);
  }, []);

  async function start() {
    setMessage(""); setPasted("");
    const verifier = randomToken(48);
    const state = randomToken(24);
    if (!STATE_PATTERN.test(state)) return;
    pending.current = { verifier, state };
    let port: number; let platform: "macos" | "windows" | "linux";
    try {
      const info = await desktop.info();
      platform = info.os;
      // One-shot listener on 127.0.0.1: the browser returns the code straight to this app.
      port = await desktop.listenForSignIn(state);
    } catch { setMessage("Sign-in could not start. Restart Passkey-X and try again."); return; }
    const url = signInUrl(WEB_ORIGIN, { challenge: await challengeFor(verifier), state, port, platform });
    // The app opens passkey-x.com links in the default browser.
    window.open(url, "_blank", "noopener");
    setWaiting(true);
  }

  function submitCode(event: React.FormEvent) {
    event.preventDefault();
    const current = pending.current;
    const code = current ? parsePastedCode(pasted) : null;
    if (!code) { setMessage("That does not look like a Passkey-X sign-in code. Copy it again from your browser."); return; }
    void finish(code);
  }

  return <main className="center-screen unlock-bg"><Card className="auth-card desktop-signin"><CardHeader><Brand />
    <div className="vault-icon"><Laptop /></div>
    <CardTitle>{waiting ? "Finish in your browser" : "Sign in to Passkey-X"}</CardTitle>
    <CardDescription>{waiting
      ? "Sign in on the page that opened, then choose Allow. You'll come straight back here."
      : "You sign in with your browser, where your passkeys, company sign-in and security checks already work. Your vault password is only ever typed into this app."}</CardDescription>
  </CardHeader><CardContent><div className="form-stack">
    {!waiting && <Button size="lg" disabled={busy} onClick={() => void start()}><Globe /> Sign in with your browser</Button>}
    {waiting && <>
      <form className="form-stack" onSubmit={submitCode}>
        <div><Label htmlFor="desktop-code">Didn&apos;t come back automatically? Paste the code shown in your browser</Label>
          <Input id="desktop-code" autoComplete="off" spellCheck={false} value={pasted} onChange={(event) => setPasted(event.target.value)} placeholder="Sign-in code" /></div>
        <Button disabled={busy || !pasted.trim()}>{busy ? "Signing in…" : "Continue"}</Button>
      </form>
      <Button variant="ghost" disabled={busy} onClick={() => void start()}><ExternalLink /> Open the browser page again</Button>
    </>}
    {message && <p className="form-message" role="alert">{message}</p>}
    <Button variant="ghost" onClick={() => window.open(`${WEB_ORIGIN}/login`, "_blank", "noopener")}>New to Passkey-X? Create an account</Button>
    <div className="privacy-note"><ShieldCheck /><span>The sign-in code works once, for two minutes, and only in the app that asked for it. Never share it with anyone.</span></div>
  </div></CardContent></Card></main>;
}

/** Shown when the account has no vault yet: vault setup needs the browser's security check. */
export function DesktopFinishSetup({ email }: { email: string }) {
  return <main className="center-screen setup-bg"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Create your vault first</CardTitle>
    <CardDescription>{email} is signed in, but its encrypted vault hasn&apos;t been created yet. Finish setup on passkey-x.com (it takes two minutes and gives you your recovery key), then come back.</CardDescription>
  </CardHeader><CardContent><div className="form-stack">
    <Button size="lg" onClick={() => window.open(`${WEB_ORIGIN}/login`, "_blank", "noopener")}><Globe /> Finish setup in your browser</Button>
    <Button variant="outline" onClick={() => window.location.reload()}>I&apos;ve finished — reload</Button>
    <Button variant="ghost" onClick={() => void supabase?.auth.signOut()}>Use another account</Button>
  </div></CardContent></Card></main>;
}
