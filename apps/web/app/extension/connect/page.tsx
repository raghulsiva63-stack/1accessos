"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { TurnstileCheck } from "@/components/turnstile-check";
import { captchaEnabled, passkeysEnabled } from "@/lib/supabase/client";

// The UAT (unpacked) build has a fixed ID. Store builds get their IDs from the Chrome Web Store and
// Edge Add-ons; list them in NEXT_PUBLIC_EXTENSION_IDS (comma-separated) so pairing accepts them.
const UAT_EXTENSION_ID = "egkaneajfcaomheahcmopioiemmplebg";
const EXTENSION_IDS = new Set([UAT_EXTENSION_ID, ...(process.env.NEXT_PUBLIC_EXTENSION_IDS ?? "").split(",").map((value) => value.trim())]
  .filter((value) => /^[a-p]{32}$/u.test(value)));
type Runtime = { lastError?: { message?: string }; sendMessage: (id: string, message: unknown, callback: (response?: { ok?: boolean; error?: string }) => void) => void };
function runtime() { return (window as Window & { chrome?: { runtime?: Runtime } }).chrome?.runtime; }
type Factor = { id: string; label: string; type: "phone" | "totp" };

export default function ExtensionConnectPage() {
  const router = useRouter();
  const client = useRef<SupabaseClient | null>(null);
  const nonce = useRef("");
  const extensionId = useRef("");
  const [valid, setValid] = useState(false);
  const [stage, setStage] = useState<"signin" | "mfa" | "approve" | "done">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const [status, setStatus] = useState("Checking the extension connection…");
  const [busy, setBusy] = useState(false);
  const [factors, setFactors] = useState<Factor[]>([]);
  const [factorId, setFactorId] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [code, setCode] = useState("");

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("extension_id");
    // The fragment is a one-use pairing nonce, never an account bearer token.
    nonce.current ||= window.location.hash.slice(1);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
    const accepted = id !== null && EXTENSION_IDS.has(id) && /^[a-f0-9]{64}$/u.test(nonce.current) && window.location.origin === "https://passkey-x.com";
    if (accepted) extensionId.current = id;
    if (accepted && url && key) {
      // A fresh memory-only login belongs exclusively to the extension. The web
      // vault's session is never shared, persisted, or refreshed by this client.
      client.current ??= createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false, storageKey: "passkey-x-extension-handoff", experimental: { passkey: passkeysEnabled } } });
    }
    // Synchronize the browser-only URL/configuration once after hydration.
    setValid(Boolean(accepted && client.current));
    setStatus(accepted && client.current ? "Sign in to connect this browser. This request expires after five minutes." : "Start a new connection from the installed Passkey-X extension.");
  }, []);

  async function finishSignIn() {
    const auth = client.current!.auth;
    const { data, error } = await auth.mfa.getAuthenticatorAssuranceLevel();
    if (error) throw error;
    if (data.nextLevel === "aal2" && data.currentLevel !== "aal2") {
      const result = await auth.mfa.listFactors();
      if (result.error) throw result.error;
      const available: Factor[] = result.data.all.filter(f => f.status === "verified" && (f.factor_type === "phone" || f.factor_type === "totp"))
        .map(f => ({ id: f.id, label: f.friendly_name || (f.factor_type === "phone" ? "Mobile verification" : "Authenticator app"), type: f.factor_type as "phone" | "totp" }));
      if (!available.length) throw new Error("Your account needs a verification method that is not supported here. Use account settings to review your factors.");
      setFactors(available); setFactorId(available[0].id); setStage("mfa"); setStatus("Complete your account's second verification step.");
    } else {
      const session = await auth.getSession();
      setEmail(session.data.session?.user.email ?? email);
      setStage("approve"); setStatus("Signed in. Review the access below before approving.");
    }
  }

  async function signIn(event?: FormEvent, passkey = false) {
    event?.preventDefault();
    if (!valid || !client.current) return;
    if (captchaEnabled && !captchaToken) { setStatus("Complete the security check first."); return; }
    setBusy(true); setStatus("Signing in securely…");
    try {
      const options = captchaToken ? { captchaToken } : undefined;
      const result = passkey ? await client.current.auth.signInWithPasskey({ options }) : await client.current.auth.signInWithPassword({ email, password, options });
      if (result.error) throw result.error;
      await finishSignIn();
    } catch (error) { setStatus(error instanceof Error ? error.message : "Sign-in failed. Try again."); }
    finally { setPassword(""); setCaptchaToken(null); setResetKey(value => value + 1); setBusy(false); }
  }

  async function challenge() {
    if (!client.current) return;
    setBusy(true);
    try {
      const result = await client.current.auth.mfa.challenge({ factorId });
      if (result.error) throw result.error;
      setChallengeId(result.data.id); setStatus("Enter your verification code.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Unable to start verification."); }
    finally { setBusy(false); }
  }

  async function verify(event: FormEvent) {
    event.preventDefault(); if (!client.current) return;
    setBusy(true);
    try {
      const result = await client.current.auth.mfa.verify({ factorId, challengeId, code });
      if (result.error) throw result.error;
      await finishSignIn();
    } catch (error) { setStatus(error instanceof Error ? error.message : "Verification failed."); }
    finally { setCode(""); setBusy(false); }
  }

  async function connect() {
    const bridge = runtime();
    if (!valid || !client.current || !bridge || !extensionId.current) { setStatus("The extension is unavailable. Enable it and start a new connection."); return; }
    setBusy(true); setStatus("Connecting this browser…");
    try {
      const { data, error } = await client.current.auth.getSession();
      if (error || !data.session) throw new Error("Your sign-in expired. Start a new connection.");
      await new Promise<void>((resolve, reject) => {
        const timer = window.setTimeout(() => reject(new Error("Connection timed out. Check the extension before starting again.")), 20000);
        bridge.sendMessage(extensionId.current, { type: "PX_PAIR_SESSION", extensionId: extensionId.current, nonce: nonce.current, accessToken: data.session!.access_token, refreshToken: data.session!.refresh_token }, response => {
          window.clearTimeout(timer);
          const error = bridge.lastError;
          if (error || !response?.ok) reject(new Error(response?.error || error?.message || "Connection was not accepted."));
          else resolve();
        });
      });
      // Drop all page references without signing out the session just transferred.
      client.current = null; nonce.current = ""; setStage("done");
      setStatus("Connected. Close this tab, open Passkey-X from the toolbar, and unlock your vault.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Connection failed."); }
    finally { setBusy(false); }
  }

  async function cancel() {
    setBusy(true);
    try { await client.current?.auth.signOut({ scope: "local" }); }
    finally { client.current = null; router.push("/"); }
  }

  return <main className="extension-connect-shell"><section className="extension-connect-card">
    <Image src="/brand/passkey-x-horizontal.png" width={380} height={96} alt="Passkey-X by Vlightsoft" priority />
    <p className="kicker">Chrome &amp; Edge extension</p><h1>Connect your private vault</h1>
    <p>Approve this browser to save and fill logins. You will unlock the vault separately in the extension.</p>
    {valid && stage === "signin" && <form onSubmit={signIn}>
      <label>Email<input type="email" autoComplete="username" value={email} onChange={event => setEmail(event.target.value)} required disabled={busy} /></label>
      <label>Login password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required disabled={busy} /></label>
      <TurnstileCheck action="auth-signin" resetKey={resetKey} onProblem={() => setStatus("The security check could not load. Try again.")} onToken={setCaptchaToken} />
      <button disabled={busy}>Sign in</button>
      {passkeysEnabled && <button type="button" disabled={busy} onClick={() => void signIn(undefined, true)}>Sign in with a passkey</button>}
      <Link href="/#access">Create an account or reset your login password</Link>
    </form>}
    {stage === "mfa" && <form onSubmit={verify}>
      <label>Verification method<select value={factorId} disabled={busy} onChange={event => { setFactorId(event.target.value); setChallengeId(""); }}>{factors.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}</select></label>
      {!challengeId ? <button type="button" disabled={busy} onClick={() => void challenge()}>{factors.find(f => f.id === factorId)?.type === "phone" ? "Send verification code" : "Use authenticator code"}</button> : <><label>Verification code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6,10}" required value={code} onChange={event => setCode(event.target.value.replace(/\D/gu, ""))} /></label><button disabled={busy}>Verify</button></>}
    </form>}
    {stage === "approve" && <><p><strong>{email}</strong></p><ul><li>Read and save encrypted logins in your authorized workspaces.</li><li>Fill only when you click Fill or use the keyboard shortcut.</li><li>Lock after five minutes of inactivity; reconnect after a browser restart.</li></ul><button onClick={() => void connect()} disabled={busy}>Approve this extension</button></>}
    <p className="extension-connect-status" role="status" aria-live="polite">{status}</p>
    {stage !== "done" && valid ? <button type="button" onClick={() => void cancel()} disabled={busy}>Cancel connection</button> : <Link href="/">Return to Passkey-X</Link>}
  </section></main>;
}
