"use client";

import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { TriangleAlert, CircleCheck, Copy, Laptop, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AuthScreen } from "@/components/app/shell/auth-screens";
import { Brand, customerError } from "@/components/app/shell/shared";
import { MfaChallengeScreen } from "@/components/enterprise/mfa";
import { type LinkRequest, parseLinkRequest, parsePendingLink, pendingLinkValue, PENDING_LINK_KEY, PLATFORM_LABELS, returnUrl } from "@/lib/desktop/handoff";
import { isSupabaseConfigured, supabase } from "@/lib/supabase/client";

type Step = "loading" | "invalid" | "signin" | "mfa" | "approve" | "done" | "cancelled";

function readRequest(): LinkRequest | null {
  const fromUrl = parseLinkRequest(window.location.search);
  if (fromUrl) return fromUrl;
  try { return parsePendingLink(window.sessionStorage.getItem(PENDING_LINK_KEY)); } catch { return null; }
}

/**
 * Browser page that approves a sign-in for the Passkey-X desktop app. The person signs in
 * here as usual (security check, passkeys, SSO, two-step verification), sees which app is
 * asking, and chooses Allow. The one-time code goes straight back to the app through its
 * 127.0.0.1 listener; it is only shown (with a warning) if that fails.
 */
export function DesktopLinkApproval() {
  const [request, setRequest] = useState<LinkRequest | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [step, setStep] = useState<Step>("loading");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showCode, setShowCode] = useState(false);

  useEffect(() => {
    const next = readRequest();
    if (!next || !supabase) { setStep("invalid"); return; }
    setRequest(next);
    // Keep the request across an SSO redirect in this tab (it returns to the home page).
    try { window.sessionStorage.setItem(PENDING_LINK_KEY, pendingLinkValue(next)); } catch { /* storage blocked */ }
    if (window.location.search) window.history.replaceState(null, "", window.location.pathname);
    let active = true;
    async function evaluate(current: Session | null) {
      if (!active) return;
      setSession(current);
      if (!current) { setStep("signin"); return; }
      const { data } = await supabase!.auth.mfa.getAuthenticatorAssuranceLevel();
      if (!active) return;
      const next = data?.nextLevel === "aal2" && data.currentLevel !== "aal2" ? "mfa" : "approve";
      // Signed in: nothing left to resume after a redirect.
      if (next === "approve") { try { window.sessionStorage.removeItem(PENDING_LINK_KEY); } catch { /* ignore */ } }
      setStep(next);
    }
    supabase.auth.getSession().then(({ data }) => void evaluate(data.session));
    const { data } = supabase.auth.onAuthStateChange((_event, next) => { void evaluate(next); });
    return () => { active = false; data.subscription.unsubscribe(); };
  }, []);

  function clearPending() { try { window.sessionStorage.removeItem(PENDING_LINK_KEY); } catch { /* ignore */ } }

  async function allow() {
    if (!request || !supabase) return;
    setBusy(true); setMessage("");
    try {
      const { data, error } = await (supabase as unknown as { rpc: (name: string, args: Record<string, unknown>) => Promise<{ data: unknown; error: unknown }> })
        .rpc("create_desktop_handoff", { p_challenge: request.challenge, p_device_name: PLATFORM_LABELS[request.platform] });
      if (error || typeof data !== "string") throw error ?? new Error("no code");
      clearPending();
      setCode(data);
      setStep("done");
      // Straight back to the app on this computer (127.0.0.1); the code is not shown.
      window.location.href = returnUrl(request.port, data, request.state);
    } catch (reason) {
      setMessage(customerError(reason, "The desktop app could not be approved. Start again from the app."));
    } finally { setBusy(false); }
  }

  async function copy() {
    try { await navigator.clipboard.writeText(code); setCopied(true); window.setTimeout(() => setCopied(false), 3_000); } catch { setCopied(false); }
  }

  if (!isSupabaseConfigured || step === "loading") return <main className="center-screen"><div className="loading-ring" aria-label="Loading" /></main>;
  if (step === "signin") return <AuthScreen clientMode="login" />;
  if (step === "mfa") return <MfaChallengeScreen brand={<Brand />} onComplete={() => setStep("approve")} footer={null} />;

  return <main className="center-screen unlock-bg"><Card className="auth-card desktop-link"><CardHeader><Brand />
    <div className="vault-icon">{step === "done" ? <CircleCheck /> : step === "invalid" ? <TriangleAlert /> : <Laptop />}</div>
    <CardTitle>{step === "invalid" ? "This link has expired" : step === "done" ? "You're signed in on the desktop app" : step === "cancelled" ? "Sign-in cancelled" : "Sign in to Passkey-X desktop?"}</CardTitle>
    <CardDescription>{step === "invalid"
      ? "Open the Passkey-X desktop app and choose Sign in with your browser again."
      : step === "done" ? "Return to the Passkey-X app. It finishes signing in on its own."
      : step === "cancelled" ? "Nothing was shared with the desktop app. You can close this tab."
      : <>Signed in here as <strong>{session?.user.email}</strong>. <strong>{request ? PLATFORM_LABELS[request.platform] : "The desktop app"}</strong> on this computer is asking to use this account.</>}</CardDescription>
  </CardHeader><CardContent><div className="form-stack">
    {step === "approve" && <>
      <div className="desktop-link-warning"><ShieldCheck /><span>Only choose Allow if you just clicked <strong>Sign in with your browser</strong> in the Passkey-X app on this computer. Passkey-X will never ask you to approve a sign-in by email, phone or chat.</span></div>
      <Button size="lg" disabled={busy} onClick={() => void allow()}>{busy ? "Approving…" : "Allow"}</Button>
      <Button variant="ghost" disabled={busy} onClick={() => { clearPending(); setStep("cancelled"); }}>Cancel</Button>
      <p className="field-hint">Your vault stays locked. You&apos;ll unlock it in the app with your vault password.</p>
    </>}
    {step === "done" && <>
      {!showCode && <Button variant="ghost" onClick={() => setShowCode(true)}>The app didn&apos;t sign in</Button>}
      {showCode && <>
        <div className="desktop-link-warning"><ShieldCheck /><span>Paste this code only into the Passkey-X app on <strong>this</strong> computer. Anyone who asks you for it — by phone, email, chat or a website — is trying to get into your account.</span></div>
        <div className="recovery-box"><code>{code}</code></div>
        <Button variant="outline" onClick={() => void copy()}><Copy /> {copied ? "Copied" : "Copy code"}</Button>
        <p className="field-hint">It works once, for two minutes.</p>
      </>}
      <p className="field-hint">You can close this tab.</p>
    </>}
    {message && <p className="form-message" role="alert">{message}</p>}
  </div></CardContent></Card></main>;
}
