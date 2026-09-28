"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TurnstileCheck } from "@/components/turnstile-check";
import { captchaOptions, captchaReady } from "@/lib/auth/captcha";
import { captchaEnabled, supabase } from "@/lib/supabase/client";
import { functionErrorCode } from "@/lib/supabase/function-error";

type Preflight = {
  can_delete?: boolean;
  blocking_tenant_ids?: string[];
  personal_tenant_count?: number;
};

export function AccountDeletionCard({ email }: { email: string }) {
  const router = useRouter();
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [totpFactorId, setTotpFactorId] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  async function runPreflight() {
    if (!supabase) return;
    const { data, error } = await supabase.functions.invoke("account-lifecycle", { body: { action: "preflight" } });
    if (error) throw new Error(await functionErrorCode(error));
    if (data?.error) throw new Error(String(data.error));
    setPreflight(data.preflight as Preflight);
    const factors = await supabase.auth.mfa.listFactors();
    setTotpFactorId(factors.data?.totp?.find((factor) => factor.status === "verified")?.id ?? null);
  }

  useEffect(() => {
    if (!expanded || preflight) return;
    const timer = window.setTimeout(() => { void runPreflight().catch(() => setMessage("Deletion readiness could not be checked. Try again.")); }, 0);
    return () => window.clearTimeout(timer);
  }, [expanded, preflight]);

  async function deleteAccount(event: React.FormEvent) {
    event.preventDefault();
    if (!supabase || confirmation !== "DELETE MY ACCOUNT") return;
    if (!captchaReady(captchaEnabled, captchaToken)) { setMessage("Complete the security check before continuing."); return; }
    setBusy(true); setMessage("");
    try {
      const { error: authError } = await supabase.auth.signInWithPassword({ email, password, options: captchaOptions(captchaToken) });
      setPassword("");
      setCaptchaToken(null);
      setCaptchaReset((current) => current + 1);
      if (authError) throw authError;
      // Signing in again drops the session to aal1; accounts with two-step verification must confirm a code.
      if (totpFactorId) {
        const code = mfaCode.replace(/\s+/gu, "");
        setMfaCode("");
        const { error: mfaError } = await supabase.auth.mfa.challengeAndVerify({ factorId: totpFactorId, code });
        if (mfaError) throw new Error("mfa_code_invalid");
      }
      const { data, error } = await supabase.functions.invoke("account-lifecycle", { body: { action: "delete", confirmation } });
      if (error) throw new Error(await functionErrorCode(error, "deletion_failed"));
      if (data?.error || data?.deleted !== true) throw new Error(String(data?.error ?? "deletion_failed"));
      await supabase.auth.signOut({ scope: "local" });
      router.replace("/");
      router.refresh();
    } catch (reason) {
      const text = reason instanceof Error ? reason.message : String(reason ?? "");
      if (/ownership_transfer/iu.test(text)) setMessage("Transfer ownership of each shared tenant that has no other owner, then retry.");
      else if (/mfa_code_invalid/iu.test(text)) setMessage("That authenticator code is incorrect or expired.");
      else if (/mfa_required/iu.test(text)) setMessage("Enter the code from your authenticator app to confirm.");
      else if (/recent_reauthentication/iu.test(text)) setMessage("Your sign-in check expired. Enter your password again.");
      else if (/invalid login|credential|password/iu.test(text)) setMessage("Your login password is incorrect.");
      else setMessage("The account could not be deleted. No successful deletion was reported; contact support before retrying if this persists.");
    } finally { setBusy(false); }
  }

  return <Card className="danger-card"><CardHeader><CardTitle><Trash2 /> Delete account</CardTitle><CardDescription>Permanently remove your Auth account, personal tenant data, encrypted attachments, devices, keys, and memberships. Shared audit attribution remains as a revoked identity tombstone.</CardDescription></CardHeader><CardContent>
    {!expanded ? <Button variant="outline" onClick={() => setExpanded(true)}><Trash2 /> Review account deletion</Button> : <>
      {preflight && !preflight.can_delete && <div className="deletion-blocker"><ShieldAlert /><div><strong>Ownership transfer required</strong><p>You are the only owner of {preflight.blocking_tenant_ids?.length ?? 0} shared tenant(s) with active members. Assign another owner before deletion.</p></div></div>}
      {preflight?.can_delete && <form className="form-stack" onSubmit={deleteAccount}>
        <div className="deletion-warning"><ShieldAlert /><p>This cannot be undone. Download any encrypted backup and confirm that your recovery material is no longer needed.</p></div>
        <div><Label htmlFor="delete-password">Login password</Label><Input id="delete-password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
        {totpFactorId && <div><Label htmlFor="delete-mfa">Authenticator code</Label><Input id="delete-mfa" inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9 ]{6,8}" value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} /></div>}
        <div><Label htmlFor="delete-confirmation">Type DELETE MY ACCOUNT</Label><Input id="delete-confirmation" autoComplete="off" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div>
        <TurnstileCheck action="account-delete" resetKey={captchaReset} onToken={setCaptchaToken} onProblem={() => setMessage("The security check could not load. Refresh and try again.")} />
        <Button className="destructive-button" disabled={busy || confirmation !== "DELETE MY ACCOUNT" || !captchaReady(captchaEnabled, captchaToken)}>{busy ? "Deleting account…" : "Permanently delete account"}</Button>
      </form>}
      {!preflight && !message && <p className="field-hint">Checking tenant ownership and deletion readiness…</p>}
      {message && <p className="settings-message" role="status">{message}</p>}
      <Button variant="ghost" disabled={busy} onClick={() => { setExpanded(false); setPassword(""); setConfirmation(""); setMessage(""); }}>Cancel</Button>
    </>}
  </CardContent></Card>;
}
