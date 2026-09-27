"use client";

import { useEffect, useState, type ReactNode } from "react";
import type { Factor } from "@supabase/supabase-js";
import { KeyRound, LoaderCircle, QrCode, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { supabase } from "@/lib/supabase/client";

type AnyFactor = Factor & { factor_type: string; friendly_name?: string | null };

function mfaError(reason: unknown, fallback: string) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message).toLowerCase() : "";
  if (detail.includes("invalid") || detail.includes("expired")) return "That code is invalid or expired. Try the current code.";
  if (detail.includes("rate") || detail.includes("too many")) return "Too many attempts. Wait a minute and try again.";
  return fallback;
}

/** Sign-in step-up that supports authenticator apps (TOTP) and verified phones. */
export function MfaChallengeScreen({ brand, footer, onComplete }: { brand: ReactNode; footer?: ReactNode; onComplete: () => void }) {
  const [factors, setFactors] = useState<AnyFactor[]>([]);
  const [factorId, setFactorId] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const factor = factors.find((entry) => entry.id === factorId);
  const isPhone = factor?.factor_type === "phone";

  useEffect(() => {
    let active = true;
    supabase!.auth.mfa.listFactors().then(({ data, error }) => {
      if (!active) return;
      if (error) setMessage(mfaError(error, "Your verification methods could not be loaded."));
      else {
        const verified = [...data.totp, ...data.phone].filter((entry) => entry.status === "verified") as AnyFactor[];
        setFactors(verified);
        setFactorId(verified.find((entry) => entry.factor_type === "totp")?.id ?? verified[0]?.id ?? "");
      }
      setLoading(false);
    });
    return () => { active = false; };
  }, []);

  async function sendCode() {
    if (!factorId) return;
    setBusy(true); setMessage(""); setCode("");
    try {
      const { data, error } = await supabase!.auth.mfa.challenge(isPhone ? { factorId, channel: "sms" } : { factorId });
      if (error) throw error;
      setChallengeId(data.id);
      if (isPhone) setMessage("A one-time security code was sent to your verified mobile number.");
    } catch (reason) { setMessage(mfaError(reason, "The security challenge could not start. Try again shortly.")); }
    finally { setBusy(false); }
  }

  async function verify(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      let activeChallenge = challengeId;
      if (!activeChallenge) {
        if (isPhone) { setMessage("Send a security code first."); return; }
        const { data, error } = await supabase!.auth.mfa.challenge({ factorId });
        if (error) throw error;
        activeChallenge = data.id;
      }
      const { error } = await supabase!.auth.mfa.verify({ factorId, challengeId: activeChallenge, code: code.trim() });
      if (error) throw error;
      onComplete();
    } catch (reason) { setChallengeId(""); setMessage(mfaError(reason, "That security code could not be verified.")); }
    finally { setBusy(false); }
  }

  return <main className="center-screen setup-bg"><Card className="auth-card"><CardHeader>{brand}<div className="step-pill"><ShieldCheck /> Two-step verification</div><CardTitle>Verify it’s you</CardTitle><CardDescription>{isPhone ? "Enter the code sent to your verified mobile number." : "Enter the 6-digit code from your authenticator app."} Your vault password is still required afterwards.</CardDescription></CardHeader><CardContent>
    {loading ? <div className="loading-ring" aria-label="Loading verification methods" /> : factors.length === 0 ? <p className="form-message">No verified second factor is available. Contact your administrator.</p> : <form className="form-stack" onSubmit={verify}>
      {factors.length > 1 && <div><Label htmlFor="mfa-factor">Method</Label><select id="mfa-factor" value={factorId} onChange={(event) => { setFactorId(event.target.value); setChallengeId(""); setCode(""); }}>{factors.map((entry) => <option key={entry.id} value={entry.id}>{entry.factor_type === "totp" ? "Authenticator app" : "Text message"}{entry.friendly_name ? ` · ${entry.friendly_name}` : ""}</option>)}</select></div>}
      {isPhone && <Button type="button" variant="outline" onClick={() => void sendCode()} disabled={busy}><Smartphone /> {challengeId ? "Send a new code" : "Send code"}</Button>}
      <div><Label htmlFor="mfa-code">Security code</Label><Input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" autoFocus minLength={6} maxLength={10} pattern="[0-9]{6,10}" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/gu, ""))} /></div>
      <Button disabled={busy || code.length < 6}>{busy ? <LoaderCircle className="spin" /> : <KeyRound />} Verify</Button>
    </form>}
    {message && <p className="form-message" role="status">{message}</p>}
    {footer}
  </CardContent></Card></main>;
}

/** Authenticator-app (TOTP) enrollment and management. */
export function TotpCard() {
  const { refreshCompliance, policy } = useEnterprise();
  const [factors, setFactors] = useState<AnyFactor[]>([]);
  const [enrollment, setEnrollment] = useState<{ id: string; qr: string; secret: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    supabase?.auth.mfa.listFactors().then(({ data }) => {
      if (active && data) setFactors(data.totp.filter((entry) => entry.status === "verified") as AnyFactor[]);
    });
    return () => { active = false; };
  }, [version]);

  async function start() {
    setBusy(true); setMessage("");
    try {
      const { data, error } = await supabase!.auth.mfa.enroll({ factorType: "totp", friendlyName: `Authenticator ${new Date().toISOString().slice(0, 10)} · ${crypto.randomUUID().slice(0, 4)}` });
      if (error) throw error;
      setEnrollment({ id: data.id, qr: data.totp.qr_code, secret: data.totp.secret });
    } catch (reason) { setMessage(mfaError(reason, "Authenticator setup could not start. Your organization may need to enable it.")); }
    finally { setBusy(false); }
  }

  async function verify(event: React.FormEvent) {
    event.preventDefault();
    if (!enrollment) return;
    setBusy(true); setMessage("");
    try {
      const { error } = await supabase!.auth.mfa.challengeAndVerify({ factorId: enrollment.id, code: code.trim() });
      if (error) throw error;
      setEnrollment(null); setCode(""); setMessage("Authenticator app added. You'll be asked for a code when you sign in.");
      setVersion((value) => value + 1); refreshCompliance();
    } catch (reason) { setMessage(mfaError(reason, "That code could not be verified.")); }
    finally { setBusy(false); }
  }

  async function cancel() {
    if (enrollment) await supabase!.auth.mfa.unenroll({ factorId: enrollment.id }).catch(() => undefined);
    setEnrollment(null); setCode("");
  }

  async function remove(factor: AnyFactor) {
    if (policy.mfaRequired && factors.length <= 1 && !window.confirm("Your organization requires two-step verification. Removing your only authenticator will make your account non-compliant. Continue?")) return;
    if (!window.confirm("Remove this authenticator app?")) return;
    setBusy(true); setMessage("");
    try {
      const { error } = await supabase!.auth.mfa.unenroll({ factorId: factor.id });
      if (error) throw error;
      setVersion((value) => value + 1); refreshCompliance();
    } catch (reason) { setMessage(mfaError(reason, "Remove requires a recent two-step sign-in. Sign in again and retry.")); }
    finally { setBusy(false); }
  }

  return <Card>
    <CardHeader><CardTitle>Authenticator app</CardTitle><CardDescription>Use Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app as a second sign-in factor.{policy.mfaRequired ? " Required by your organization." : ""}</CardDescription></CardHeader>
    <CardContent>
      {factors.length > 0 && <ul className="factor-list">{factors.map((factor) => <li key={factor.id}><ShieldCheck /><span><strong>{factor.friendly_name ?? "Authenticator app"}</strong><small>Added {new Date(factor.created_at).toLocaleDateString()}</small></span><Button variant="ghost" size="icon-sm" aria-label="Remove authenticator" onClick={() => void remove(factor)} disabled={busy}><Trash2 /></Button></li>)}</ul>}
      {!enrollment ? <Button variant={factors.length ? "outline" : "default"} onClick={() => void start()} disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <QrCode />} {factors.length ? "Add another authenticator" : "Set up authenticator app"}</Button> :
        <form className="totp-enroll" onSubmit={verify}>
          {/* eslint-disable-next-line @next/next/no-img-element -- Supabase returns a data: SVG QR code */}
          <img src={enrollment.qr} alt="Scan this QR code with your authenticator app" width={180} height={180} />
          <div className="form-stack">
            <p className="field-hint">Scan the code, or enter this setup key manually:</p>
            <code className="totp-secret">{enrollment.secret.match(/.{1,4}/gu)?.join(" ")}</code>
            <div><Label htmlFor="totp-code">6-digit code</Label><Input id="totp-code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} pattern="[0-9]{6}" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/gu, ""))} /></div>
            <div className="inline-actions"><Button disabled={busy || code.length !== 6}>{busy ? <LoaderCircle className="spin" /> : <ShieldCheck />} Verify &amp; turn on</Button><Button type="button" variant="ghost" onClick={() => void cancel()} disabled={busy}>Cancel</Button></div>
          </div>
        </form>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}
