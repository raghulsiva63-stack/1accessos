"use client";

import { useState } from "react";
import { Building2, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { signInWithSso, ssoStatusForEmail } from "@/lib/enterprise/identity";

/** "Sign in with SSO" for organizations that connected a SAML identity provider. */
export function SsoSignIn() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const status = await ssoStatusForEmail(email.trim());
      if (!status.available) { setMessage("Single sign-on isn’t set up for this email domain. Sign in with your password or passkey."); return; }
      await signInWithSso(email.trim());
    } catch { setMessage("Single sign-on could not start. Try again or contact your IT team."); }
    finally { setBusy(false); }
  }

  if (!open) return <div className="sso-entry"><Button type="button" variant="outline" onClick={() => setOpen(true)}><Building2 /> Sign in with SSO</Button></div>;
  return <form className="form-stack sso-entry" onSubmit={submit}>
    <div><Label htmlFor="sso-email">Work email</Label><Input id="sso-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" /></div>
    <Button disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <Building2 />} Continue with SSO</Button>
    <small className="field-hint">SSO signs you in to your account. Your vault password is still needed to decrypt your vault.</small>
    {message && <p className="form-message" role="status">{message}</p>}
  </form>;
}
