"use client";

import { useEffect, useRef, useState } from "react";
import { vaultPasswordFacts, type VaultPasswordFacts } from "@/components/enterprise/compliance-banner";
import { copySecret } from "@/components/enterprise/vault-guards";
import { Copy, Download, Fingerprint, KeyRound, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ClientAuthFrame } from "@/components/client-experience";
import type { ClientMode } from "@/lib/browser/client-mode";
import { TurnstileCheck } from "@/components/turnstile-check";
import {
  createDeviceKeyPair, createRecoveryKey, deriveMasterKey, fromBase64Url, parseRecoveryKey,
  randomBytes, recoveryFile, recoveryVerifier, saveProtectedDeviceKey, toBase64Url, toPostgresBytea,
  unwrapKey, WEB_KDF_PROFILE, wrapKey,
} from "@/lib/crypto/vault";
import { captchaEnabled, passkeysEnabled, supabase } from "@/lib/supabase/client";
import { captchaOptions, captchaReady } from "@/lib/auth/captcha";
import { downloadBlob } from "@/lib/browser/download";
import { estimateStrength } from "@/lib/enterprise/health";
import { OrgRecoveryUnlock } from "@/components/app/org-membership";
import { SsoSignIn } from "@/components/app/sso-sign-in";
import { type CryptoProfile, Brand, bytea, customerError } from "@/components/app/shell/shared";

export function ConfigurationNotice() {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Passkey-X is temporarily unavailable</CardTitle><CardDescription>The secure account service could not start. Please try again later or contact Passkey-X support.</CardDescription></CardHeader></Card></main>;
}

export function FatalNotice({ message }: { message: string }) {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Passkey-X could not open</CardTitle><CardDescription>{message}</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => supabase?.auth.signOut()}>Sign out</Button></CardContent></Card></main>;
}

export function AuthScreen({ clientMode }: { clientMode: ClientMode }) {
  const [mode, setMode] = useState<"signin" | "signup" | "forgot">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [resetSent, setResetSent] = useState(false);

  function requireCaptcha() {
    if (captchaReady(captchaEnabled, captchaToken)) return true;
    setMessage("Complete the security check before continuing.");
    return false;
  }

  function resetCaptcha() {
    setCaptchaToken(null);
    setCaptchaReset((current) => current + 1);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (mode === "forgot") return;
    if (mode === "signup" && password !== confirmPassword) {
      setMessage("The login passwords do not match.");
      return;
    }
    if (!requireCaptcha()) return;
    setBusy(true); setMessage("");
    try {
      const security = captchaOptions(captchaToken);
      const normalizedEmail = email.trim().toLowerCase();
      const result = mode === "signin"
        ? await supabase!.auth.signInWithPassword({ email: normalizedEmail, password, options: security })
        : await supabase!.auth.signUp({ email: normalizedEmail, password, options: { emailRedirectTo: `${window.location.origin}/#access`, ...security } });
      if (result.error) setMessage(customerError(result.error, mode === "signin" ? "Sign-in could not be completed. Try again." : "Your account could not be created. Try again."));
      else if (mode === "signup" && !result.data.session) {
        if (result.data.user?.identities?.length === 0) setMessage("An account already exists for this email. Sign in or reset the login password.");
        else {
          setPassword("");
          setConfirmPassword("");
          setMessage("Account created. Check your email, confirm the address, then return here to sign in.");
        }
      }
    } catch (reason) {
      setMessage(customerError(reason, "The account service is temporarily unavailable. Try again."));
    } finally { resetCaptcha(); setBusy(false); }
  }

  async function signInWithPasskey() {
    if (!requireCaptcha()) return;
    setBusy(true); setMessage("");
    try {
      const { error } = await supabase!.auth.signInWithPasskey({ options: captchaOptions(captchaToken) });
      if (error) setMessage(customerError(error, "Passkey sign-in could not be completed. Use your login password or try again."));
    } catch (reason) {
      setMessage(customerError(reason, "Passkey sign-in could not be completed. Use your login password or try again."));
    } finally { resetCaptcha(); setBusy(false); }
  }

  async function requestPasswordReset(event: React.FormEvent) {
    event.preventDefault();
    if (!email) { setMessage("Enter your email first."); return; }
    if (!requireCaptcha()) return;
    setBusy(true); setMessage("");
    try {
      const { error } = await supabase!.auth.resetPasswordForEmail(email.trim().toLowerCase(), { redirectTo: `${window.location.origin}/#access`, ...captchaOptions(captchaToken) });
      if (error) throw error;
      setResetSent(true);
      setMessage("If an account exists for this email, a secure reset link is on its way.");
    } catch (reason) {
      setMessage(customerError(reason, "A reset link could not be sent. Try again shortly."));
    } finally { resetCaptcha(); setBusy(false); }
  }

  function switchMode(nextMode: "signin" | "signup" | "forgot") {
    setMode(nextMode);
    setMessage("");
    setPassword("");
    setConfirmPassword("");
    setResetSent(false);
    resetCaptcha();
  }

  const title = mode === "signin" ? "Sign in to Passkey-X" : mode === "signup" ? "Create your account" : "Reset your login password";
  const description = mode === "forgot"
    ? "We’ll send a single-use recovery link. This changes account login only; it cannot decrypt or reset your vault."
    : "Account login and vault unlock are separate security steps.";
  const turnstileAction = mode === "signin" ? "auth-signin" : mode === "signup" ? "auth-signup" : "auth-reset";

  return <ClientAuthFrame mode={clientMode}><Card className="auth-card"><CardHeader><p className="eyebrow">{mode === "signin" ? "Welcome back" : mode === "signup" ? "Create your private vault" : "Account recovery"}</p><CardTitle>{title}</CardTitle><CardDescription>{description}</CardDescription></CardHeader><CardContent>
    {mode === "forgot" ? <form className="form-stack" onSubmit={requestPasswordReset}>
      <div><Label htmlFor="reset-email">Email</Label><Input id="reset-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></div>
      <TurnstileCheck action={turnstileAction} resetKey={captchaReset} onToken={setCaptchaToken} onProblem={() => setMessage("The security check could not load. Refresh the page and try again.")} />
      {message && <p className="form-message" role="status">{message}</p>}
      <Button size="lg" disabled={busy || resetSent}>{busy ? "Sending…" : resetSent ? "Reset email sent" : "Send secure reset link"}</Button>
      <Button type="button" variant="ghost" disabled={busy} onClick={() => switchMode("signin")}>Back to sign in</Button>
    </form> : <form className="form-stack" onSubmit={submit}>
      <div><Label htmlFor="email">Email</Label><Input id="email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></div>
      <div><Label htmlFor="password">Login password</Label><Input id="password" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} />{mode === "signup" && <p className="field-hint">Use at least 12 characters. This password signs in to your account but never decrypts the vault.</p>}</div>
      {mode === "signup" && <div><Label htmlFor="confirm-login-password">Confirm login password</Label><Input id="confirm-login-password" type="password" autoComplete="new-password" minLength={12} required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></div>}
      <TurnstileCheck action={turnstileAction} resetKey={captchaReset} onToken={setCaptchaToken} onProblem={() => setMessage("The security check could not load. Refresh the page and try again.")} />
      {message && <p className="form-message" role="status">{message}</p>}
      <Button size="lg" disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Continue securely" : "Create account"}</Button>
      {mode === "signin" && <Button type="button" variant="ghost" disabled={busy} onClick={() => switchMode("forgot")}>Forgot login password?</Button>}
      <Button type="button" variant="ghost" disabled={busy} onClick={() => switchMode(mode === "signin" ? "signup" : "signin")}>{mode === "signin" ? "New to Passkey-X? Create account" : "I already have an account"}</Button>
    </form>}
    {mode === "signin" && passkeysEnabled && <div className="passkey-signin"><span>or</span><Button type="button" size="lg" variant="outline" disabled={busy} onClick={() => void signInWithPasskey()}><Fingerprint /> Sign in with a passkey</Button><small>Account authentication only. Your separate vault password is still required.</small></div>}{mode === "signin" && <SsoSignIn />}
  </CardContent></Card></ClientAuthFrame>;
}

export function AccountPasswordReset({ email, onComplete }: { email: string; onComplete: () => void }) {
  const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) { event.preventDefault(); if (password !== confirm) { setMessage("The login passwords do not match."); return; } setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.updateUser({ password }); if (error) throw error; setMessage("Login password updated. Your vault password and recovery key are unchanged."); setTimeout(onComplete, 1500); } catch (reason) { setMessage(customerError(reason, "Your login password could not be updated. Request a new reset link and try again.")); } finally { setBusy(false); } }
  return <main className="center-screen setup-bg"><Card className="auth-card"><CardHeader><Brand /><div className="step-pill">Secure account recovery</div><CardTitle>Create a new login password</CardTitle><CardDescription>Updating the login for {email} does not reset or decrypt the separate vault password.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={submit}><div><Label htmlFor="new-login-password">New login password</Label><Input id="new-login-password" type="password" minLength={12} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div><div><Label htmlFor="confirm-login-password">Confirm login password</Label><Input id="confirm-login-password" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>{message && <p className="form-message" role="status">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Updating…" : "Update login password"}</Button></form></CardContent></Card></main>;
}

export type PendingVaultSetup = Omit<CryptoProfile, "identity_id"> & {
  workspace_nonce: string;
  workspace_wrapped_key: string;
  device_public_key: string;
};

export function VaultSetup({ email, onComplete }: { email: string; onComplete: (profile: CryptoProfile) => void }) {
  const [loginPassword, setLoginPassword] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [pendingSetup, setPendingSetup] = useState<PendingVaultSetup | null>(null);
  const [downloaded, setDownloaded] = useState(false);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);

  async function setup(event: React.FormEvent) {
    event.preventDefault();
    if (password !== confirm) { setMessage("The vault passwords do not match."); return; }
    if (password === loginPassword) { setMessage("Your vault password must be different from your login password."); return; }
    if (!captchaReady(captchaEnabled, captchaToken)) { setMessage("Complete the security check before continuing."); return; }
    setBusy(true);
    setMessage("Verifying your account and deriving encryption keys. This can take a few seconds.");
    const salt = randomBytes(16);
    const accountRoot = randomBytes(32);
    const workspaceKey = randomBytes(32);
    let masterKey: Uint8Array | null = null;
    let recoverySecret: Uint8Array | null = null;
    let verifier: Uint8Array | null = null;
    let devicePrivateKey: Uint8Array | null = null;
    try {
      const reauth = await supabase!.auth.signInWithPassword({
        email: email.trim().toLowerCase(),
        password: loginPassword,
        options: captchaOptions(captchaToken),
      });
      if (reauth.error) throw reauth.error;
      masterKey = await deriveMasterKey(password, salt);
      const recovery = createRecoveryKey();
      recoverySecret = recovery.secret;
      verifier = await recoveryVerifier(recoverySecret);
      const masterWrapped = await wrapKey(masterKey, accountRoot, "1accessos:account-root:v1");
      const recoveryWrapped = await wrapKey(recoverySecret, accountRoot, "1accessos:recovery:v1");
      const workspaceWrapped = await wrapKey(accountRoot, workspaceKey, "1accessos:workspace:v1");
      const device = await createDeviceKeyPair();
      devicePrivateKey = device.privateKey;
      const devicePrivate = await wrapKey(accountRoot, devicePrivateKey, "1accessos:device-private:v1");
      await saveProtectedDeviceKey(devicePrivate);
      setRecoveryKey(recovery.display);
      setPendingSetup({
        salt: toBase64Url(salt),
        kdf_parameters: WEB_KDF_PROFILE,
        master_nonce: masterWrapped.nonce,
        master_wrapped_root: masterWrapped.ciphertext,
        recovery_nonce: recoveryWrapped.nonce,
        recovery_wrapped_root: recoveryWrapped.ciphertext,
        recovery_verifier: toBase64Url(verifier),
        workspace_nonce: workspaceWrapped.nonce,
        workspace_wrapped_key: workspaceWrapped.ciphertext,
        device_public_key: toBase64Url(device.publicKey),
      });
      setDownloaded(false);
      setSavedConfirmed(false);
      setMessage("Recovery material is ready. Download the file and store it offline before creating the vault.");
      setPassword("");
      setConfirm("");
    } catch (reason) {
      setMessage(customerError(reason, "Your private vault setup could not be prepared. Check the login password and try again."));
    } finally {
      accountRoot.fill(0);
      workspaceKey.fill(0);
      masterKey?.fill(0);
      recoverySecret?.fill(0);
      verifier?.fill(0);
      devicePrivateKey?.fill(0);
      setLoginPassword("");
      setCaptchaToken(null);
      setCaptchaReset((current) => current + 1);
      setBusy(false);
    }
  }

  function download() {
    if (!recoveryKey) return;
    setMessage("");
    try {
      downloadBlob(recoveryFile(recoveryKey), "passkey-x-recovery-key.json");
      setDownloaded(true);
      setSavedConfirmed(false);
      setMessage("Recovery-key download started. Find the JSON file in Downloads, then confirm below.");
    } catch {
      setDownloaded(false);
      setSavedConfirmed(false);
      setMessage("The recovery-key file could not be downloaded. Allow downloads for this site and try again.");
    }
  }

  async function copyRecoveryKey() {
    if (!recoveryKey) return;
    try {
      await copySecret(recoveryKey, 60);
      setMessage("Recovery key copied. Store it offline; the downloadable file is still required before vault creation.");
    } catch {
      setMessage("Clipboard access was blocked. Use the Download recovery key button instead.");
    }
  }

  async function finishSetup() {
    if (!pendingSetup || !downloaded || !savedConfirmed) {
      setMessage("Download the recovery file and confirm that it is stored safely before continuing.");
      return;
    }
    setBusy(true);
    setMessage("Creating your encrypted vault…");
    try {
      const { data, error } = await supabase!.rpc("bootstrap_personal_vault", {
        p_salt: toPostgresBytea(fromBase64Url(pendingSetup.salt)),
        p_kdf_parameters: pendingSetup.kdf_parameters,
        p_master_nonce: toPostgresBytea(fromBase64Url(pendingSetup.master_nonce)),
        p_master_wrapped_root: toPostgresBytea(fromBase64Url(pendingSetup.master_wrapped_root)),
        p_recovery_nonce: toPostgresBytea(fromBase64Url(pendingSetup.recovery_nonce)),
        p_recovery_wrapped_root: toPostgresBytea(fromBase64Url(pendingSetup.recovery_wrapped_root)),
        p_recovery_verifier: toPostgresBytea(fromBase64Url(pendingSetup.recovery_verifier!)),
        p_workspace_nonce: toPostgresBytea(fromBase64Url(pendingSetup.workspace_nonce)),
        p_workspace_wrapped_key: toPostgresBytea(fromBase64Url(pendingSetup.workspace_wrapped_key)),
        p_device_public_key: toPostgresBytea(fromBase64Url(pendingSetup.device_public_key)),
      });
      if (error) throw error;
      const bootstrap = data as { identity_id: string };
      onComplete({
        identity_id: bootstrap.identity_id,
        salt: pendingSetup.salt,
        kdf_parameters: pendingSetup.kdf_parameters,
        master_nonce: pendingSetup.master_nonce,
        master_wrapped_root: pendingSetup.master_wrapped_root,
        recovery_nonce: pendingSetup.recovery_nonce,
        recovery_wrapped_root: pendingSetup.recovery_wrapped_root,
        recovery_verifier: pendingSetup.recovery_verifier,
      });
    } catch (reason) {
      setMessage(customerError(reason, "Your encrypted vault could not be created. The downloaded recovery key is not active yet; retry safely."));
    } finally {
      setBusy(false);
    }
  }

  function restartSetup() {
    setRecoveryKey(null);
    setPendingSetup(null);
    setDownloaded(false);
    setSavedConfirmed(false);
    setMessage("");
  }

  const step = recoveryKey ? 2 : 1;
  return <main className="center-screen setup-bg"><Card className="setup-card"><CardHeader><Brand /><div className="step-pill">Account verified</div><div className="setup-progress" aria-label={`Vault setup step ${step} of 3`}><span className="active">1. Protect</span><span className={step >= 2 ? "active" : ""}>2. Recover</span><span>3. Create</span></div><CardTitle>{recoveryKey ? "Save your recovery key" : "Create your private vault"}</CardTitle><CardDescription>{recoveryKey ? "This is the only recovery method. Keep an offline copy before the encrypted vault is created." : `Signed in as ${email}. Choose a new password used only to unlock your vault.`}</CardDescription></CardHeader><CardContent>
    {recoveryKey ? <div className="form-stack">
      <div className="recovery-box"><KeyRound /><code>{recoveryKey}</code></div>
      <div className="recovery-actions"><Button size="lg" disabled={busy} onClick={download}><Download /> {downloaded ? "Download recovery key again" : "Download recovery key"}</Button><Button type="button" variant="outline" disabled={busy} onClick={() => void copyRecoveryKey()}><Copy /> Copy key</Button></div>
      <label className={`recovery-confirmation ${downloaded ? "ready" : ""}`}><input type="checkbox" disabled={!downloaded || busy} checked={savedConfirmed} onChange={(event) => setSavedConfirmed(event.target.checked)} /><span>I found the downloaded file and stored it safely.</span></label>
      <Button size="lg" variant="outline" disabled={!pendingSetup || !downloaded || !savedConfirmed || busy} onClick={() => void finishSetup()}>{busy ? "Creating encrypted vault…" : "Create vault and continue"}</Button>
      <Button type="button" variant="ghost" disabled={busy} onClick={restartSetup}>Restart password setup</Button>
      <p className="field-hint">No vault record is created until the file download is started and you explicitly confirm it is stored.</p>
      {message && <p className="form-message" role="status">{message}</p>}
    </div> : <form className="form-stack" onSubmit={setup}>
      <div><Label htmlFor="setup-login-password">Verify login password</Label><Input id="setup-login-password" type="password" minLength={12} autoComplete="current-password" required value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} /></div>
      <div><Label htmlFor="vault-password">New vault master password</Label><Input id="vault-password" type="password" minLength={12} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
      <div><Label htmlFor="vault-confirm">Confirm vault password</Label><Input id="vault-confirm" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>
      <p className="field-hint">Use at least 12 characters. Login and vault passwords must be different. Passkey-X cannot recover the vault password.</p>
      <TurnstileCheck action="vault-setup" resetKey={captchaReset} onToken={setCaptchaToken} onProblem={() => setMessage("The security check could not load. Refresh the page and try again.")} />
      {message && <p className="form-message" role="status">{message}</p>}
      <Button size="lg" disabled={busy}>{busy ? "Preparing recovery…" : "Prepare recovery key"}</Button>
    </form>}
  </CardContent></Card></main>;
}

export function UnlockScreen({ profile, email, onUnlock, onProfileChange }: { profile: CryptoProfile; email: string; onUnlock: (key: Uint8Array, facts?: VaultPasswordFacts) => void; onProfileChange: (profile: CryptoProfile) => void }) {
  const [password, setPassword] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const [recovering, setRecovering] = useState(false); const [orgRecovering, setOrgRecovering] = useState(false); const [recovery, setRecovery] = useState(""); const [newPassword, setNewPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const unlockGeneration = useRef(0);
  useEffect(() => {
    const invalidate = () => { unlockGeneration.current++; };
    const cancel = () => { invalidate(); setPassword(""); setRecovery(""); setNewPassword(""); setConfirm(""); };
    const visibility = () => { if (document.hidden) cancel(); };
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("pagehide", cancel);
    window.addEventListener("passkey-x:lock", cancel);
    return () => { invalidate(); document.removeEventListener("visibilitychange", visibility); window.removeEventListener("pagehide", cancel); window.removeEventListener("passkey-x:lock", cancel); };
  }, []);
  async function unlock(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    const generation = unlockGeneration.current;
    let master: Uint8Array | null = null, root: Uint8Array | null = null;
    try {
      master = await deriveMasterKey(password, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters });
      root = await unwrapKey(master, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1");
      if (generation !== unlockGeneration.current || document.hidden) { setMessage("Unlock was cancelled when the app left the foreground. Try again."); return; }
      const facts = vaultPasswordFacts(password); setPassword(""); onUnlock(root, facts); root = null;
    } catch { setMessage("That vault password could not unlock this vault."); }
    finally { master?.fill(0); root?.fill(0); setBusy(false); }
  }
  async function recover(event: React.FormEvent) { event.preventDefault(); const generation = unlockGeneration.current; if (newPassword !== confirm) { setMessage("The new vault passwords do not match."); return; } if (newPassword.length < 12 || estimateStrength(newPassword).score < 2) { setMessage("Choose a stronger vault password: at least 12 characters that are hard to guess (a passphrase of 4+ random words works well)."); return; } if (newPassword.trim().toLowerCase() === email.trim().toLowerCase()) { setMessage("Your vault password must not be your email address."); return; } setBusy(true); setMessage(""); let recoverySecret: Uint8Array | null = null; let verifier: Uint8Array | null = null; let root: Uint8Array | null = null; let master: Uint8Array | null = null; try { recoverySecret = parseRecoveryKey(recovery); root = await unwrapKey(recoverySecret, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.recovery_nonce)), ciphertext: toBase64Url(bytea(profile.recovery_wrapped_root)) }, "1accessos:recovery:v1"); verifier = await recoveryVerifier(recoverySecret); if (!profile.recovery_verifier) { const legacy = await supabase!.rpc("set_recovery_verifier_once", { p_verifier: toPostgresBytea(verifier) }); if (legacy.error) throw legacy.error; } const salt = randomBytes(16); master = await deriveMasterKey(newPassword, salt); const wrapped = await wrapKey(master, root, "1accessos:account-root:v1"); if (generation !== unlockGeneration.current || document.hidden) throw new Error("Recovery cancelled; return to the app and try again."); const { error } = await supabase!.rpc("rotate_master_with_recovery", { p_recovery_verifier: toPostgresBytea(verifier), p_salt: toPostgresBytea(salt), p_kdf_parameters: WEB_KDF_PROFILE, p_master_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)), p_master_wrapped_root: toPostgresBytea(fromBase64Url(wrapped.ciphertext)) }); if (error) throw error; const next = { ...profile, salt: toBase64Url(salt), kdf_parameters: WEB_KDF_PROFILE, master_nonce: wrapped.nonce, master_wrapped_root: wrapped.ciphertext, recovery_verifier: toBase64Url(verifier) }; onProfileChange(next); if (generation === unlockGeneration.current && !document.hidden) { onUnlock(root, vaultPasswordFacts(newPassword)); root = null; } else { setMessage("Vault password updated. Unlock again to continue."); } } catch (reason) { setMessage(customerError(reason, "The recovery key could not restore this vault.")); } finally { recoverySecret?.fill(0); verifier?.fill(0); root?.fill(0); master?.fill(0); setBusy(false); } }
  return <main className="center-screen unlock-bg"><Card className="auth-card"><CardHeader><Brand /><div className="vault-icon"><LockKeyhole /></div><CardTitle>{recovering ? "Recover your vault" : "Unlock your vault"}</CardTitle><CardDescription>{recovering ? "Use the downloadable recovery key and set a new vault password." : email}</CardDescription></CardHeader><CardContent>{orgRecovering ? <OrgRecoveryUnlock identityId={profile.identity_id} email={email} onCancel={() => setOrgRecovering(false)} onRecovered={(next) => { onProfileChange({ ...profile, salt: next.salt, kdf_parameters: next.kdf_parameters as CryptoProfile["kdf_parameters"], master_nonce: next.master_nonce, master_wrapped_root: next.master_wrapped_root }); setOrgRecovering(false); setMessage("Your vault password was reset with your organization’s help. Unlock with the new password."); }} /> : recovering ? <form className="form-stack" onSubmit={recover}><div><Label htmlFor="recovery-key">Recovery key</Label><Input id="recovery-key" autoComplete="off" required value={recovery} onChange={(event) => setRecovery(event.target.value)} placeholder="PX-RK1-…" /></div><div><Label htmlFor="new-vault-password">New vault password</Label><Input id="new-vault-password" type="password" minLength={12} autoComplete="new-password" required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></div><div><Label htmlFor="new-vault-confirm">Confirm new password</Label><Input id="new-vault-confirm" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Recovering…" : "Recover and unlock"}</Button><Button type="button" variant="ghost" onClick={() => { setRecovering(false); setMessage(""); }}>Back to password</Button></form> : <form className="form-stack" onSubmit={unlock}><div><Label htmlFor="unlock-password">Vault master password</Label><Input id="unlock-password" type="password" autoFocus autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Unlocking…" : "Unlock vault"}</Button><Button type="button" variant="ghost" onClick={() => { setRecovering(true); setMessage(""); }}>Use recovery key</Button><Button type="button" variant="ghost" onClick={() => { setOrgRecovering(true); setMessage(""); }}>Ask my organization</Button><Button type="button" variant="ghost" onClick={() => supabase!.auth.signOut()}>Use another account</Button></form>}</CardContent></Card></main>;
}
