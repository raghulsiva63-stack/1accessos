"use client";

import { useEffect, useState } from "react";
import { useEnterprise } from "@/components/enterprise/policy-context";
import type { VaultPasswordFacts } from "@/components/enterprise/compliance-banner";
import { ChangeVaultPasswordCard } from "@/components/enterprise/change-vault-password";
import { TotpCard } from "@/components/enterprise/mfa";
import { ImportCard } from "@/components/app/import-card";
import type { Factor } from "@supabase/supabase-js";
import {
  Download, Fingerprint, Laptop, Pencil, Plus, RefreshCw, Send, SlidersHorizontal, Smartphone, ShieldCheck,
  Trash2, WandSparkles, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AccountDeletionCard } from "@/components/account-deletion-card";
import { isDesktopApp, WEB_ORIGIN } from "@/lib/desktop/bridge";
import { createEncryptedExport, deriveMasterKey, toBase64Url, unwrapKey } from "@/lib/crypto/vault";
import { passkeysEnabled, phoneMfaEnabled, supabase } from "@/lib/supabase/client";
import { downloadBlob } from "@/lib/browser/download";
import type { VaultItem, WorkspaceVault } from "@/lib/vault/items";
import { generatePassphrase, generatePassword } from "@/lib/vault/tools";
import { type CryptoProfile, type DeviceRow, type Entitlement, bytea, customerError, CopyButton } from "@/components/app/shell/shared";

export function GeneratorView() {
  const [mode, setMode] = useState<"password" | "passphrase">("password"); const [length, setLength] = useState(24); const [value, setValue] = useState(() => generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); const [options, setOptions] = useState({ uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true });
  function regenerate() { setValue(mode === "password" ? generatePassword({ length, ...options }) : generatePassphrase(7)); }
  return <div className="feature-page narrow-page"><Card className="generator-card"><CardHeader><span className="feature-icon"><WandSparkles /></span><CardTitle>Private password generator</CardTitle><CardDescription>Generated with the browser cryptographic random-number generator. Values never leave this device.</CardDescription></CardHeader><CardContent><div className="segmented"><button className={mode === "password" ? "active" : ""} onClick={() => { setMode("password"); setValue(generatePassword({ length, ...options })); }}>Password</button><button className={mode === "passphrase" ? "active" : ""} onClick={() => { setMode("passphrase"); setValue(generatePassphrase(7)); }}>Passphrase</button></div><div className="generated-value"><code>{value}</code><CopyButton value={value} /><button aria-label="Generate another" onClick={regenerate}><RefreshCw /></button></div>{mode === "password" && <><div className="range-row"><Label htmlFor="password-length">Length</Label><strong>{length}</strong><input id="password-length" type="range" min="12" max="64" value={length} onChange={(event) => { const next = Number(event.target.value); setLength(next); setValue(generatePassword({ length: next, ...options })); }} /></div><div className="option-grid">{(["uppercase", "lowercase", "numbers", "symbols", "avoidAmbiguous"] as const).map((key) => <label key={key}><input type="checkbox" disabled={key !== "avoidAmbiguous" && options[key] && [options.uppercase, options.lowercase, options.numbers, options.symbols].filter(Boolean).length === 1} checked={options[key]} onChange={(event) => { const next = { ...options, [key]: event.target.checked }; setOptions(next); try { setValue(generatePassword({ length, ...next })); } catch { /* wait for another option */ } }} /><span>{key === "avoidAmbiguous" ? "Avoid ambiguous" : key[0].toUpperCase() + key.slice(1)}</span></label>)}</div></>}<p className="field-hint">Passphrases use seven randomly selected words. <a href="/third-party-notices.txt" target="_blank" rel="noreferrer">Wordlist attribution</a></p><div className="privacy-note"><ShieldCheck /><span>Clipboard copies are cleared after 30 seconds when the copied value is still present.</span></div></CardContent></Card></div>;
}

export type AccountPasskey = { id: string; friendly_name?: string; created_at: string; last_used_at?: string };

export function AccountSecurityView() {
  const { refreshCompliance } = useEnterprise();
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]); const [busy, setBusy] = useState(false); const [loading, setLoading] = useState(passkeysEnabled); const [message, setMessage] = useState("");
  async function refresh() { if (!passkeysEnabled) return; const { data, error } = await supabase!.auth.passkey.list(); if (error) setMessage(customerError(error, "Your passkeys could not be loaded. Try again.")); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }
  useEffect(() => { if (!passkeysEnabled) return; let active = true; supabase!.auth.passkey.list().then(({ data, error }) => { if (!active) return; if (error) setMessage(customerError(error, "Your passkeys could not be loaded. Try again.")); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }); return () => { active = false; }; }, []);
  async function register() { setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.registerPasskey(); if (error) throw error; refreshCompliance(); setMessage("Passkey registered. Your vault password remains separate."); await refresh(); } catch (reason) { setMessage(customerError(reason, "Passkey registration could not be completed. Try again.")); } finally { setBusy(false); } }
  async function rename(passkey: AccountPasskey) { const friendlyName = window.prompt("Passkey name", passkey.friendly_name ?? "My passkey")?.trim(); if (!friendlyName) return; setBusy(true); const { error } = await supabase!.auth.passkey.update({ passkeyId: passkey.id, friendlyName }); if (error) setMessage(customerError(error, "This passkey could not be renamed. Try again.")); else await refresh(); setBusy(false); }
  async function remove(passkey: AccountPasskey) { if (!window.confirm(`Remove ${passkey.friendly_name ?? "this passkey"}? It will no longer sign in to Passkey-X.`)) return; setBusy(true); const { error } = await supabase!.auth.passkey.delete({ passkeyId: passkey.id }); if (error) setMessage(customerError(error, "This passkey could not be removed. Try again.")); else { setMessage("Passkey removed."); await refresh(); } setBusy(false); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Fingerprint /> Account protection</span><h2>Sign-in security</h2><p>Use phishing-resistant passkeys and optional mobile verification for your account. Neither method replaces or discloses the separate vault password.</p></div><Button disabled={!passkeysEnabled || busy} onClick={() => void register()}><Plus /> Add passkey</Button></div>{!passkeysEnabled && <Card className="passkey-readiness"><CardHeader><CardTitle>Passkeys are unavailable</CardTitle><CardDescription>{isDesktopApp() ? "Add and manage passkeys on passkey-x.com in your browser. The desktop app signs in through your browser, so your passkeys work there." : "Passwordless sign-in is not available in this environment. Continue using your login password; your encrypted vault is unaffected."}</CardDescription></CardHeader></Card>}{passkeysEnabled && <Card><CardHeader><CardTitle>Your passkeys</CardTitle><CardDescription>Your public sign-in credential is stored securely. The private key remains on your authenticator and never leaves it.</CardDescription></CardHeader><CardContent>{loading ? <div className="loading-ring" /> : passkeys.length ? <div className="account-passkey-list">{passkeys.map((passkey) => <article key={passkey.id}><span className="device-icon"><Fingerprint /></span><div><strong>{passkey.friendly_name ?? "Passkey"}</strong><small>Added {new Date(passkey.created_at).toLocaleDateString()}{passkey.last_used_at ? ` · Last used ${new Date(passkey.last_used_at).toLocaleDateString()}` : ""}</small></div><Button variant="ghost" onClick={() => void rename(passkey)} disabled={busy}><Pencil /> Rename</Button><Button variant="outline" onClick={() => void remove(passkey)} disabled={busy}><Trash2 /> Remove</Button></article>)}</div> : <div className="small-empty"><Fingerprint /><strong>No passkeys registered</strong><span>Add one after signing in with your existing account method.</span></div>}</CardContent></Card>}<TotpCard /><PhoneMfaCard />{message && <p className="settings-message" role="status">{message}</p>}<div className="privacy-note"><ShieldCheck /><span>Account authentication establishes a session only. Client-side Argon2id and AES-256-GCM vault encryption are unchanged.</span></div></div>;
}

export function PhoneMfaCard() {
  const [factors, setFactors] = useState<Factor<"phone", "verified">[]>([]);
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<{ factorId: string; challengeId: string } | null>(null);
  const [loading, setLoading] = useState(phoneMfaEnabled);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function refresh() {
    if (!phoneMfaEnabled) return;
    const { data, error } = await supabase!.auth.mfa.listFactors();
    if (error) setMessage(customerError(error, "Mobile verification methods could not be loaded."));
    else setFactors(data.phone);
    setLoading(false);
  }

  useEffect(() => {
    if (!phoneMfaEnabled) return;
    let active = true;
    supabase!.auth.mfa.listFactors().then(({ data, error }) => {
      if (!active) return;
      if (error) setMessage(customerError(error, "Mobile verification methods could not be loaded."));
      else setFactors(data.phone);
      setLoading(false);
    });
    return () => { active = false; };
  }, []);

  async function enroll(event: React.FormEvent) {
    event.preventDefault();
    const normalized = phone.replace(/[\s()-]/gu, "");
    if (!/^\+[1-9]\d{7,14}$/u.test(normalized)) { setMessage("Enter a mobile number in international format, such as +14155550123."); return; }
    setBusy(true); setMessage(""); setCode("");
    try {
      const enrolled = await supabase!.auth.mfa.enroll({ factorType: "phone", phone: normalized, friendlyName: `Mobile ${normalized.slice(-4)} · ${crypto.randomUUID().slice(0, 4)}` });
      if (enrolled.error) throw enrolled.error;
      const challenged = await supabase!.auth.mfa.challenge({ factorId: enrolled.data.id, channel: "sms" });
      if (challenged.error) {
        await supabase!.auth.mfa.unenroll({ factorId: enrolled.data.id });
        throw challenged.error;
      }
      setPending({ factorId: enrolled.data.id, challengeId: challenged.data.id });
      setMessage("A verification code was sent. Enter it to finish adding this mobile number.");
    } catch (reason) {
      setMessage(customerError(reason, "This mobile number could not be enrolled. Try again shortly."));
    } finally { setBusy(false); }
  }

  async function verify(event: React.FormEvent) {
    event.preventDefault();
    if (!pending) return;
    setBusy(true); setMessage("");
    try {
      const { error } = await supabase!.auth.mfa.verify({ factorId: pending.factorId, challengeId: pending.challengeId, code: code.trim() });
      if (error) throw error;
      setPending(null); setPhone(""); setCode(""); setMessage("Mobile two-step verification is now active.");
      await refresh();
    } catch (reason) {
      setMessage(customerError(reason, "That verification code is invalid or expired. Start again for a new code."));
    } finally { setBusy(false); }
  }

  async function cancelEnrollment() {
    if (!pending) return;
    setBusy(true);
    await supabase!.auth.mfa.unenroll({ factorId: pending.factorId });
    setPending(null); setCode(""); setMessage("Mobile enrollment cancelled."); setBusy(false);
  }

  async function remove(factor: Factor<"phone", "verified">) {
    if (!window.confirm("Remove mobile two-step verification? Future sign-ins will no longer require codes from this number.")) return;
    setBusy(true); setMessage("");
    const { error } = await supabase!.auth.mfa.unenroll({ factorId: factor.id });
    if (error) setMessage(customerError(error, "This mobile verification method could not be removed."));
    else { setMessage("Mobile verification removed."); await refresh(); }
    setBusy(false);
  }

  if (!phoneMfaEnabled) return <Card className="passkey-readiness"><CardHeader><span className="feature-icon"><Smartphone /></span><CardTitle>Mobile verification is being prepared</CardTitle><CardDescription>Phone numbers remain optional. SMS enrollment will become available only after the signed Supabase-to-Sent delivery path is activated and tested.</CardDescription></CardHeader></Card>;

  return <Card><CardHeader><span className="feature-icon"><Smartphone /></span><CardTitle>Mobile two-step verification</CardTitle><CardDescription>Add a mobile number after sign-in. It will be used for a second account-verification step, never as the only way to recover or decrypt the vault.</CardDescription></CardHeader><CardContent>{loading ? <div className="loading-ring" /> : <div className="phone-mfa-stack">{factors.length > 0 && <div className="account-passkey-list">{factors.map((factor, index) => <article key={factor.id}><span className="device-icon"><Smartphone /></span><div><strong>{factor.friendly_name ?? `Mobile ${index + 1}`}</strong><small>Verified {new Date(factor.updated_at).toLocaleDateString()}</small></div><Button variant="outline" disabled={busy} onClick={() => void remove(factor)}>Remove</Button></article>)}</div>}{!pending ? <form className="form-stack" onSubmit={enroll}><div><Label htmlFor="mfa-phone">Mobile number</Label><Input id="mfa-phone" type="tel" autoComplete="tel" placeholder="+14155550123" required value={phone} onChange={(event) => setPhone(event.target.value)} /><p className="field-hint">Use international E.164 format. The number is managed by Supabase Auth and is not stored in your encrypted vault.</p></div><Button disabled={busy}><Send /> {busy ? "Sending…" : factors.length ? "Add another mobile" : "Send verification code"}</Button></form> : <form className="form-stack" onSubmit={verify}><div><Label htmlFor="mfa-enroll-code">Verification code</Label><Input id="mfa-enroll-code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={10} pattern="[0-9]{6,10}" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/gu, ""))} /></div><div className="inline-actions"><Button disabled={busy || code.length < 6}>{busy ? "Verifying…" : "Verify mobile"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={() => void cancelEnrollment()}>Cancel</Button></div></form>}{message && <p className="form-message neutral-message" role="status">{message}</p>}</div>}</CardContent></Card>;
}

export function DevicesView({ identityId }: { identityId: string }) {
  const [devices, setDevices] = useState<DeviceRow[]>([]); const [loading, setLoading] = useState(true); const [message, setMessage] = useState("");
  async function refresh() { const { data, error } = await supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }); if (error) setMessage(customerError(error, "Your devices could not be loaded. Try again.")); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }
  useEffect(() => { let active = true; supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }).then(({ data, error }) => { if (!active) return; if (error) setMessage(customerError(error, "Your devices could not be loaded. Try again.")); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }); return () => { active = false; }; }, [identityId]);
  async function revoke(device: DeviceRow) { if (!window.confirm("Revoke this device? It cannot be trusted again.")) return; const { error } = await supabase!.from("devices").update({ status: "revoked", revoked_at: new Date().toISOString() }).eq("id", device.id).neq("status", "revoked"); if (error) setMessage(customerError(error, "This device could not be revoked. Try again.")); else await refresh(); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Laptop /> Trusted-device boundary</span><h2>Devices with vault access</h2><p>Free accounts support two active devices. Revocation is one-way and removes device-key eligibility.</p></div></div>{message && <p className="form-message" role="alert">{message}</p>}<div className="device-list">{loading ? <div className="loading-ring" /> : devices.map((device, index) => <Card key={device.id}><CardContent><span className="device-icon"><Laptop /></span><div><strong>{index === devices.length - 1 ? "Initial browser" : `Browser device ${devices.length - index}`}</strong><span>Added {new Date(device.created_at).toLocaleDateString()} · {device.status}</span><code>{device.id.slice(0, 8)}…{device.id.slice(-4)}</code></div><span className={`device-status ${device.status}`}>{device.status}</span>{device.status !== "revoked" && <Button variant="outline" onClick={() => revoke(device)}>Revoke</Button>}</CardContent></Card>)}</div><div className="privacy-note"><ShieldCheck /><span>Passkey-X stores only a public device key and encrypted labels. Private device key material stays protected in the client.</span></div></div>;
}

export function SettingsView({ email, items, vault, profile, entitlement, onImported, onProfileChange, onPasswordFacts }: { email: string; items: VaultItem[]; vault: WorkspaceVault; profile: CryptoProfile; entitlement: Entitlement; onImported: () => Promise<void> | void; onProfileChange: (profile: CryptoProfile) => void; onPasswordFacts: (facts: VaultPasswordFacts) => void }) {
  const { canExport, policy, record } = useEnterprise();
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const [exportPassword, setExportPassword] = useState(""); const [showExport, setShowExport] = useState(false);
  async function exportVault(event: React.FormEvent) { event.preventDefault(); if (!canExport) { record("policy.blocked", null); setMessage("Your organization's policy does not allow vault export."); setShowExport(false); return; } setBusy(true); setMessage(""); let master: Uint8Array | null = null; let verified: Uint8Array | null = null; try { master = await deriveMasterKey(exportPassword, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters }); verified = await unwrapKey(master, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1"); const data = await createEncryptedExport({ product: "Passkey-X", version: 1, items }, exportPassword); downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), `passkey-x-export-${new Date().toISOString().slice(0, 10)}.pxvault`); setExportPassword(""); setShowExport(false); record("vault.exported", null); setMessage("Encrypted export download started."); } catch { setMessage("Vault reauthentication failed or the browser blocked the download; no export was saved."); } finally { master?.fill(0); verified?.fill(0); setBusy(false); } }
  const planName = entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1);
  return <div className="feature-page settings-v3"><div className="feature-intro"><div><span className="status-pill"><SlidersHorizontal /> Settings</span><h2>Your account and your data</h2><p>Bring passwords in from another app, keep an encrypted backup, change your vault password, or close your account.</p></div></div>
    <h3 className="settings-section">Account</h3>
    <div className="settings-grid"><Card><CardHeader><CardTitle>Account</CardTitle><CardDescription>Signed in as {email}</CardDescription></CardHeader><CardContent><div className="setting-row"><span>Plan</span><strong>{planName}</strong></div><div className="setting-row"><span>Billing status</span><strong>{entitlement.subscription_status.replaceAll("_", " ")}</strong></div><div className="setting-row"><span>Encryption</span><strong>Argon2id + AES-256-GCM</strong></div><div className="setting-row"><span>Workspace</span><code>{vault.workspaceId.slice(0, 8)}…</code></div><p className="field-hint">Change or cancel your plan in Plans & billing. Billing never receives vault contents.</p></CardContent></Card><ChangeVaultPasswordCard profile={profile} onProfileChange={onProfileChange} onPasswordChanged={onPasswordFacts} /></div>
    <h3 className="settings-section">Move your passwords</h3>
    <div className="settings-grid"><ImportCard vault={vault} onImported={onImported} /><Card><CardHeader><CardTitle>Encrypted backup</CardTitle><CardDescription>Download everything in this workspace as one encrypted file. You confirm with your vault password first.</CardDescription></CardHeader><CardContent>{canExport ? <Button variant="outline" onClick={() => setShowExport(true)}><Download /> Export {items.length} items</Button> : <p className="field-hint">Export is {policy.exportMode === "blocked" ? "disabled" : "limited to owners and admins"} by your organization.</p>}</CardContent></Card></div>
    <h3 className="settings-section danger">Close your account</h3>
    <div className="settings-grid">{isDesktopApp()
      ? <Card><CardHeader><CardTitle>Delete your account</CardTitle><CardDescription>For your protection, account deletion is done on passkey-x.com in your browser, where it asks for your login password and a security check.</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => window.open(`${WEB_ORIGIN}/login`, "_blank", "noopener")}>Open passkey-x.com</Button></CardContent></Card>
      : <AccountDeletionCard email={email} />}</div>
    {message && <p className="settings-message" role="status">{message}</p>}{showExport && <div className="modal-backdrop"><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="export-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={() => setShowExport(false)}><X /></button><CardTitle id="export-title">Confirm encrypted export</CardTitle><CardDescription>Enter your vault password. The export is encrypted locally with a fresh salt.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={exportVault}><div><Label htmlFor="export-password">Vault password</Label><Input id="export-password" type="password" autoComplete="current-password" required value={exportPassword} onChange={(event) => setExportPassword(event.target.value)} /></div><Button disabled={busy}>{busy ? "Encrypting…" : "Reauthenticate and download"}</Button></form></CardContent></Card></div>}</div>;
}
