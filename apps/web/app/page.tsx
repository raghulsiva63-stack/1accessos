"use client";

import Image from "next/image";
import { useEffect, useMemo, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import {
  Archive, Bot, Braces, BriefcaseBusiness, Check, ChevronRight, CircleGauge, Clock3,
  Copy, CreditCard, Database, Download, Eye, EyeOff, FileKey, FileText, Fingerprint,
  FolderKanban, Heart, History, IdCard, Inbox, KeyRound, Laptop, LockKeyhole, LogOut,
  MoreHorizontal, Paperclip, Pencil, Play, Plus, Radio, RefreshCw, Search, Send,
  Settings, Share2, ShieldAlert, ShieldCheck, Sparkles, Star, Trash2, Upload,
  UserPlus, UserRound, Users, Vault, WandSparkles, Wifi, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  createDeviceKeyPair, createEncryptedExport, createRecoveryKey, deriveMasterKey,
  fromBase64Url, parseRecoveryKey, randomBytes, recoveryFile, recoveryVerifier, saveProtectedDeviceKey,
  toBase64Url, toPostgresBytea, unwrapKey, WEB_KDF_PROFILE, wrapKey,
} from "@/lib/crypto/vault";
import { isSupabaseConfigured, passkeysEnabled, supabase } from "@/lib/supabase/client";
import {
  createVaultItem, deleteVaultItem, type ItemKind, listVaultItemHistory,
  listVaultItems, listWorkspaceVaults, restoreVaultItem, type VaultHistoryEntry,
  type VaultItem, type VaultPayload, type WorkspaceVault, updateVaultItem,
} from "@/lib/vault/items";
import { generatePassphrase, generatePassword, parseLoginCsv, passwordHealth } from "@/lib/vault/tools";
import { downloadEncryptedAttachment, listEncryptedAttachments, type VaultAttachment, uploadEncryptedAttachment } from "@/lib/vault/attachments";
import {
  acceptAccessCapsule, acceptWorkspaceInvite, consumeAccessCapsule, createAccessCapsule,
  createAccessRequest, createMission, createSharedWorkspace, createWorkspaceInvite,
  decideAccessRequest, listAccessRequests, listMissions, listReceivedCapsules,
  listSentCapsules, listWorkspaceInvites, listWorkspaceMembers, parseCollaborationLink,
  revokeAccessCapsule, revokeWorkspaceInvite, revokeWorkspaceMember, startMission,
  type AccessRequest, type InviteLink, type Mission, type ReceivedCapsule,
  type SentCapsule, type WorkspaceInvite, type WorkspaceMember, type WorkspaceRole,
  type WorkspaceSuite,
} from "@/lib/collaboration/phase2";

type CryptoProfile = {
  identity_id: string;
  salt: string;
  kdf_parameters: { memoryKib: number; iterations: number; parallelism: number; hashLength: 32 };
  master_nonce: string;
  master_wrapped_root: string;
  recovery_nonce: string;
  recovery_wrapped_root: string;
  recovery_verifier: string | null;
};

type View = "home" | "vault" | "workspaces" | "missions" | "sharing" | "inbox" | "security" | "account-security" | "generator" | "automations" | "devices" | "settings";
type VaultFilter = ItemKind | "all" | "favorites" | "archive" | "trash";
type DeviceRow = { id: string; status: "pending" | "trusted" | "revoked"; created_at: string; last_seen_at: string | null; revoked_at: string | null };
type Entitlement = { plan_code: "free" | "personal" | "family" | "professional" | "team"; ai_credits_remaining: number; automation_runs_remaining: number; phase2_preview_enabled?: boolean };

const ITEM_TYPES: Record<ItemKind, { label: string; plural: string; icon: typeof KeyRound; secretLabel?: string; userLabel?: string }> = {
  login: { label: "Login", plural: "Logins", icon: UserRound, secretLabel: "Password" },
  passkey: { label: "Passkey reference", plural: "Passkeys", icon: Fingerprint, secretLabel: "Credential ID", userLabel: "Account" },
  "secure-note": { label: "Secure note", plural: "Secure notes", icon: FileText },
  identity: { label: "Identity", plural: "Identities", icon: IdCard, secretLabel: "Identity number", userLabel: "Full name" },
  "payment-card": { label: "Payment card", plural: "Payment cards", icon: CreditCard, secretLabel: "Card number", userLabel: "Cardholder" },
  "recovery-codes": { label: "Recovery codes", plural: "Recovery codes", icon: ShieldAlert, secretLabel: "Codes", userLabel: "Service" },
  wifi: { label: "Wi-Fi", plural: "Wi-Fi", icon: Wifi, secretLabel: "Password", userLabel: "Network name" },
  "software-license": { label: "Software license", plural: "Licenses", icon: FileKey, secretLabel: "License key", userLabel: "Account" },
  "api-key": { label: "API key", plural: "API keys", icon: KeyRound, secretLabel: "Secret", userLabel: "Service or account" },
  "ssh-key": { label: "SSH key reference", plural: "SSH keys", icon: Radio, secretLabel: "Private key or reference", userLabel: "Host or account" },
  database: { label: "Database credential", plural: "Databases", icon: Database, secretLabel: "Password", userLabel: "Username" },
  certificate: { label: "Certificate / secret file", plural: "Certificates", icon: FileKey, secretLabel: "Private material", userLabel: "Subject" },
  "custom-secret": { label: "Custom secret", plural: "Custom secrets", icon: Braces, secretLabel: "Secret", userLabel: "Account" },
};

const NAV: { id: View; label: string; icon: typeof Vault }[] = [
  { id: "home", label: "Home", icon: CircleGauge },
  { id: "vault", label: "Vault", icon: Vault },
  { id: "workspaces", label: "Workspaces", icon: Users },
  { id: "missions", label: "Missions", icon: FolderKanban },
  { id: "sharing", label: "Sharing", icon: Share2 },
  { id: "inbox", label: "Access inbox", icon: Inbox },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "account-security", label: "Account security", icon: Fingerprint },
  { id: "generator", label: "Generator", icon: WandSparkles },
  { id: "automations", label: "Automations", icon: Bot },
  { id: "devices", label: "Devices", icon: Laptop },
  { id: "settings", label: "Settings", icon: Settings },
];

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={`brand ${compact ? "brand-compact" : ""}`}><Image src={compact ? "/brand/passkey-x-mark.png" : "/brand/passkey-x-horizontal.png"} alt="Passkey-X by Vlightsoft" width={compact ? 48 : 230} height={compact ? 48 : 66} priority /></div>;
}

function bytea(value: string) {
  return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64Url(value);
}

export default function Home() {
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<CryptoProfile | null>(null);
  const [rootKey, setRootKey] = useState<Uint8Array | null>(null);
  const [loading, setLoading] = useState(isSupabaseConfigured);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!supabase) return;
    let active = true;
    supabase.auth.getSession().then(({ data }) => { if (active) { setSession(data.session); setLoading(false); } });
    const { data } = supabase.auth.onAuthStateChange((_event, next) => { setSession(next); setProfile(null); setError(""); if (!next) setRootKey((current) => { current?.fill(0); return null; }); });
    return () => { active = false; data.subscription.unsubscribe(); };
  }, []);

  useEffect(() => {
    if (!supabase || !session) return;
    let active = true;
    supabase.from("account_crypto_profiles").select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root,recovery_nonce,recovery_wrapped_root,recovery_verifier").maybeSingle().then(({ data, error: profileError }) => { if (!active) return; if (profileError) setError(profileError.message); setProfile(data as CryptoProfile | null); setLoading(false); });
    return () => { active = false; };
  }, [session]);

  if (loading) return <main className="center-screen"><div className="loading-ring" aria-label="Loading Passkey-X" /></main>;
  if (!isSupabaseConfigured) return <ConfigurationNotice />;
  if (!session) return <AuthScreen />;
  if (error) return <FatalNotice message={error} />;
  if (!profile) return <VaultSetup email={session.user.email ?? "your account"} onComplete={setProfile} />;
  if (!rootKey) return <UnlockScreen profile={profile} email={session.user.email ?? ""} onUnlock={setRootKey} onProfileChange={setProfile} />;
  return <VaultShell email={session.user.email ?? ""} profile={profile} rootKey={rootKey} onLock={() => { rootKey.fill(0); setRootKey(null); }} />;
}

function ConfigurationNotice() {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Connect the development project</CardTitle><CardDescription>Add the public Supabase URL and publishable key to the hosting environment. Secret keys are never used by the browser.</CardDescription></CardHeader></Card></main>;
}

function FatalNotice({ message }: { message: string }) {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Passkey-X could not open</CardTitle><CardDescription>{message}</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => supabase?.auth.signOut()}>Sign out</Button></CardContent></Card></main>;
}

function AuthScreen() {
  const [mode, setMode] = useState<"signin" | "signup">("signin"); const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); const result = mode === "signin" ? await supabase!.auth.signInWithPassword({ email, password }) : await supabase!.auth.signUp({ email, password, options: { emailRedirectTo: window.location.origin } }); setBusy(false); if (result.error) setMessage(result.error.message); else if (mode === "signup" && !result.data.session) setMessage("Check your email to confirm the account, then sign in."); }
  async function signInWithPasskey() { setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.signInWithPasskey(); if (error) setMessage(error.message); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Passkey sign-in could not start."); } finally { setBusy(false); } }
  return <main className="auth-layout"><section className="auth-story"><div className="auth-brand"><Brand /></div><div className="auth-copy"><div className="security-kicker"><ShieldCheck /> Zero-knowledge protection</div><h1>The keys to your digital life. Yours alone.</h1><p>Passwords, passkeys, API tokens, recovery codes, and private credentials are encrypted on this device before storage.</p><div className="trust-row"><span>Argon2id</span><span>AES-256-GCM</span><span>Client encrypted</span></div></div><p className="trust-note">Passkey-X and Vlightsoft cannot read or reset your encrypted vault.</p></section><section className="auth-panel"><Card className="auth-card"><CardHeader><div className="mobile-brand"><Brand /></div><p className="eyebrow">{mode === "signin" ? "Welcome back" : "Create your private vault"}</p><CardTitle>{mode === "signin" ? "Sign in to Passkey-X" : "Create your account"}</CardTitle><CardDescription>Account login and vault unlock are separate security steps.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={submit}><div><Label htmlFor="email">Email</Label><Input id="email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></div><div><Label htmlFor="password">Login password</Label><Input id="password" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} /></div>{message && <p className="form-message" role="status">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Continue securely" : "Create account"}</Button><Button type="button" variant="ghost" onClick={() => { setMode(mode === "signin" ? "signup" : "signin"); setMessage(""); }}>{mode === "signin" ? "New to Passkey-X? Create account" : "I already have an account"}</Button></form>{mode === "signin" && passkeysEnabled && <div className="passkey-signin"><span>or</span><Button type="button" size="lg" variant="outline" disabled={busy} onClick={() => void signInWithPasskey()}><Fingerprint /> Sign in with a passkey</Button><small>Account authentication only. Your separate vault password is still required.</small></div>}</CardContent></Card></section></main>;
}

function VaultSetup({ email, onComplete }: { email: string; onComplete: (profile: CryptoProfile) => void }) {
  const [loginPassword, setLoginPassword] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(""); const [recoveryKey, setRecoveryKey] = useState<string | null>(null); const [pendingProfile, setPendingProfile] = useState<CryptoProfile | null>(null); const [downloaded, setDownloaded] = useState(false);
  async function setup(event: React.FormEvent) {
    event.preventDefault(); if (password !== confirm) { setMessage("The vault passwords do not match."); return; } if (password === loginPassword) { setMessage("Your vault password must be different from your login password."); return; } setBusy(true); setMessage("");
    const salt = randomBytes(16); const accountRoot = randomBytes(32); const workspaceKey = randomBytes(32); let masterKey: Uint8Array | null = null;
    try { const reauth = await supabase!.auth.signInWithPassword({ email, password: loginPassword }); if (reauth.error) throw new Error("Login-password verification failed."); masterKey = await deriveMasterKey(password, salt); const recovery = createRecoveryKey(); const verifier = await recoveryVerifier(recovery.secret); const masterWrapped = await wrapKey(masterKey, accountRoot, "1accessos:account-root:v1"); const recoveryWrapped = await wrapKey(recovery.secret, accountRoot, "1accessos:recovery:v1"); const workspaceWrapped = await wrapKey(accountRoot, workspaceKey, "1accessos:workspace:v1"); const device = await createDeviceKeyPair(); const devicePrivate = await wrapKey(accountRoot, device.privateKey, "1accessos:device-private:v1"); await saveProtectedDeviceKey(devicePrivate); const { data, error } = await supabase!.rpc("bootstrap_personal_vault", { p_salt: toPostgresBytea(salt), p_kdf_parameters: WEB_KDF_PROFILE, p_master_nonce: toPostgresBytea(fromBase64Url(masterWrapped.nonce)), p_master_wrapped_root: toPostgresBytea(fromBase64Url(masterWrapped.ciphertext)), p_recovery_nonce: toPostgresBytea(fromBase64Url(recoveryWrapped.nonce)), p_recovery_wrapped_root: toPostgresBytea(fromBase64Url(recoveryWrapped.ciphertext)), p_recovery_verifier: toPostgresBytea(verifier), p_workspace_nonce: toPostgresBytea(fromBase64Url(workspaceWrapped.nonce)), p_workspace_wrapped_key: toPostgresBytea(fromBase64Url(workspaceWrapped.ciphertext)), p_device_public_key: toPostgresBytea(device.publicKey) }); const verifierValue = toBase64Url(verifier); verifier.fill(0); if (error) throw error; const bootstrap = data as { identity_id: string }; setRecoveryKey(recovery.display); setPendingProfile({ identity_id: bootstrap.identity_id, salt: toBase64Url(salt), kdf_parameters: WEB_KDF_PROFILE, master_nonce: masterWrapped.nonce, master_wrapped_root: masterWrapped.ciphertext, recovery_nonce: recoveryWrapped.nonce, recovery_wrapped_root: recoveryWrapped.ciphertext, recovery_verifier: verifierValue }); setLoginPassword(""); setPassword(""); setConfirm(""); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Vault setup failed."); } finally { accountRoot.fill(0); workspaceKey.fill(0); masterKey?.fill(0); setLoginPassword(""); setBusy(false); }
  }
  function download() { if (!recoveryKey) return; const url = URL.createObjectURL(recoveryFile(recoveryKey)); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "passkey-x-recovery-key.json"; anchor.click(); URL.revokeObjectURL(url); setDownloaded(true); }
  return <main className="center-screen setup-bg"><Card className="setup-card"><CardHeader><Brand /><div className="step-pill">Account verified</div><CardTitle>{recoveryKey ? "Save your recovery key" : "Create your private vault"}</CardTitle><CardDescription>{recoveryKey ? "This is the only recovery method. Keep an offline copy." : `Signed in as ${email}. Choose a new password used only to unlock your vault.`}</CardDescription></CardHeader><CardContent>{recoveryKey ? <div className="form-stack"><div className="recovery-box"><KeyRound /><code>{recoveryKey}</code></div><Button size="lg" onClick={download}><Download /> Download recovery key</Button><Button variant="outline" disabled={!pendingProfile || !downloaded} onClick={() => { if (pendingProfile) onComplete(pendingProfile); }}>I saved it securely — continue</Button><p className="field-hint">The continue button unlocks after the recovery file has been downloaded.</p></div> : <form className="form-stack" onSubmit={setup}><div><Label htmlFor="setup-login-password">Verify login password</Label><Input id="setup-login-password" type="password" minLength={12} autoComplete="current-password" required value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} /></div><div><Label htmlFor="vault-password">Vault master password</Label><Input id="vault-password" type="password" minLength={12} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div><div><Label htmlFor="vault-confirm">Confirm vault password</Label><Input id="vault-confirm" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div><p className="field-hint">Login and vault passwords must be different. Passkey-X cannot recover the vault password.</p>{message && <p className="form-message" role="alert">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Securing vault…" : "Create encrypted vault"}</Button></form>}</CardContent></Card></main>;
}

function UnlockScreen({ profile, email, onUnlock, onProfileChange }: { profile: CryptoProfile; email: string; onUnlock: (key: Uint8Array) => void; onProfileChange: (profile: CryptoProfile) => void }) {
  const [password, setPassword] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const [recovering, setRecovering] = useState(false); const [recovery, setRecovery] = useState(""); const [newPassword, setNewPassword] = useState(""); const [confirm, setConfirm] = useState("");
  async function unlock(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); let master: Uint8Array | null = null; try { master = await deriveMasterKey(password, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters }); const root = await unwrapKey(master, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1"); setPassword(""); onUnlock(root); } catch { setMessage("That vault password could not unlock this vault."); } finally { master?.fill(0); setBusy(false); } }
  async function recover(event: React.FormEvent) { event.preventDefault(); if (newPassword !== confirm) { setMessage("The new vault passwords do not match."); return; } setBusy(true); setMessage(""); let recoverySecret: Uint8Array | null = null; let verifier: Uint8Array | null = null; let root: Uint8Array | null = null; let master: Uint8Array | null = null; try { recoverySecret = parseRecoveryKey(recovery); root = await unwrapKey(recoverySecret, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.recovery_nonce)), ciphertext: toBase64Url(bytea(profile.recovery_wrapped_root)) }, "1accessos:recovery:v1"); verifier = await recoveryVerifier(recoverySecret); if (!profile.recovery_verifier) { const legacy = await supabase!.rpc("set_recovery_verifier_once", { p_verifier: toPostgresBytea(verifier) }); if (legacy.error) throw legacy.error; } const salt = randomBytes(16); master = await deriveMasterKey(newPassword, salt); const wrapped = await wrapKey(master, root, "1accessos:account-root:v1"); const { error } = await supabase!.rpc("rotate_master_with_recovery", { p_recovery_verifier: toPostgresBytea(verifier), p_salt: toPostgresBytea(salt), p_kdf_parameters: WEB_KDF_PROFILE, p_master_nonce: toPostgresBytea(fromBase64Url(wrapped.nonce)), p_master_wrapped_root: toPostgresBytea(fromBase64Url(wrapped.ciphertext)) }); if (error) throw error; const next = { ...profile, salt: toBase64Url(salt), kdf_parameters: WEB_KDF_PROFILE, master_nonce: wrapped.nonce, master_wrapped_root: wrapped.ciphertext, recovery_verifier: toBase64Url(verifier) }; onProfileChange(next); onUnlock(root); root = null; } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Recovery failed."); } finally { recoverySecret?.fill(0); verifier?.fill(0); root?.fill(0); master?.fill(0); setBusy(false); } }
  return <main className="center-screen unlock-bg"><Card className="auth-card"><CardHeader><Brand /><div className="vault-icon"><LockKeyhole /></div><CardTitle>{recovering ? "Recover your vault" : "Unlock your vault"}</CardTitle><CardDescription>{recovering ? "Use the downloadable recovery key and set a new vault password." : email}</CardDescription></CardHeader><CardContent>{recovering ? <form className="form-stack" onSubmit={recover}><div><Label htmlFor="recovery-key">Recovery key</Label><Input id="recovery-key" autoComplete="off" required value={recovery} onChange={(event) => setRecovery(event.target.value)} placeholder="PX-RK1-…" /></div><div><Label htmlFor="new-vault-password">New vault password</Label><Input id="new-vault-password" type="password" minLength={12} autoComplete="new-password" required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></div><div><Label htmlFor="new-vault-confirm">Confirm new password</Label><Input id="new-vault-confirm" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Recovering…" : "Recover and unlock"}</Button><Button type="button" variant="ghost" onClick={() => { setRecovering(false); setMessage(""); }}>Back to password</Button></form> : <form className="form-stack" onSubmit={unlock}><div><Label htmlFor="unlock-password">Vault master password</Label><Input id="unlock-password" type="password" autoFocus autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Unlocking…" : "Unlock vault"}</Button><Button type="button" variant="ghost" onClick={() => { setRecovering(true); setMessage(""); }}>Use recovery key</Button><Button type="button" variant="ghost" onClick={() => supabase!.auth.signOut()}>Use another account</Button></form>}</CardContent></Card></main>;
}

function VaultShell({ email, profile, rootKey, onLock }: { email: string; profile: CryptoProfile; rootKey: Uint8Array; onLock: () => void }) {
  const [view, setView] = useState<View>("home");
  const [workspaces, setWorkspaces] = useState<WorkspaceVault[]>([]);
  const [vault, setVault] = useState<WorkspaceVault | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [trash, setTrash] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<VaultFilter>("all");
  const [editor, setEditor] = useState<VaultItem | "new" | null>(null);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [history, setHistory] = useState<VaultHistoryEntry[] | null>(null);
  const [pendingLink, setPendingLink] = useState<InviteLink | null>(() => typeof window === "undefined" ? null : parseCollaborationLink(window.location.hash));
  const [accepting, setAccepting] = useState(false);
  const [entitlement, setEntitlement] = useState<Entitlement>({ plan_code: "free", ai_credits_remaining: 20, automation_runs_remaining: 50 });
  const initials = useMemo(() => email.slice(0, 2).toUpperCase(), [email]);

  async function refresh(openVault: WorkspaceVault) {
    const [active, deleted] = await Promise.all([listVaultItems(openVault), listVaultItems(openVault, { trash: true })]);
    setItems(active);
    setTrash(deleted);
    setSelected((current) => current ? [...active, ...deleted].find((item) => item.id === current.id) ?? null : null);
  }

  async function reloadWorkspaces(preferredId?: string) {
    const next = await listWorkspaceVaults(profile.identity_id, rootKey);
    setWorkspaces((previous) => {
      previous.forEach((entry) => entry.key.fill(0));
      return next;
    });
    const chosen = next.find((entry) => entry.workspaceId === (preferredId ?? vault?.workspaceId)) ?? next[0];
    setVault(chosen);
    await refresh(chosen);
    return chosen;
  }

  useEffect(() => {
    let active = true;
    let opened: WorkspaceVault[] = [];
    listWorkspaceVaults(profile.identity_id, rootKey).then(async (next) => {
      opened = next;
      if (!active) { next.forEach((entry) => entry.key.fill(0)); return; }
      setWorkspaces(next);
      setVault(next[0]);
      await refresh(next[0]);
    }).catch((reason) => { if (active) setError(reason instanceof Error ? reason.message : "Unable to open workspace."); })
      .finally(() => { if (active) setLoading(false); });
    supabase!.from("account_entitlements")
      .select("plan_code,ai_credits_remaining,automation_runs_remaining,phase2_preview_enabled")
      .maybeSingle().then(({ data }) => { if (active && data) setEntitlement(data as Entitlement); });
    return () => { active = false; opened.forEach((entry) => entry.key.fill(0)); };
  }, [profile.identity_id, rootKey]);

  async function switchWorkspace(workspaceId: string) {
    const next = workspaces.find((entry) => entry.workspaceId === workspaceId);
    if (!next) return;
    setLoading(true); setSelected(null); setFilter("all"); setQuery(""); setVault(next);
    try { await refresh(next); } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to switch workspace."); }
    finally { setLoading(false); }
  }

  async function acceptPendingLink() {
    if (!pendingLink) return;
    setAccepting(true); setError("");
    try {
      const workspaceId = pendingLink.kind === "invite"
        ? await acceptWorkspaceInvite(pendingLink, rootKey)
        : (await acceptAccessCapsule(pendingLink, rootKey), undefined);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      setPendingLink(null);
      if (workspaceId) { await reloadWorkspaces(workspaceId); setView("workspaces"); }
      else setView("inbox");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to accept this secure link."); }
    finally { setAccepting(false); }
  }

  const health = useMemo(() => passwordHealth(items), [items]);
  const visibleItems = useMemo(() => { const source = filter === "trash" ? trash : items; const normalized = query.trim().toLowerCase(); return source.filter((item) => { if (filter !== "all" && filter !== "trash" && filter !== "favorites" && filter !== "archive" && item.contentType !== filter) return false; if (filter === "favorites" && !item.payload.favorite) return false; if (filter === "archive" && !item.payload.archived) return false; if (filter !== "archive" && filter !== "trash" && item.payload.archived) return false; return !normalized || [item.payload.title, item.payload.username, item.payload.url, item.payload.notes, ...(item.payload.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)); }); }, [filter, items, query, trash]);
  async function saveItem(contentType: ItemKind, payload: VaultPayload) { if (!vault) return; if (editor === "new") await createVaultItem(vault, contentType, payload); else if (editor) await updateVaultItem(vault, editor, payload); await refresh(vault); setEditor(null); }
  async function removeItem(item: VaultItem) { if (!vault || !window.confirm(`Move “${item.payload.title}” to Trash?`)) return; try { await deleteVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to delete item."); } }
  async function restoreItem(item: VaultItem) { if (!vault) return; try { await restoreVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to restore item."); } }
  async function toggle(item: VaultItem, key: "favorite" | "archived") { if (!vault) return; await updateVaultItem(vault, item, { ...item.payload, [key]: !item.payload[key], updatedAt: new Date().toISOString() }); await refresh(vault); }
  async function showHistory(item: VaultItem) { if (vault) setHistory(await listVaultItemHistory(vault, item)); }
  function openVault(filterValue: VaultFilter = "all") { setFilter(filterValue); setView("vault"); setSelected(null); }
  function lockVault() { workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); onLock(); }
  async function signOut() { workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); await supabase!.auth.signOut(); }
  const planLabel = entitlement.phase2_preview_enabled ? "Phase 2 preview" : entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1);
  return <main className="vault-app">
    <aside className="vault-sidebar"><Brand /><nav>{NAV.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${view === id ? "active" : ""}`} onClick={() => { setView(id); setSelected(null); }}><Icon /> {label}{id === "vault" && <span>{items.length}</span>}</button>)}</nav><div className="plan-chip"><Sparkles /><div><strong>{planLabel}</strong><span>{entitlement.ai_credits_remaining} private AI credits</span></div></div><div className="sidebar-account"><div className="avatar">{initials}</div><div><strong>{email.split("@")[0]}</strong><span>{vault?.name ?? "Opening workspace"}</span></div><MoreHorizontal /></div></aside>
    <section className="vault-content"><header><div><p className="eyebrow">Passkey-X / {vault?.suite ?? "Personal"}</p><h1>{view === "home" ? "Good to see you" : NAV.find((entry) => entry.id === view)?.label}</h1></div><div className="header-actions">{workspaces.length > 0 && <select className="workspace-switcher" aria-label="Current workspace" value={vault?.workspaceId ?? ""} onChange={(event) => void switchWorkspace(event.target.value)}>{workspaces.map((entry) => <option key={entry.workspaceId} value={entry.workspaceId}>{entry.name}</option>)}</select>}<Button variant="outline" onClick={lockVault}><LockKeyhole /> Lock</Button><Button variant="ghost" size="icon" aria-label="Sign out" onClick={() => void signOut()}><LogOut /></Button></div></header>
      {error && <div className="vault-error" role="alert">{error}<button aria-label="Dismiss" onClick={() => setError("")}><X /></button></div>}
      {pendingLink && <div className="secure-link-banner"><span className="feature-icon">{pendingLink.kind === "invite" ? <UserPlus /> : <Share2 />}</span><div><strong>{pendingLink.kind === "invite" ? "Workspace invitation" : "Access Capsule"}</strong><p>This link is addressed to your verified email. Its 256-bit secret stayed in the URL fragment and was not sent to the server.</p></div><Button disabled={accepting} onClick={() => void acceptPendingLink()}>{accepting ? "Accepting…" : "Review and accept"}</Button></div>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /><p>Decrypting your workspace on this device…</p></div> : <>
        {view === "home" && <Dashboard items={items} trash={trash} health={health} entitlement={entitlement} onOpenVault={openVault} onNew={() => { setEditor("new"); setView("vault"); }} />}
        {view === "vault" && vault && <VaultView vault={vault} items={visibleItems} allItems={items} trash={trash} filter={filter} query={query} selected={selected} revealed={revealed} onQuery={setQuery} onFilter={setFilter} onNew={() => setEditor("new")} onSelect={(item) => { setSelected(item); setRevealed(false); setHistory(null); }} onReveal={() => setRevealed(!revealed)} onClose={() => setSelected(null)} onEdit={(item) => setEditor(item)} onDelete={removeItem} onRestore={restoreItem} onToggle={toggle} onHistory={showHistory} />}
        {view === "workspaces" && vault && <WorkspacesView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} workspaces={workspaces} vault={vault} onSelect={switchWorkspace} onReload={reloadWorkspaces} />}
        {view === "missions" && vault && <MissionsView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "sharing" && vault && <SharingView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "inbox" && vault && <AccessInboxView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} vault={vault} items={items} />}
        {view === "security" && <SecurityView health={health} items={items} onOpen={(id) => { const item = items.find((candidate) => candidate.id === id); if (item) { setView("vault"); setSelected(item); } }} />}
        {view === "account-security" && <AccountSecurityView />}
        {view === "generator" && <GeneratorView />}
        {view === "automations" && <AutomationsView entitlement={entitlement} />}
        {view === "devices" && <DevicesView identityId={profile.identity_id} />}
        {view === "settings" && vault && <SettingsView email={email} items={items} vault={vault} profile={profile} entitlement={entitlement} onImported={() => refresh(vault)} />}
      </>}
    </section>
    {editor && <ItemEditor item={editor === "new" ? undefined : editor} onClose={() => setEditor(null)} onSave={saveItem} />}
    {history && selected && <HistoryDialog item={selected} history={history} onClose={() => setHistory(null)} />}
  </main>;
}

function Dashboard({ items, trash, health, entitlement, onOpenVault, onNew }: { items: VaultItem[]; trash: VaultItem[]; health: ReturnType<typeof passwordHealth>; entitlement: Entitlement; onOpenVault: (filter?: VaultFilter) => void; onNew: () => void }) {
  const recent = items.slice(0, 4);
  return <div className="dashboard"><section className="welcome-card"><div><span className="status-pill"><ShieldCheck /> Vault protected</span><h2>Your digital life, under your control.</h2><p>Every item is encrypted before it leaves this device. Search and security checks happen locally.</p><div className="welcome-actions"><Button onClick={onNew}><Plus /> Add secure item</Button><Button variant="outline" onClick={() => onOpenVault()}>Open vault <ChevronRight /></Button></div></div><Image src="/brand/passkey-x-mark.png" alt="" width={220} height={220} /></section><div className="metric-grid"><Metric icon={Vault} label="Protected items" value={items.length} detail={`${trash.length} in trash`} onClick={() => onOpenVault()} /><Metric icon={CircleGauge} label="Security score" value={`${health.score}%`} detail={`${health.findings.filter((finding) => finding.severity !== "good").length} findings`} /><Metric icon={Bot} label="Automation runs" value={entitlement.automation_runs_remaining} detail="remaining this month" /><Metric icon={Laptop} label="Device limit" value={entitlement.plan_code === "free" ? "2" : "∞"} detail={`${entitlement.plan_code} plan`} /></div><div className="dashboard-columns"><Card><CardHeader><div><CardTitle>Recently updated</CardTitle><CardDescription>Decrypted only on this device</CardDescription></div><Button variant="ghost" onClick={() => onOpenVault()}>View all</Button></CardHeader><CardContent>{recent.length ? <div className="recent-list">{recent.map((item) => { const Icon = ITEM_TYPES[item.contentType].icon; return <button key={item.id} onClick={() => onOpenVault(item.contentType)}><span className="item-kind-icon"><Icon /></span><span><strong>{item.payload.title}</strong><small>{ITEM_TYPES[item.contentType].label}</small></span><ChevronRight /></button>; })}</div> : <div className="small-empty"><Vault /><strong>Your vault is ready</strong><span>Add your first password, passkey, note, or credential.</span></div>}</CardContent></Card><SponsorCard /></div></div>;
}

function Metric({ icon: Icon, label, value, detail, onClick }: { icon: typeof Vault; label: string; value: string | number; detail: string; onClick?: () => void }) { return <button className="metric-card" onClick={onClick}><span className="metric-icon"><Icon /></span><span><small>{label}</small><strong>{value}</strong><em>{detail}</em></span></button>; }
function SponsorCard() { return <Card className="sponsor-card"><CardHeader><div className="sponsor-label">Passkey-X sponsor · privacy safe</div><CardTitle>Safer accounts start with MFA</CardTitle><CardDescription>This first-party educational card is not selected from vault contents. No third-party script or tracker runs here.</CardDescription></CardHeader><CardContent><Button variant="outline">Read the security guide</Button><p>Sponsored cards only appear on Home for Free accounts.</p></CardContent></Card>; }

function WorkspacesView({ identityId, rootKey, workspaces, vault, onSelect, onReload }: {
  identityId: string; rootKey: Uint8Array; workspaces: WorkspaceVault[]; vault: WorkspaceVault;
  onSelect: (id: string) => Promise<void>; onReload: (id?: string) => Promise<WorkspaceVault>;
}) {
  const [name, setName] = useState("");
  const [suite, setSuite] = useState<WorkspaceSuite>("team");
  const [recipient, setRecipient] = useState("");
  const [role, setRole] = useState<WorkspaceRole>("viewer");
  const [expiresDays, setExpiresDays] = useState(7);
  const [shareLink, setShareLink] = useState("");
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [invites, setInvites] = useState<WorkspaceInvite[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function refreshLists(current = vault) {
    const [nextMembers, nextInvites] = await Promise.all([listWorkspaceMembers(current), listWorkspaceInvites(current)]);
    setMembers(nextMembers); setInvites(nextInvites);
  }
  useEffect(() => { let active = true; Promise.all([listWorkspaceMembers(vault), listWorkspaceInvites(vault)]).then(([nextMembers, nextInvites]) => { if (active) { setMembers(nextMembers); setInvites(nextInvites); } }).catch((reason) => { if (active) setMessage(reason instanceof Error ? reason.message : "Unable to load collaboration details."); }); return () => { active = false; }; }, [vault]);

  async function createWorkspace(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const created = await createSharedWorkspace(identityId, rootKey, name, suite);
      await onReload(created.workspaceId); setName(""); setMessage(`${created.name} is ready.`);
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to create workspace."); }
    finally { setBusy(false); }
  }
  async function invite(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage(""); setShareLink("");
    try {
      const link = await createWorkspaceInvite(vault, recipient, role, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), window.location.origin);
      setShareLink(link); setRecipient(""); await refreshLists();
    } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to create invitation."); }
    finally { setBusy(false); }
  }
  async function revokeMember(member: WorkspaceMember) {
    if (!window.confirm("Revoke this member now? Future server access ends immediately and the workspace will be marked for key rotation.")) return;
    setBusy(true); setMessage("");
    try { await revokeWorkspaceMember(vault, member.identityId); await onReload(vault.workspaceId); setMessage("Member revoked. Cryptographic key rotation is now required."); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to revoke member."); }
    finally { setBusy(false); }
  }
  async function revokeInvite(inviteRow: WorkspaceInvite) {
    setBusy(true); setMessage("");
    try { await revokeWorkspaceInvite(inviteRow.id); await refreshLists(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to revoke invitation."); }
    finally { setBusy(false); }
  }

  const canManage = vault.role === "owner" || vault.role === "manager";
  return <div className="feature-page phase2-page">
    <div className="feature-intro"><div><span className="status-pill"><Users /> Encrypted collaboration</span><h2>One account, isolated workspaces</h2><p>Family, client and team workspace names and keys are encrypted in this browser. Invitations release a wrapped key only after the exact email is verified.</p></div><div className="credit-meter"><span>Workspaces</span><strong>{workspaces.length}</strong><small>active</small></div></div>
    <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Your workspaces</CardTitle><CardDescription>Switching changes which client-side key is active.</CardDescription></CardHeader><CardContent><div className="workspace-list">{workspaces.map((entry) => <button key={entry.workspaceId} className={entry.workspaceId === vault.workspaceId ? "active" : ""} onClick={() => void onSelect(entry.workspaceId)}><span className="feature-icon">{entry.suite === "professional" ? <BriefcaseBusiness /> : <Users />}</span><span><strong>{entry.name}</strong><small>{entry.suite} · {entry.role}</small></span>{entry.keyRotationRequired ? <ShieldAlert /> : <ChevronRight />}</button>)}</div></CardContent></Card>
      <Card><CardHeader><CardTitle>Create a workspace</CardTitle><CardDescription>For a household, client engagement or small team.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={createWorkspace}><div><Label htmlFor="workspace-name">Encrypted name</Label><Input id="workspace-name" required minLength={2} value={name} onChange={(event) => setName(event.target.value)} placeholder="Client Aurora" /></div><div><Label htmlFor="workspace-suite">Suite</Label><select id="workspace-suite" value={suite} onChange={(event) => setSuite(event.target.value as WorkspaceSuite)}><option value="family">Family</option><option value="professional">Professional / client</option><option value="team">Team</option></select></div><Button disabled={busy}>{busy ? "Creating…" : "Create encrypted workspace"}</Button></form></CardContent></Card>
    </div>
    {vault.keyRotationRequired && <div className="rotation-warning"><ShieldAlert /><div><strong>Workspace key rotation required</strong><p>A member was revoked. Their server access and envelopes are disabled. Because a device may have retained a previously decrypted value, move sensitive credentials into a freshly keyed workspace before future use.</p></div></div>}
    {vault.suite !== "personal" && <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Invite a verified member</CardTitle><CardDescription>The full link contains a 256-bit secret in its fragment. Send it through a trusted channel.</CardDescription></CardHeader><CardContent>{canManage ? <form className="form-stack" onSubmit={invite}><div><Label htmlFor="invite-email">Recipient email</Label><Input id="invite-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="invite-role">Role</Label><select id="invite-role" value={role} onChange={(event) => setRole(event.target.value as WorkspaceRole)}><option value="manager">Manager</option><option value="editor">Member / editor</option><option value="viewer">Guest / viewer</option></select></div><div><Label htmlFor="invite-expiry">Expires</Label><select id="invite-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div></div><Button disabled={busy}><UserPlus /> {busy ? "Creating…" : "Create secure invitation"}</Button></form> : <p className="field-hint">Only workspace owners and managers can invite members.</p>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} /><small>Passkey-X stores only its verifier. The secret cannot be recovered later.</small></div>}</CardContent></Card>
      <Card><CardHeader><CardTitle>People and invitations</CardTitle><CardDescription>Roles are enforced by row-level authorization on every request.</CardDescription></CardHeader><CardContent><div className="member-list">{members.map((member) => <article key={member.identityId}><span className="avatar">{member.role.slice(0, 1).toUpperCase()}</span><div><strong>{member.identityId === identityId ? "You" : `Member ${member.identityId.slice(0, 8)}`}</strong><small>{member.role} · {member.status}</small></div>{canManage && member.role !== "owner" && member.status === "active" && <Button variant="ghost" disabled={busy} onClick={() => void revokeMember(member)}>Revoke</Button>}</article>)}{invites.map((inviteRow) => <article key={inviteRow.id}><span className="feature-icon"><Send /></span><div><strong>Invitation {inviteRow.id.slice(0, 8)}</strong><small>{inviteRow.role} · {inviteRow.status} · expires {new Date(inviteRow.expiresAt).toLocaleDateString()}</small></div>{canManage && ["pending","accepted"].includes(inviteRow.status) && <Button variant="ghost" disabled={busy} onClick={() => void revokeInvite(inviteRow)}>Revoke</Button>}</article>)}</div></CardContent></Card>
    </div>}
    {message && <p className="settings-message" role="status">{message}</p>}
  </div>;
}

function SharingView({ vault, items }: { vault: WorkspaceVault; items: VaultItem[] }) {
  const [itemId, setItemId] = useState(items[0]?.id ?? "");
  const [recipient, setRecipient] = useState("");
  const [policy, setPolicy] = useState<"reveal" | "fill_only">("fill_only");
  const [purpose, setPurpose] = useState("support");
  const [expiresDays, setExpiresDays] = useState(1);
  const [oneTime, setOneTime] = useState(true);
  const [sent, setSent] = useState<SentCapsule[]>([]);
  const [shareLink, setShareLink] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { setSent(await listSentCapsules(vault)); }
  useEffect(() => { let active = true; listSentCapsules(vault).then((next) => { if (active) setSent(next); }).catch((reason) => { if (active) setMessage(reason instanceof Error ? reason.message : "Unable to load shares."); }); return () => { active = false; }; }, [vault]);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); const item = items.find((candidate) => candidate.id === itemId); if (!item) return;
    setBusy(true); setMessage(""); setShareLink("");
    try { setShareLink(await createAccessCapsule(vault, item, recipient, policy, purpose, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), oneTime ? 1 : 0, window.location.origin)); setRecipient(""); await refresh(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to create Access Capsule."); }
    finally { setBusy(false); }
  }
  async function revoke(capsule: SentCapsule) { if (!window.confirm("Revoke this Access Capsule?")) return; setBusy(true); try { await revokeAccessCapsule(capsule.id); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to revoke capsule."); } finally { setBusy(false); } }
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Share2 /> Access Capsule</span><h2>Share a purpose, not a copied password</h2><p>Passkey-X encrypts a snapshot with a fresh share key. Email verification, expiry, usage limits and revocation control future delivery.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Create Access Capsule</CardTitle><CardDescription>No plaintext credential is placed in the link, database, audit record or email.</CardDescription></CardHeader><CardContent>{items.length ? <form className="form-stack" onSubmit={submit}><div><Label htmlFor="share-item">Item</Label><select id="share-item" value={itemId} onChange={(event) => setItemId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div><Label htmlFor="share-email">Verified recipient email</Label><Input id="share-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="share-policy">Reveal policy</Label><select id="share-policy" value={policy} onChange={(event) => setPolicy(event.target.value as "reveal" | "fill_only")}><option value="fill_only">Fill-only / no reveal</option><option value="reveal">Reveal allowed</option></select></div><div><Label htmlFor="share-purpose">Purpose</Label><select id="share-purpose" value={purpose} onChange={(event) => setPurpose(event.target.value)}><option value="family">Family</option><option value="client">Client</option><option value="project">Project</option><option value="support">Support</option><option value="handover">Handover</option><option value="other">Other</option></select></div></div><div className="inline-fields"><div><Label htmlFor="share-expiry">Expires</Label><select id="share-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div><label className="check-row"><input type="checkbox" checked={oneTime} onChange={(event) => setOneTime(event.target.checked)} /> One-time use</label></div><Button disabled={busy}><Send /> {busy ? "Encrypting…" : "Create secure link"}</Button></form> : <div className="small-empty"><Vault /><strong>Add an item first</strong><span>Access Capsules are encrypted snapshots of an existing item.</span></div>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} /><small>The fragment secret is shown only once.</small></div>}</CardContent></Card><Card><CardHeader><CardTitle>Sent capsules</CardTitle><CardDescription>Revocation stops future server delivery. It cannot erase knowledge already captured by a recipient device.</CardDescription></CardHeader><CardContent><div className="member-list">{sent.length ? sent.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{items.find((item) => item.id === capsule.itemId)?.payload.title ?? "Encrypted item"}</strong><small>{capsule.revealPolicy.replace("_", "-")} · {capsule.status} · {capsule.maxUses ? `${capsule.useCount}/${capsule.maxUses} uses` : "unlimited uses"}</small></div>{["pending","accepted"].includes(capsule.status) && <Button variant="ghost" disabled={busy} onClick={() => void revoke(capsule)}>Revoke</Button>}</article>) : <div className="small-empty"><Send /><strong>No active shares</strong><span>Created capsules will appear here.</span></div>}</div></CardContent></Card></div>{policy === "fill_only" && <div className="rotation-warning neutral"><ShieldAlert /><div><strong>Fill-only is not DRM</strong><p>Passkey-X hides the value in its normal interface, but a compromised recipient device or target website may still capture a filled credential.</p></div></div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

function MissionsView({ vault, items }: { vault: WorkspaceVault; items: VaultItem[] }) {
  const [missions, setMissions] = useState<Mission[]>([]);
  const [title, setTitle] = useState("");
  const [duration, setDuration] = useState(60);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [active, setActive] = useState<Mission | null>(null);
  const [activeExpiresAt, setActiveExpiresAt] = useState<Date | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { setMissions(await listMissions(vault)); }
  useEffect(() => { let mounted = true; listMissions(vault).then((next) => { if (mounted) setMissions(next); }).catch((reason) => { if (mounted) setMessage(reason instanceof Error ? reason.message : "Unable to load Missions."); }); return () => { mounted = false; }; }, [vault]);
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createMission(vault, title, selectedIds, duration); setTitle(""); setSelectedIds([]); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to create Mission."); } finally { setBusy(false); } }
  async function run(mission: Mission) { setBusy(true); setMessage(""); try { const expiresAt = await startMission(vault, mission); setActive(mission); setActiveExpiresAt(new Date(expiresAt)); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to start Mission."); } finally { setBusy(false); } }
  function openSite(item: VaultItem) { try { const url = new URL(item.payload.url ?? ""); if (!["http:","https:"].includes(url.protocol)) throw new Error(); window.open(url.href, "_blank", "noopener,noreferrer"); } catch { setMessage("This item does not have a safe HTTP or HTTPS address."); } }
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><FolderKanban /> Mission Mode</span><h2>Open only what the task needs</h2><p>A Mission is an encrypted task definition with an explicit item set and a timeboxed run. It does not grant access outside this workspace.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Build a Mission</CardTitle><CardDescription>Choose the minimum credentials needed for one task.</CardDescription></CardHeader><CardContent>{items.length ? <form className="form-stack" onSubmit={submit}><div><Label htmlFor="mission-title">Encrypted Mission name</Label><Input id="mission-title" required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Client Aurora support" /></div><div><Label htmlFor="mission-duration">Run duration</Label><select id="mission-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={480}>8 hours</option></select></div><fieldset className="item-checklist"><legend>Allowed items</legend>{items.map((item) => <label key={item.id}><input type="checkbox" checked={selectedIds.includes(item.id)} onChange={(event) => setSelectedIds(event.target.checked ? [...selectedIds, item.id] : selectedIds.filter((id) => id !== item.id))} /><span><strong>{item.payload.title}</strong><small>{item.payload.url || ITEM_TYPES[item.contentType].label}</small></span></label>)}</fieldset><Button disabled={busy || selectedIds.length === 0}><Plus /> Create Mission</Button></form> : <div className="small-empty"><FolderKanban /><strong>No items available</strong><span>Add credentials before building a Mission.</span></div>}</CardContent></Card><Card><CardHeader><CardTitle>Saved Missions</CardTitle><CardDescription>Definitions decrypt only after this workspace unlocks.</CardDescription></CardHeader><CardContent><div className="mission-list">{missions.length ? missions.map((mission) => <article key={mission.id} className={active?.id === mission.id ? "active" : ""}><div><strong>{mission.title}</strong><small>{mission.itemIds.length} items · {mission.durationMinutes} minutes</small></div><Button variant="outline" disabled={busy} onClick={() => void run(mission)}><Play /> Start</Button>{active?.id === mission.id && activeExpiresAt && <div className="mission-run"><span><Clock3 /> Active until {activeExpiresAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>{mission.itemIds.map((id) => { const item = items.find((candidate) => candidate.id === id); return item ? <button key={id} onClick={() => openSite(item)}>{item.payload.title}<ChevronRight /></button> : null; })}</div>}</article>) : <div className="small-empty"><Play /><strong>No Missions yet</strong><span>Your encrypted task launchers will appear here.</span></div>}</div></CardContent></Card></div>{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

function AccessInboxView({ identityId, rootKey, vault, items }: { identityId: string; rootKey: Uint8Array; vault: WorkspaceVault; items: VaultItem[] }) {
  const [capsules, setCapsules] = useState<ReceivedCapsule[]>([]);
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [opened, setOpened] = useState<ReceivedCapsule | null>(null);
  const [scope, setScope] = useState<AccessRequest["requestedScope"]>("reveal");
  const [itemId, setItemId] = useState(items[0]?.id ?? "");
  const [purpose, setPurpose] = useState("");
  const [duration, setDuration] = useState(60);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { const [nextCapsules, nextRequests] = await Promise.all([listReceivedCapsules(identityId, rootKey), listAccessRequests(vault)]); setCapsules(nextCapsules); setRequests(nextRequests); }
  useEffect(() => { let active = true; Promise.all([listReceivedCapsules(identityId, rootKey), listAccessRequests(vault)]).then(([nextCapsules, nextRequests]) => { if (active) { setCapsules(nextCapsules); setRequests(nextRequests); } }).catch((reason) => { if (active) setMessage(reason instanceof Error ? reason.message : "Unable to load access inbox."); }); return () => { active = false; }; }, [identityId, rootKey, vault]);
  async function openCapsule(capsule: ReceivedCapsule) { setBusy(true); setMessage(""); try { await consumeAccessCapsule(capsule.id); setOpened(capsule); setCapsules((current) => current.filter((entry) => entry.id !== capsule.id)); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Capsule is no longer available."); } finally { setBusy(false); } }
  async function request(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createAccessRequest(vault, itemId || null, scope, purpose, duration); setPurpose(""); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to request access."); } finally { setBusy(false); } }
  async function decide(row: AccessRequest, decision: "approved" | "denied") { setBusy(true); setMessage(""); try { await decideAccessRequest(row.id, decision); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to record decision."); } finally { setBusy(false); } }
  const canApprove = vault.role === "owner" || vault.role === "manager";
  const canRequest = vault.role !== "owner";
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Inbox /> Access inbox</span><h2>Timeboxed access with a clear decision trail</h2><p>Purposes are encrypted with the workspace key. Decisions and expiry remain visible as authorization metadata and audit evidence.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Received Access Capsules</CardTitle><CardDescription>Opening records a use. Fill-only entries never expose the secret in this interface.</CardDescription></CardHeader><CardContent><div className="member-list">{capsules.length ? capsules.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{capsule.payload.title}</strong><small>{capsule.revealPolicy.replace("_", "-")} · expires {new Date(capsule.expiresAt).toLocaleString()}</small></div><Button variant="outline" disabled={busy} onClick={() => void openCapsule(capsule)}>Open</Button></article>) : <div className="small-empty"><Inbox /><strong>Inbox is clear</strong><span>Accepted capsules that are still valid appear here.</span></div>}</div></CardContent></Card><Card><CardHeader><CardTitle>{canRequest ? "Request temporary access" : "Pending approvals"}</CardTitle><CardDescription>{canRequest ? "Ask an owner or manager for an attributable, expiring scope." : "Review requests without exposing their vault contents."}</CardDescription></CardHeader><CardContent>{canRequest && <form className="form-stack" onSubmit={request}><div><Label htmlFor="request-item">Resource</Label><select id="request-item" value={itemId} onChange={(event) => setItemId(event.target.value)}><option value="">Whole workspace</option>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div className="inline-fields"><div><Label htmlFor="request-scope">Scope</Label><select id="request-scope" value={scope} onChange={(event) => setScope(event.target.value as AccessRequest["requestedScope"])}><option value="use">Use</option><option value="reveal">Reveal</option><option value="edit">Edit</option>{vault.role === "manager" && <option value="manage">Manage</option>}</select></div><div><Label htmlFor="request-duration">Duration</Label><select id="request-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={480}>8 hours</option></select></div></div><div><Label htmlFor="request-purpose">Encrypted purpose</Label><textarea id="request-purpose" required rows={3} value={purpose} onChange={(event) => setPurpose(event.target.value)} placeholder="Why this access is needed" /></div><Button disabled={busy}><Send /> Submit request</Button></form>}<div className="request-list">{requests.map((row) => <article key={row.id}><div><strong>{row.requestedScope} for {row.itemId ? items.find((item) => item.id === row.itemId)?.payload.title ?? "item" : "workspace"}</strong><p>{row.purpose}</p><small>{row.status} · {row.durationMinutes} minutes · requester {row.requesterIdentityId.slice(0, 8)}</small></div>{canApprove && row.status === "pending" && <div><Button disabled={busy} onClick={() => void decide(row, "approved")}><Check /> Approve</Button><Button variant="outline" disabled={busy} onClick={() => void decide(row, "denied")}><X /> Deny</Button></div>}</article>)}</div></CardContent></Card></div>{opened && <div className="capsule-open"><div className="detail-heading"><div><span>{opened.revealPolicy.replace("_", "-")}</span><h2>{opened.payload.title}</h2></div><button aria-label="Close capsule" onClick={() => setOpened(null)}><X /></button></div>{opened.payload.username && <DetailField label="Username" value={opened.payload.username} copyable={opened.revealPolicy === "reveal"} />}{opened.revealPolicy === "reveal" && opened.payload.secret && <DetailField label="Shared secret" value={opened.payload.secret} copyable />}{opened.payload.url && <DetailField label="Website" value={opened.payload.url} copyable />}{opened.revealPolicy === "fill_only" && <div className="rotation-warning neutral"><ShieldCheck /><div><strong>Fill-only policy active</strong><p>The secret is intentionally hidden here. Use the trusted Passkey-X extension to fill it at the matching site. A compromised endpoint can still capture a filled value.</p></div></div>}</div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

function VaultView({ vault, items, allItems, trash, filter, query, selected, revealed, onQuery, onFilter, onNew, onSelect, onReveal, onClose, onEdit, onDelete, onRestore, onToggle, onHistory }: { vault: WorkspaceVault; items: VaultItem[]; allItems: VaultItem[]; trash: VaultItem[]; filter: VaultFilter; query: string; selected: VaultItem | null; revealed: boolean; onQuery: (value: string) => void; onFilter: (value: VaultFilter) => void; onNew: () => void; onSelect: (item: VaultItem) => void; onReveal: () => void; onClose: () => void; onEdit: (item: VaultItem) => void; onDelete: (item: VaultItem) => void; onRestore: (item: VaultItem) => void; onToggle: (item: VaultItem, key: "favorite" | "archived") => void; onHistory: (item: VaultItem) => void }) {
  return <div className="vault-view"><div className="vault-toolbar"><div className="search-box"><Search /><input aria-label="Search vault" placeholder="Search locally in your decrypted vault" value={query} onChange={(event) => onQuery(event.target.value)} /></div><Button onClick={onNew}><Plus /> New item</Button></div><div className="filter-strip"><button className={filter === "all" ? "active" : ""} onClick={() => onFilter("all")}>All <span>{allItems.filter((item) => !item.payload.archived).length}</span></button><button className={filter === "favorites" ? "active" : ""} onClick={() => onFilter("favorites")}><Star /> Favorites</button><button className={filter === "archive" ? "active" : ""} onClick={() => onFilter("archive")}><Archive /> Archive</button><button className={filter === "trash" ? "active" : ""} onClick={() => onFilter("trash")}><Trash2 /> Trash <span>{trash.length}</span></button><select aria-label="Filter item type" value={(filter in ITEM_TYPES) ? filter : "all"} onChange={(event) => onFilter(event.target.value as VaultFilter)}><option value="all">All item types</option>{(Object.keys(ITEM_TYPES) as ItemKind[]).map((kind) => <option key={kind} value={kind}>{ITEM_TYPES[kind].plural}</option>)}</select></div>{items.length === 0 ? <div className="empty-vault"><div className="empty-icon"><Vault /></div><h2>{query ? "No matching items" : filter === "trash" ? "Trash is empty" : "Nothing here yet"}</h2><p>{query ? "Try another search or filter." : "Add a protected item. Its contents will be encrypted before syncing."}</p>{filter !== "trash" && <Button onClick={onNew}><Plus /> Add secure item</Button>}</div> : <div className={`items-layout ${selected ? "with-detail" : ""}`}><div className="item-list">{items.map((item) => { const Icon = ITEM_TYPES[item.contentType].icon; return <button key={item.id} className={`item-row ${selected?.id === item.id ? "selected" : ""}`} onClick={() => onSelect(item)}><span className="item-kind-icon"><Icon /></span><span className="item-summary"><strong>{item.payload.title}</strong><small>{item.payload.username || item.payload.url || ITEM_TYPES[item.contentType].label}</small></span><span className="item-badges">{item.payload.favorite && <Star />}{item.payload.archived && <Archive />}<span>{ITEM_TYPES[item.contentType].label}</span></span></button>; })}</div>{selected && <aside className="item-detail"><div className="detail-heading"><div><span>{ITEM_TYPES[selected.contentType].label}</span><h2>{selected.payload.title}</h2></div><button aria-label="Close details" onClick={onClose}><X /></button></div>{selected.payload.username && <DetailField label={ITEM_TYPES[selected.contentType].userLabel ?? "Username"} value={selected.payload.username} copyable />}{selected.payload.secret && <div className="detail-field"><span>{ITEM_TYPES[selected.contentType].secretLabel ?? "Secret"}</span><div><code>{revealed ? selected.payload.secret : "••••••••••••"}</code><button aria-label={revealed ? "Hide secret" : "Reveal secret"} onClick={onReveal}>{revealed ? <EyeOff /> : <Eye />}</button><CopyButton value={selected.payload.secret} /></div></div>}{selected.payload.url && <DetailField label="Website" value={selected.payload.url} copyable />}{selected.payload.notes && <DetailField label="Notes" value={selected.payload.notes} />}{selected.payload.tags?.length ? <DetailField label="Tags" value={selected.payload.tags.join(", ")} /> : null}{!selected.deletedAt && <AttachmentPanel vault={vault} item={selected} />}<div className="detail-meta"><span>Revision {selected.revision}</span><span>Updated {new Date(selected.payload.updatedAt).toLocaleDateString()}</span></div><div className="detail-actions">{selected.deletedAt ? <Button onClick={() => onRestore(selected)}><RefreshCw /> Restore</Button> : <><Button variant="outline" onClick={() => onEdit(selected)}><Pencil /> Edit</Button><Button variant="ghost" aria-label="Toggle favorite" onClick={() => onToggle(selected, "favorite")}><Heart className={selected.payload.favorite ? "filled" : ""} /></Button><Button variant="ghost" aria-label="Toggle archive" onClick={() => onToggle(selected, "archived")}><Archive /></Button><Button variant="ghost" aria-label="View history" onClick={() => onHistory(selected)}><History /></Button><Button variant="ghost" className="danger-button" onClick={() => onDelete(selected)}><Trash2 /></Button></>}</div></aside>}</div>}</div>;
}

function AttachmentPanel({ vault, item }: { vault: WorkspaceVault; item: VaultItem }) {
  const [attachments, setAttachments] = useState<VaultAttachment[]>([]); const [busy, setBusy] = useState(false); const [message, setMessage] = useState("");
  async function refresh() { try { setAttachments(await listEncryptedAttachments(vault, item.id)); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to load attachments."); } }
  useEffect(() => { let active = true; listEncryptedAttachments(vault, item.id).then((next) => { if (active) setAttachments(next); }).catch((reason) => { if (active) setMessage(reason instanceof Error ? reason.message : "Unable to load attachments."); }); return () => { active = false; }; }, [item.id, vault]);
  async function upload(file: File) { setBusy(true); setMessage(""); try { await uploadEncryptedAttachment(vault, item.id, file); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Attachment upload failed."); } finally { setBusy(false); } }
  return <div className="attachment-panel"><span>Encrypted attachments</span>{attachments.map((attachment) => <button key={attachment.id} onClick={() => void downloadEncryptedAttachment(vault, attachment)}><Paperclip /><span>{attachment.name}</span><small>{Math.max(1, Math.round(attachment.size / 1024))} KB</small><Download /></button>)}<label><Paperclip /><span>{busy ? "Encrypting…" : "Add attachment"}</span><input type="file" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.target.value = ""; }} /></label>{message && <small className="attachment-error">{message}</small>}</div>;
}

function DetailField({ label, value, copyable = false }: { label: string; value: string; copyable?: boolean }) { return <div className="detail-field"><span>{label}</span><div><p>{value}</p>{copyable && <CopyButton value={value} />}</div></div>; }
function CopyButton({ value }: { value: string }) { const [copied, setCopied] = useState(false); return <button aria-label="Copy" onClick={async () => { await navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => { setCopied(false); navigator.clipboard.readText().then((current) => { if (current === value) navigator.clipboard.writeText(""); }).catch(() => undefined); }, 30_000); }}>{copied ? <ShieldCheck /> : <Copy />}</button>; }

function SecurityView({ health, items, onOpen }: { health: ReturnType<typeof passwordHealth>; items: VaultItem[]; onOpen: (id: string) => void }) {
  const passkeys = items.filter((item) => item.contentType === "passkey").length;
  return <div className="feature-page"><section className="score-hero"><div className="score-ring" style={{ "--score": `${health.score * 3.6}deg` } as React.CSSProperties}><div><strong>{health.score}</strong><span>/ 100</span></div></div><div><span className="status-pill"><ShieldCheck /> Local analysis</span><h2>{health.score >= 80 ? "Your vault is in good shape" : "There are risks worth fixing"}</h2><p>Passwords are evaluated in memory on this device. No password, URL, or username is sent for scoring.</p></div></section><div className="security-stats"><Metric icon={KeyRound} label="Login passwords" value={health.loginCount} detail="checked locally" /><Metric icon={Fingerprint} label="Passkey references" value={passkeys} detail="passwordless accounts" /><Metric icon={ShieldAlert} label="Open findings" value={health.findings.filter((finding) => finding.severity !== "good").length} detail="prioritized below" /></div><Card><CardHeader><CardTitle>Security findings</CardTitle><CardDescription>Passkey-X never sends vault content to a breach or analytics service.</CardDescription></CardHeader><CardContent><div className="finding-list">{health.findings.map((finding) => <article key={finding.id} className={`finding ${finding.severity}`}><span>{finding.severity === "good" ? <ShieldCheck /> : <ShieldAlert />}</span><div><strong>{finding.title}</strong><p>{finding.detail}</p>{finding.itemIds.slice(0, 3).map((id) => <button key={id} onClick={() => onOpen(id)}>{items.find((item) => item.id === id)?.payload.title ?? "Review item"} <ChevronRight /></button>)}</div></article>)}</div></CardContent></Card></div>;
}

function GeneratorView() {
  const [mode, setMode] = useState<"password" | "passphrase">("password"); const [length, setLength] = useState(24); const [value, setValue] = useState(() => generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); const [options, setOptions] = useState({ uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true });
  function regenerate() { setValue(mode === "password" ? generatePassword({ length, ...options }) : generatePassphrase(5)); }
  return <div className="feature-page narrow-page"><Card className="generator-card"><CardHeader><span className="feature-icon"><WandSparkles /></span><CardTitle>Private password generator</CardTitle><CardDescription>Generated with the browser cryptographic random-number generator. Values never leave this device.</CardDescription></CardHeader><CardContent><div className="segmented"><button className={mode === "password" ? "active" : ""} onClick={() => { setMode("password"); setValue(generatePassword({ length, ...options })); }}>Password</button><button className={mode === "passphrase" ? "active" : ""} onClick={() => { setMode("passphrase"); setValue(generatePassphrase(5)); }}>Passphrase</button></div><div className="generated-value"><code>{value}</code><CopyButton value={value} /><button aria-label="Generate another" onClick={regenerate}><RefreshCw /></button></div>{mode === "password" && <><div className="range-row"><Label htmlFor="password-length">Length</Label><strong>{length}</strong><input id="password-length" type="range" min="12" max="64" value={length} onChange={(event) => { const next = Number(event.target.value); setLength(next); setValue(generatePassword({ length: next, ...options })); }} /></div><div className="option-grid">{(["uppercase", "lowercase", "numbers", "symbols", "avoidAmbiguous"] as const).map((key) => <label key={key}><input type="checkbox" checked={options[key]} onChange={(event) => { const next = { ...options, [key]: event.target.checked }; setOptions(next); try { setValue(generatePassword({ length, ...next })); } catch { /* wait for another option */ } }} /><span>{key === "avoidAmbiguous" ? "Avoid ambiguous" : key[0].toUpperCase() + key.slice(1)}</span></label>)}</div></>}<div className="privacy-note"><ShieldCheck /><span>Clipboard copies are cleared after 30 seconds when the copied value is still present.</span></div></CardContent></Card></div>;
}

function AutomationsView({ entitlement }: { entitlement: Entitlement }) {
  const recipes = [{ id: "weekly-health", title: "Weekly vault health review", detail: "Remind me to review weak, reused, and stale passwords.", icon: CircleGauge }, { id: "stale-passwords", title: "Stale password watch", detail: "Surface logins that have not been changed for one year.", icon: History }, { id: "device-review", title: "Monthly device review", detail: "Prompt me to revoke browsers and devices I no longer use.", icon: Laptop }];
  const [enabled, setEnabled] = useState<string[]>(() => { if (typeof window === "undefined") return []; return JSON.parse(localStorage.getItem("passkey-x-automations") ?? "[]") as string[]; });
  function toggle(id: string) { const next = enabled.includes(id) ? enabled.filter((value) => value !== id) : [...enabled, id]; setEnabled(next); localStorage.setItem("passkey-x-automations", JSON.stringify(next)); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Bot /> Private by default</span><h2>Useful routines, under your control</h2><p>These starter automations run as local reminders. They do not send vault fields to a remote service.</p></div><div className="credit-meter"><span>Monthly runs</span><strong>{entitlement.automation_runs_remaining}</strong><small>remaining</small></div></div><div className="recipe-grid">{recipes.map(({ id, title, detail, icon: Icon }) => <Card key={id}><CardHeader><span className="feature-icon"><Icon /></span><CardTitle>{title}</CardTitle><CardDescription>{detail}</CardDescription></CardHeader><CardContent><label className="switch-row"><span>{enabled.includes(id) ? "Enabled" : "Disabled"}</span><input type="checkbox" checked={enabled.includes(id)} onChange={() => toggle(id)} /></label></CardContent></Card>)}</div><Card className="concierge-card"><CardHeader><span className="feature-icon"><Sparkles /></span><CardTitle>Security Concierge</CardTitle><CardDescription>Local privacy mode is active. A hosted AI provider has not been connected, so Passkey-X will not pretend that remote AI is available.</CardDescription></CardHeader><CardContent><div className="privacy-mode"><ShieldCheck /><div><strong>Privacy mode: Local only</strong><span>Vault contents stay on this device. Provider connection is an explicit future hosting decision.</span></div></div></CardContent></Card></div>;
}

type AccountPasskey = { id: string; friendly_name?: string; created_at: string; last_used_at?: string };

function AccountSecurityView() {
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]); const [busy, setBusy] = useState(false); const [loading, setLoading] = useState(passkeysEnabled); const [message, setMessage] = useState("");
  async function refresh() { if (!passkeysEnabled) return; const { data, error } = await supabase!.auth.passkey.list(); if (error) setMessage(error.message); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }
  useEffect(() => { if (!passkeysEnabled) return; let active = true; supabase!.auth.passkey.list().then(({ data, error }) => { if (!active) return; if (error) setMessage(error.message); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }); return () => { active = false; }; }, []);
  async function register() { setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.registerPasskey(); if (error) throw error; setMessage("Passkey registered. Your vault password remains separate."); await refresh(); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Passkey registration failed."); } finally { setBusy(false); } }
  async function rename(passkey: AccountPasskey) { const friendlyName = window.prompt("Passkey name", passkey.friendly_name ?? "My passkey")?.trim(); if (!friendlyName) return; setBusy(true); const { error } = await supabase!.auth.passkey.update({ passkeyId: passkey.id, friendlyName }); if (error) setMessage(error.message); else await refresh(); setBusy(false); }
  async function remove(passkey: AccountPasskey) { if (!window.confirm(`Remove ${passkey.friendly_name ?? "this passkey"}? It will no longer sign in to Passkey-X.`)) return; setBusy(true); const { error } = await supabase!.auth.passkey.delete({ passkeyId: passkey.id }); if (error) setMessage(error.message); else { setMessage("Passkey removed."); await refresh(); } setBusy(false); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Fingerprint /> Phase 3 identity</span><h2>Passwordless account access</h2><p>Passkeys authenticate your Passkey-X account. They never replace or disclose the separate password that decrypts your vault.</p></div><Button disabled={!passkeysEnabled || busy} onClick={() => void register()}><Plus /> Add passkey</Button></div>{!passkeysEnabled && <Card className="passkey-readiness"><CardHeader><CardTitle>Ready for domain activation</CardTitle><CardDescription>Passkey enrolment is deliberately disabled until passkey-x.com is configured in Supabase Auth with passkey-x.com as its permanent relying-party ID.</CardDescription></CardHeader><CardContent><div className="readiness-list"><span><Check /> Application code prepared</span><span><Check /> Custom domain and TLS connected</span><span><Clock3 /> Supabase Auth activation pending</span></div></CardContent></Card>}{passkeysEnabled && <Card><CardHeader><CardTitle>Your passkeys</CardTitle><CardDescription>Public credentials are stored by Supabase Auth; private keys remain in your authenticator.</CardDescription></CardHeader><CardContent>{loading ? <div className="loading-ring" /> : passkeys.length ? <div className="account-passkey-list">{passkeys.map((passkey) => <article key={passkey.id}><span className="device-icon"><Fingerprint /></span><div><strong>{passkey.friendly_name ?? "Passkey"}</strong><small>Added {new Date(passkey.created_at).toLocaleDateString()}{passkey.last_used_at ? ` · Last used ${new Date(passkey.last_used_at).toLocaleDateString()}` : ""}</small></div><Button variant="ghost" onClick={() => void rename(passkey)} disabled={busy}><Pencil /> Rename</Button><Button variant="outline" onClick={() => void remove(passkey)} disabled={busy}><Trash2 /> Remove</Button></article>)}</div> : <div className="small-empty"><Fingerprint /><strong>No passkeys registered</strong><span>Add one after signing in with your existing account method.</span></div>}</CardContent></Card>}{message && <p className="settings-message" role="status">{message}</p>}<div className="privacy-note"><ShieldCheck /><span>Passkey authentication establishes an account session only. Client-side Argon2id and AES-256-GCM vault encryption are unchanged.</span></div></div>;
}

function DevicesView({ identityId }: { identityId: string }) {
  const [devices, setDevices] = useState<DeviceRow[]>([]); const [loading, setLoading] = useState(true); const [message, setMessage] = useState("");
  async function refresh() { const { data, error } = await supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }); if (error) setMessage(error.message); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }
  useEffect(() => { let active = true; supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }).then(({ data, error }) => { if (!active) return; if (error) setMessage(error.message); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }); return () => { active = false; }; }, [identityId]);
  async function revoke(device: DeviceRow) { if (!window.confirm("Revoke this device? It cannot be trusted again.")) return; const { error } = await supabase!.from("devices").update({ status: "revoked", revoked_at: new Date().toISOString() }).eq("id", device.id).neq("status", "revoked"); if (error) setMessage(error.message); else await refresh(); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Laptop /> Trusted-device boundary</span><h2>Devices with vault access</h2><p>Free accounts support two active devices. Revocation is one-way and removes device-key eligibility.</p></div></div>{message && <p className="form-message" role="alert">{message}</p>}<div className="device-list">{loading ? <div className="loading-ring" /> : devices.map((device, index) => <Card key={device.id}><CardContent><span className="device-icon"><Laptop /></span><div><strong>{index === devices.length - 1 ? "Initial browser" : `Browser device ${devices.length - index}`}</strong><span>Added {new Date(device.created_at).toLocaleDateString()} · {device.status}</span><code>{device.id.slice(0, 8)}…{device.id.slice(-4)}</code></div><span className={`device-status ${device.status}`}>{device.status}</span>{device.status !== "revoked" && <Button variant="outline" onClick={() => revoke(device)}>Revoke</Button>}</CardContent></Card>)}</div><div className="privacy-note"><ShieldCheck /><span>Passkey-X stores only a public device key and encrypted labels. Private device key material stays protected in the client.</span></div></div>;
}

function SettingsView({ email, items, vault, profile, entitlement, onImported }: { email: string; items: VaultItem[]; vault: WorkspaceVault; profile: CryptoProfile; entitlement: Entitlement; onImported: () => Promise<void> | void }) {
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const [exportPassword, setExportPassword] = useState(""); const [showExport, setShowExport] = useState(false);
  async function importCsv(file: File) { if (!window.confirm("Import this CSV? It is parsed locally and each record is encrypted before upload.")) return; setBusy(true); setMessage(""); try { const rows = parseLoginCsv(await file.text()); for (const row of rows) await createVaultItem(vault, "login", { version: 1, ...row, updatedAt: new Date().toISOString() }); await onImported(); setMessage(`${rows.length} encrypted login${rows.length === 1 ? "" : "s"} imported.`); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Import failed."); } finally { setBusy(false); } }
  async function exportVault(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); let master: Uint8Array | null = null; let verified: Uint8Array | null = null; try { master = await deriveMasterKey(exportPassword, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters }); verified = await unwrapKey(master, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1"); const data = await createEncryptedExport({ product: "Passkey-X", version: 1, items }, exportPassword); const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })); const anchor = document.createElement("a"); anchor.href = url; anchor.download = `passkey-x-export-${new Date().toISOString().slice(0, 10)}.pxvault`; anchor.click(); URL.revokeObjectURL(url); setExportPassword(""); setShowExport(false); setMessage("Encrypted export downloaded."); } catch { setMessage("Vault reauthentication failed; no export was created."); } finally { master?.fill(0); verified?.fill(0); setBusy(false); } }
  return <div className="feature-page"><div className="settings-grid"><Card><CardHeader><CardTitle>Account</CardTitle><CardDescription>Signed in as {email}</CardDescription></CardHeader><CardContent><div className="setting-row"><span>Plan</span><strong>{entitlement.plan_code === "free" ? "Free" : "Personal"}</strong></div><div className="setting-row"><span>Encryption</span><strong>Argon2id + AES-256-GCM</strong></div><div className="setting-row"><span>Workspace</span><code>{vault.workspaceId.slice(0, 8)}…</code></div></CardContent></Card><Card><CardHeader><CardTitle>Import logins</CardTitle><CardDescription>Chrome-compatible or standard CSV. The source file is never uploaded.</CardDescription></CardHeader><CardContent><label className="file-action"><Upload /><span>{busy ? "Working…" : "Choose CSV file"}</span><input type="file" accept=".csv,text/csv" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void importCsv(file); event.target.value = ""; }} /></label></CardContent></Card><Card><CardHeader><CardTitle>Encrypted backup</CardTitle><CardDescription>Reauthenticate with your vault password before a portable encrypted export is created.</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => setShowExport(true)}><Download /> Export {items.length} items</Button></CardContent></Card><Card><CardHeader><CardTitle>Personal plan</CardTitle><CardDescription>Unlimited devices, more private AI credits, more automation runs, and no sponsor card.</CardDescription></CardHeader><CardContent><p className="field-hint">Billing is not connected to a payment provider in this development environment. No payment button is shown until hosting has an authorized provider.</p></CardContent></Card></div>{message && <p className="settings-message" role="status">{message}</p>}{showExport && <div className="modal-backdrop"><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="export-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={() => setShowExport(false)}><X /></button><CardTitle id="export-title">Confirm encrypted export</CardTitle><CardDescription>Enter your vault password. The export is encrypted locally with a fresh salt.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={exportVault}><div><Label htmlFor="export-password">Vault password</Label><Input id="export-password" type="password" autoComplete="current-password" required value={exportPassword} onChange={(event) => setExportPassword(event.target.value)} /></div><Button disabled={busy}>{busy ? "Encrypting…" : "Reauthenticate and download"}</Button></form></CardContent></Card></div>}</div>;
}

function ItemEditor({ item, onClose, onSave }: { item?: VaultItem; onClose: () => void; onSave: (kind: ItemKind, payload: VaultPayload) => Promise<void> }) {
  const [kind, setKind] = useState<ItemKind>(item?.contentType ?? "login"); const [title, setTitle] = useState(item?.payload.title ?? ""); const [username, setUsername] = useState(item?.payload.username ?? ""); const [secret, setSecret] = useState(item?.payload.secret ?? ""); const [url, setUrl] = useState(item?.payload.url ?? ""); const [notes, setNotes] = useState(item?.payload.notes ?? ""); const [tags, setTags] = useState(item?.payload.tags?.join(", ") ?? ""); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(""); const meta = ITEM_TYPES[kind];
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await onSave(kind, { version: 1, title: title.trim(), username: username.trim() || undefined, secret: secret || undefined, url: url.trim() || undefined, notes: notes.trim() || undefined, tags: tags.split(",").map((value) => value.trim()).filter(Boolean), favorite: item?.payload.favorite ?? false, archived: item?.payload.archived ?? false, updatedAt: new Date().toISOString() }); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to save item."); setBusy(false); } }
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="editor-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={onClose}><X /></button><CardTitle id="editor-title">{item ? "Edit encrypted item" : "Add encrypted item"}</CardTitle><CardDescription>Everything below is encrypted in this browser before it leaves the device.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={submit}><div><Label htmlFor="item-kind">Type</Label><select id="item-kind" value={kind} disabled={Boolean(item)} onChange={(event) => setKind(event.target.value as ItemKind)}>{(Object.keys(ITEM_TYPES) as ItemKind[]).map((value) => <option key={value} value={value}>{ITEM_TYPES[value].label}</option>)}</select></div><div><Label htmlFor="item-title">Name</Label><Input id="item-title" required autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="A name you will recognize" /></div>{kind !== "secure-note" && <div><Label htmlFor="item-username">{meta.userLabel ?? "Username"}</Label><Input id="item-username" value={username} onChange={(event) => setUsername(event.target.value)} /></div>}{kind !== "secure-note" && <div><div className="label-row"><Label htmlFor="item-secret">{meta.secretLabel ?? "Secret"}</Label>{kind === "login" && <button type="button" onClick={() => setSecret(generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true }))}><WandSparkles /> Generate</button>}</div><Input id="item-secret" value={secret} onChange={(event) => setSecret(event.target.value)} /></div>}<div><Label htmlFor="item-url">Website or host</Label><Input id="item-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https:// or host name" /></div><div><Label htmlFor="item-tags">Tags</Label><Input id="item-tags" value={tags} onChange={(event) => setTags(event.target.value)} placeholder="work, finance, production" /></div><div><Label htmlFor="item-notes">Notes</Label><textarea id="item-notes" rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<div className="editor-actions"><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button disabled={busy}>{busy ? "Encrypting…" : "Encrypt and save"}</Button></div></form></CardContent></Card></div>;
}

function HistoryDialog({ item, history, onClose }: { item: VaultItem; history: VaultHistoryEntry[]; onClose: () => void }) { return <div className="modal-backdrop"><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="history-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={onClose}><X /></button><CardTitle id="history-title">Revision history</CardTitle><CardDescription>{item.payload.title} · decrypted locally</CardDescription></CardHeader><CardContent><div className="history-list">{history.map((entry) => <article key={entry.revision}><span>v{entry.revision}</span><div><strong>{new Date(entry.createdAt).toLocaleString()}</strong><small>{entry.payload.title}{entry.payload.username ? ` · ${entry.payload.username}` : ""}</small></div></article>)}</div></CardContent></Card></div>; }
