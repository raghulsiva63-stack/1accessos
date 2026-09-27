"use client";

import Image from "next/image";
import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { AdminConsole } from "@/components/admin/admin-console";
import { EnterpriseProvider, useEnterprise } from "@/components/enterprise/policy-context";
import { ComplianceBanner, vaultPasswordFacts, type VaultPasswordFacts } from "@/components/enterprise/compliance-banner";
import { SecurityCenter } from "@/components/enterprise/security-center";
import { SecureSendView } from "@/components/enterprise/secure-send";
import { ChangeVaultPasswordCard } from "@/components/enterprise/change-vault-password";
import { MfaChallengeScreen, TotpCard } from "@/components/enterprise/mfa";
import { clearPendingClipboard, copySecret, PolicyCopyButton, PolicyLifecycle, RevealAudit } from "@/components/enterprise/vault-guards";
import { CommandPalette, CommandPaletteButton } from "@/components/app/command-palette";
import { OnboardingChecklist } from "@/components/app/onboarding-checklist";
import { ImportCard } from "@/components/app/import-card";
import type { Factor, Session } from "@supabase/supabase-js";
import {
  Archive, Bell, Bot, LayoutDashboard, Braces, BriefcaseBusiness, Check, ChevronRight, CircleGauge, Clock3,
  Copy, CreditCard, Database, Download, Eye, EyeOff, FileKey, FileText, Fingerprint,
  FolderKanban, Heart, History, IdCard, Inbox, KeyRound, Laptop, LockKeyhole, LogOut,
  MoreHorizontal, Paperclip, Pencil, Play, Plus, Radio, RefreshCw, Search, Send, Smartphone,
  Settings, Share2, ShieldAlert, ShieldCheck, Sparkles, Star, Trash2,
  UserPlus, UserRound, Users, Vault, WandSparkles, Waypoints, Wifi, X,
  LifeBuoy,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { OrganizationView } from "@/components/organization-view";
import { SaasAiManager } from "@/components/saas-ai-manager";
import { AutomationsView } from "@/components/automations-view";
import { ClientAuthFrame, CompanionHome } from "@/components/client-experience";
import { NativeAutofillReview } from "@/components/native-autofill";
import { useClientMode, type ClientMode } from "@/lib/browser/client-mode";
import { TurnstileCheck } from "@/components/turnstile-check";
import { AccountDeletionCard } from "@/components/account-deletion-card";
import { NotificationsView } from "@/components/notifications-view";
import { RuntimeAccessView } from "@/components/runtime-access-view";
import {
  createDeviceKeyPair, createEncryptedExport, createRecoveryKey, deriveMasterKey,
  fromBase64Url, parseRecoveryKey, randomBytes, recoveryFile, recoveryVerifier, saveProtectedDeviceKey,
  toBase64Url, toPostgresBytea, unwrapKey, WEB_KDF_PROFILE, wrapKey,
} from "@/lib/crypto/vault";
import { captchaEnabled, isSupabaseConfigured, passkeysEnabled, phoneMfaEnabled, supabase } from "@/lib/supabase/client";
import { captchaOptions, captchaReady } from "@/lib/auth/captcha";
import { authSessionTransition } from "@/lib/auth/session-machine";
import { downloadBlob } from "@/lib/browser/download";
import {
  createVaultItem, deleteVaultItem, type ItemKind, listVaultItemHistory,
  listVaultItemsWithStatus, listWorkspaceVaults, restoreVaultItem, type VaultHistoryEntry,
  type VaultItem, type VaultPayload, type WorkspaceVault, updateVaultItem,
} from "@/lib/vault/items";
import { WorkspaceRequestGate } from "@/lib/vault/request-gate";
import { generatePassphrase, generatePassword, passwordHealth } from "@/lib/vault/tools";
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
import {
  beginCheckout, billingEnabled, clearPlanSelection, FREE_ENTITLEMENT, loadBillingCatalog,
  loadPublicPlanCatalog, loadTenantEntitlement, openCustomerPortal, type BillingCurrency,
  readPlanSelection, stripeTestMode, type BillingInterval, type BillingPrice, type PlanCode,
  type PublicCatalogPlan, type TenantEntitlement,
} from "@/lib/billing/client";
import {
  acceptOrganizationInvitation, parseOrganizationInvitationLink,
  type OrganizationInvitationLink,
} from "@/lib/organization/phase5";
import { estimateStrength } from "@/lib/enterprise/health";
import { ItemFields } from "@/components/app/item-fields";
import { ThemeToggle } from "@/components/app/theme-toggle";
import { EmergencyAccessView, EmergencyInviteBanner, EmergencyRequestNotice } from "@/components/app/emergency-access-view";
import { parseEmergencyLink, type EmergencyLink } from "@/lib/enterprise/emergency";
import { OrgRecoveryEnrollment, OrgRecoveryUnlock, ProvisioningBanner } from "@/components/app/org-membership";
import { SsoSignIn } from "@/components/app/sso-sign-in";

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

type View = "home" | "vault" | "workspaces" | "organization" | "admin" | "send" | "saas-ai" | "runtime" | "notifications" | "missions" | "sharing" | "inbox" | "security" | "emergency" | "account-security" | "generator" | "automations" | "devices" | "billing" | "settings";
type VaultFilter = ItemKind | "all" | "favorites" | "archive" | "trash";
type DeviceRow = { id: string; status: "pending" | "trusted" | "revoked"; created_at: string; last_seen_at: string | null; revoked_at: string | null };
type Entitlement = TenantEntitlement;

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
  { id: "admin", label: "Admin console", icon: LayoutDashboard },
  { id: "organization", label: "Organization", icon: BriefcaseBusiness },
  { id: "saas-ai", label: "SaaS & AI", icon: Sparkles },
  { id: "runtime", label: "Runtime & Twin", icon: Waypoints },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "missions", label: "Missions", icon: FolderKanban },
  { id: "sharing", label: "Sharing", icon: Share2 },
  { id: "send", label: "Secure Send", icon: Send },
  { id: "inbox", label: "Access inbox", icon: Inbox },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "emergency", label: "Emergency access", icon: LifeBuoy },
  { id: "account-security", label: "Account security", icon: Fingerprint },
  { id: "generator", label: "Generator", icon: WandSparkles },
  { id: "automations", label: "Automations", icon: Bot },
  { id: "devices", label: "Devices", icon: Laptop },
  { id: "billing", label: "Plans & billing", icon: CreditCard },
  { id: "settings", label: "Settings", icon: Settings },
];

const NAV_SECTIONS: { label: string; views: View[] }[] = [
  { label: "Workspace", views: ["home", "vault", "workspaces"] },
  { label: "Access", views: ["missions", "sharing", "send", "inbox"] },
  { label: "Protect", views: ["security", "emergency", "account-security", "notifications", "generator", "devices"] },
  { label: "Manage", views: ["admin", "saas-ai", "runtime", "automations", "billing", "settings"] },
];

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={`brand ${compact ? "brand-compact" : ""}`}><Image src={compact ? "/brand/passkey-x-mark.png" : "/brand/passkey-x-horizontal.png"} alt="Passkey-X by Vlightsoft" width={compact ? 48 : 230} height={compact ? 48 : 66} priority /></div>;
}

function bytea(value: string) {
  return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64Url(value);
}

function customerError(reason: unknown, fallback: string) {
  const detail = typeof reason === "object" && reason !== null
    ? `${"code" in reason ? String(reason.code) : ""} ${"message" in reason ? String(reason.message) : ""}`.toLowerCase()
    : String(reason ?? "").toLowerCase();

  if (detail.includes("invalid_credentials") || detail.includes("invalid login credentials")) return "Email or login password is incorrect.";
  if (detail.includes("email_not_confirmed") || detail.includes("email not confirmed")) return "Confirm your email before signing in.";
  if (detail.includes("user_already_exists") || detail.includes("already registered") || detail.includes("already exists")) return "An account already exists for this email.";
  if (detail.includes("weak_password") || detail.includes("password should be")) return "Choose a stronger login password with at least 12 characters.";
  if (detail.includes("signup_disabled") || detail.includes("signups not allowed")) return "New account registration is temporarily unavailable.";
  if (detail.includes("rate") || detail.includes("too many")) return "Too many attempts. Wait a moment and try again.";
  if (detail.includes("captcha")) return "Complete the security check again, then retry.";
  if (detail.includes("mfa_phone_enroll_not_enabled") || detail.includes("phone enroll") || detail.includes("sms provider")) return "SMS verification is not active for this environment yet.";
  if (detail.includes("invalid phone") || detail.includes("phone format")) return "Enter a mobile number in international format, such as +14155550123.";
  if (detail.includes("factor") && detail.includes("already")) return "This mobile verification method is already enrolled.";
  if (detail.includes("challenge") || detail.includes("invalid otp") || detail.includes("otp expired")) return "That security code is invalid or expired. Request a new code.";
  if (detail.includes("notallowederror") || detail.includes("cancel") || detail.includes("webauthn")) return "Passkey verification was cancelled or could not be completed.";
  if (detail.includes("passkey") && (detail.includes("disabled") || detail.includes("not enabled"))) return "Passkey sign-in is temporarily unavailable. Use your login password.";
  if (detail.includes("secure device storage")) return "Secure browser storage is unavailable or blocked. Close other Passkey-X tabs, allow site storage, and try again.";
  if (detail.includes("billing_not_configured")) return "Secure billing is not active yet. Your current plan is unchanged.";
  if (detail.includes("subscription_exists")) return "This workspace already has a subscription. Use Manage billing to make changes.";
  if (detail.includes("customer_missing")) return "No billing profile exists for this workspace yet.";
  if (detail.includes("billing_unavailable")) return "Billing is temporarily unavailable. Your current plan is unchanged.";
  return fallback;
}

export default function Home() {
  const clientMode = useClientMode();
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<CryptoProfile | null>(null);
  const [rootKey, setRootKey] = useState<Uint8Array | null>(null);
  const [passwordFacts, setPasswordFacts] = useState<VaultPasswordFacts>(null);
  const [accountRecovery, setAccountRecovery] = useState(false);
  const [mfaState, setMfaState] = useState<"checking" | "required" | "satisfied">("checking");
  const [loading, setLoading] = useState(isSupabaseConfigured);
  const [error, setError] = useState("");
  const activeUserId = useRef<string | null>(null);
  const sessionUserId = session?.user.id ?? null;

  // Also clear the root when client-side navigation unmounts the vault page.
  useEffect(() => () => { rootKey?.fill(0); }, [rootKey]);

  useEffect(() => {
    if (!supabase) return;
    let active = true;
    supabase.auth.getSession().then(({ data }) => {
      if (!active) return;
      activeUserId.current = data.session?.user.id ?? null;
      setSession(data.session);
      setLoading(false);
    });
    const { data } = supabase.auth.onAuthStateChange((event, next) => {
      const transition = authSessionTransition(activeUserId.current, next?.user.id ?? null, event);
      activeUserId.current = transition.nextUserId;
      setSession(next);
      if (transition.accountChanged) {
        setMfaState(next ? "checking" : "satisfied");
        setProfile(null);
        setError("");
        setAccountRecovery(transition.passwordRecovery);
      } else if (transition.passwordRecovery) {
        setAccountRecovery(true);
      }
      if (transition.clearVaultState) {
        setRootKey((current) => { current?.fill(0); return null; });
      }
    });
    return () => { active = false; data.subscription.unsubscribe(); };
  }, []);

  useEffect(() => {
    if (!supabase || !sessionUserId) return;
    let active = true;
    supabase.auth.mfa.getAuthenticatorAssuranceLevel().then(({ data, error: mfaError }) => {
      if (!active) return;
      if (mfaError) { setError(customerError(mfaError, "Your account security level could not be verified. Sign in again.")); return; }
      setMfaState(data.nextLevel === "aal2" && data.currentLevel !== "aal2" ? "required" : "satisfied");
    });
    return () => { active = false; };
  }, [sessionUserId]);

  useEffect(() => {
    if (!supabase || !sessionUserId || mfaState !== "satisfied") return;
    let active = true;
    supabase.from("account_crypto_profiles").select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root,recovery_nonce,recovery_wrapped_root,recovery_verifier").maybeSingle().then(({ data, error: profileError }) => { if (!active) return; if (profileError) setError(customerError(profileError, "Your secure vault profile could not be loaded. Try signing in again.")); setProfile(data as CryptoProfile | null); setLoading(false); });
    return () => { active = false; };
  }, [sessionUserId, mfaState]);

  if (loading || !clientMode) return <main className="center-screen"><div className="loading-ring" aria-label="Loading Passkey-X" /></main>;
  if (!isSupabaseConfigured) return <ConfigurationNotice />;
  if (accountRecovery && session) return <AccountPasswordReset email={session.user.email ?? "your account"} onComplete={() => { setAccountRecovery(false); void supabase?.auth.signOut(); }} />;
  if (error) return <FatalNotice message={error} />;
  if (session && mfaState === "checking") return <main className="center-screen"><div className="loading-ring" aria-label="Checking account security" /></main>;
  if (session && mfaState === "required") return <MfaChallengeScreen brand={<Brand />} onComplete={() => setMfaState("satisfied")} footer={<><Button type="button" variant="ghost" onClick={() => void supabase?.auth.signOut()}>Use another account</Button><div className="privacy-note"><ShieldCheck /><span>Two-step verification (authenticator app or SMS) verifies the account session only. It cannot reset the vault password, decrypt vault data, or replace the recovery key.</span></div></>} />;
  if (!session) return <AuthScreen clientMode={clientMode} />;
  if (!profile) return <VaultSetup email={session.user.email ?? "your account"} onComplete={setProfile} />;
  if (!rootKey) return <UnlockScreen profile={profile} email={session.user.email ?? ""} onUnlock={(key, facts) => { if (document.hidden || activeUserId.current !== sessionUserId) key.fill(0); else { setPasswordFacts(facts ?? null); setRootKey(key); } }} onProfileChange={setProfile} />;
  return <VaultShell clientMode={clientMode} email={session.user.email ?? ""} profile={profile} rootKey={rootKey} passwordFacts={passwordFacts} onPasswordFacts={setPasswordFacts} onProfileChange={setProfile} onLock={() => { rootKey.fill(0); setRootKey(null); }} />;
}


function ConfigurationNotice() {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Passkey-X is temporarily unavailable</CardTitle><CardDescription>The secure account service could not start. Please try again later or contact Passkey-X support.</CardDescription></CardHeader></Card></main>;
}

function FatalNotice({ message }: { message: string }) {
  return <main className="center-screen"><Card className="auth-card"><CardHeader><Brand /><CardTitle>Passkey-X could not open</CardTitle><CardDescription>{message}</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => supabase?.auth.signOut()}>Sign out</Button></CardContent></Card></main>;
}

function AuthScreen({ clientMode }: { clientMode: ClientMode }) {
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

function AccountPasswordReset({ email, onComplete }: { email: string; onComplete: () => void }) {
  const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) { event.preventDefault(); if (password !== confirm) { setMessage("The login passwords do not match."); return; } setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.updateUser({ password }); if (error) throw error; setMessage("Login password updated. Your vault password and recovery key are unchanged."); setTimeout(onComplete, 1500); } catch (reason) { setMessage(customerError(reason, "Your login password could not be updated. Request a new reset link and try again.")); } finally { setBusy(false); } }
  return <main className="center-screen setup-bg"><Card className="auth-card"><CardHeader><Brand /><div className="step-pill">Secure account recovery</div><CardTitle>Create a new login password</CardTitle><CardDescription>Updating the login for {email} does not reset or decrypt the separate vault password.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={submit}><div><Label htmlFor="new-login-password">New login password</Label><Input id="new-login-password" type="password" minLength={12} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></div><div><Label htmlFor="confirm-login-password">Confirm login password</Label><Input id="confirm-login-password" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>{message && <p className="form-message" role="status">{message}</p>}<Button size="lg" disabled={busy}>{busy ? "Updating…" : "Update login password"}</Button></form></CardContent></Card></main>;
}

type PendingVaultSetup = Omit<CryptoProfile, "identity_id"> & {
  workspace_nonce: string;
  workspace_wrapped_key: string;
  device_public_key: string;
};

function VaultSetup({ email, onComplete }: { email: string; onComplete: (profile: CryptoProfile) => void }) {
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

function UnlockScreen({ profile, email, onUnlock, onProfileChange }: { profile: CryptoProfile; email: string; onUnlock: (key: Uint8Array, facts?: VaultPasswordFacts) => void; onProfileChange: (profile: CryptoProfile) => void }) {
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

function VaultShell({ clientMode, email, profile, rootKey, passwordFacts, onPasswordFacts, onProfileChange, onLock }: { clientMode: ClientMode; email: string; profile: CryptoProfile; rootKey: Uint8Array; passwordFacts: VaultPasswordFacts; onPasswordFacts: (facts: VaultPasswordFacts) => void; onProfileChange: (profile: CryptoProfile) => void; onLock: () => void }) {
  const [view, setView] = useState<View>(() => readPlanSelection() ? "billing" : "home");
  const requests = useRef(new WorkspaceRequestGate());
  const workspaceLoadVersion = useRef(0);
  const [workspaces, setWorkspaces] = useState<WorkspaceVault[]>([]);
  const [vault, setVault] = useState<WorkspaceVault | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [trash, setTrash] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<VaultFilter>("all");
  const [editor, setEditor] = useState<VaultItem | "new" | null>(null);
  const [rotateSecret, setRotateSecret] = useState<string | null>(null);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const revealed = revealedId !== null && revealedId === selected?.id;
  const setRevealed = (value: boolean) => setRevealedId(value ? selected?.id ?? null : null);
  const [history, setHistory] = useState<{ itemId: string; entries: VaultHistoryEntry[] } | null>(null);
  const [pendingLink, setPendingLink] = useState<InviteLink | null>(() => typeof window === "undefined" ? null : parseCollaborationLink(window.location.hash));
  const [pendingEmergency, setPendingEmergency] = useState<EmergencyLink | null>(() => typeof window === "undefined" ? null : parseEmergencyLink(window.location.hash));
  const [pendingOrganizationInvite, setPendingOrganizationInvite] = useState<OrganizationInvitationLink | null>(() => typeof window === "undefined" ? null : parseOrganizationInvitationLink(window.location.hash));
  const [accepting, setAccepting] = useState(false);
  const [notice, setNotice] = useState("");
  const [entitlement, setEntitlement] = useState<Entitlement>(FREE_ENTITLEMENT);
  const initials = useMemo(() => email.slice(0, 2).toUpperCase(), [email]);

  async function refresh(openVault: WorkspaceVault) {
    const ticket = requests.current.issue(openVault.workspaceId, "items");
    if (!ticket) return;
    try {
      const [activeList, deletedList] = await Promise.all([listVaultItemsWithStatus(openVault), listVaultItemsWithStatus(openVault, { trash: true })]);
      if (!requests.current.accepts(ticket)) return;
      const active = activeList.items; const deleted = deletedList.items;
      const unreadable = activeList.unreadable + deletedList.unreadable;
      if (unreadable) setNotice(`${unreadable} item${unreadable === 1 ? "" : "s"} could not be decrypted on this device and ${unreadable === 1 ? "is" : "are"} hidden. The rest of the vault is safe to use.`);
      setItems(active); setTrash(deleted);
      setSelected((current) => current ? [...active, ...deleted].find((item) => item.id === current.id) ?? null : null);
    } catch (reason) { if (requests.current.accepts(ticket)) throw reason; }
  }

  async function refreshEntitlement(openVault: WorkspaceVault) {
    const ticket = requests.current.issue(openVault.workspaceId, "entitlement");
    if (!ticket) return;
    try {
      const next = await loadTenantEntitlement(openVault.tenantId);
      if (requests.current.accepts(ticket)) setEntitlement(next);
    } catch { if (requests.current.accepts(ticket)) setEntitlement(FREE_ENTITLEMENT); }
  }

  function selectWorkspace(next: WorkspaceVault) {
    requests.current.select(next.workspaceId);
    setVault(next); setItems([]); setTrash([]); setSelected(null); setEditor(null);
    setHistory(null); setRevealed(false); setEntitlement(FREE_ENTITLEMENT);
    setFilter("all"); setQuery(""); setError("");
  }

  async function reloadWorkspaces(preferredId?: string) {
    const version = ++workspaceLoadVersion.current;
    const next = await listWorkspaceVaults(profile.identity_id, rootKey);
    if (version !== workspaceLoadVersion.current) { next.forEach((entry) => entry.key.fill(0)); return; }
    const chosen = next.find((entry) => entry.workspaceId === (preferredId ?? vault?.workspaceId)) ?? next[0];
    if (!chosen) { next.forEach((entry) => entry.key.fill(0)); throw new Error("No accessible workspace."); }
    workspaces.forEach((entry) => entry.key.fill(0));
    setWorkspaces(next); setLoading(true); selectWorkspace(chosen);
    try { await Promise.all([refresh(chosen), refreshEntitlement(chosen)]); }
    finally { if (version === workspaceLoadVersion.current) setLoading(false); }
  }

  useEffect(() => {
    let active = true;
    let opened: WorkspaceVault[] = [];
    const version = ++workspaceLoadVersion.current;
    listWorkspaceVaults(profile.identity_id, rootKey).then(async (next) => {
      opened = next;
      if (!active || version !== workspaceLoadVersion.current) { next.forEach((entry) => entry.key.fill(0)); return; }
      if (!next[0]) throw new Error("No accessible workspace.");
      setWorkspaces(next); selectWorkspace(next[0]);
      await Promise.all([refresh(next[0]), refreshEntitlement(next[0])]);
    }).catch((reason) => { if (active && version === workspaceLoadVersion.current) setError(customerError(reason, "Unable to open this workspace. Try again.")); })
      .finally(() => { if (active && version === workspaceLoadVersion.current) setLoading(false); });
    const gate = requests.current;
    return () => { active = false; workspaceLoadVersion.current += 1; gate.select(null); opened.forEach((entry) => entry.key.fill(0)); };
  }, [profile.identity_id, rootKey]);

  async function switchWorkspace(workspaceId: string) {
    const next = workspaces.find((entry) => entry.workspaceId === workspaceId);
    if (!next) return;
    const version = ++workspaceLoadVersion.current;
    setLoading(true); selectWorkspace(next);
    try { await Promise.all([refresh(next), refreshEntitlement(next)]); }
    catch (reason) { if (version === workspaceLoadVersion.current) setError(customerError(reason, "Unable to switch workspaces. Try again.")); }
    finally { if (version === workspaceLoadVersion.current) setLoading(false); }
  }

  async function acceptPendingLink() {
    if (!pendingLink && !pendingOrganizationInvite) return;
    setAccepting(true); setError("");
    try {
      if (pendingOrganizationInvite) {
        await acceptOrganizationInvitation(pendingOrganizationInvite);
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
        setPendingOrganizationInvite(null);
        setNotice("Organization membership accepted. Vault access arrives separately through an encrypted workspace invitation.");
        setView("home");
        return;
      }
      const workspaceId = pendingLink!.kind === "invite"
        ? await acceptWorkspaceInvite(pendingLink!, rootKey)
        : (await acceptAccessCapsule(pendingLink!, rootKey), undefined);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      setPendingLink(null);
      if (workspaceId) {
        setView("workspaces");
        try { await reloadWorkspaces(workspaceId); }
        catch { setNotice("Invitation accepted. The new workspace will appear after you lock and unlock the vault."); }
      }
      else setView("inbox");
    } catch (reason) { setError(customerError(reason, "Unable to accept this secure link. Ask the sender for a new link.")); }
    finally { setAccepting(false); }
  }

  const health = useMemo(() => passwordHealth(items), [items]);
  const visibleItems = useMemo(() => { const source = filter === "trash" ? trash : items; const normalized = query.trim().toLowerCase(); return source.filter((item) => { if (filter !== "all" && filter !== "trash" && filter !== "favorites" && filter !== "archive" && item.contentType !== filter) return false; if (filter === "favorites" && !item.payload.favorite) return false; if (filter === "archive" && !item.payload.archived) return false; if (filter !== "archive" && filter !== "trash" && item.payload.archived) return false; return !normalized || [item.payload.title, item.payload.username, item.payload.url, item.payload.notes, ...(item.payload.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)); }); }, [filter, items, query, trash]);
  async function saveItem(contentType: ItemKind, payload: VaultPayload) { if (!vault) return; if (editor === "new") await createVaultItem(vault, contentType, payload); else if (editor) await updateVaultItem(vault, editor, payload); setEditor(null); try { await refresh(vault); } catch { setNotice("Saved. The list could not refresh—lock and unlock to reload it."); } }
  async function removeItem(item: VaultItem) { if (!vault || !window.confirm(`Move “${item.payload.title}” to Trash?`)) return; try { await deleteVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(customerError(reason, "Unable to move this item to Trash. Try again.")); } }
  async function restoreItem(item: VaultItem) { if (!vault) return; try { await restoreVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(customerError(reason, "Unable to restore this item. Try again.")); } }
  async function toggle(item: VaultItem, key: "favorite" | "archived") { if (!vault) return; try { await updateVaultItem(vault, item, { ...item.payload, [key]: !item.payload[key] }); await refresh(vault); } catch (reason) { setError(customerError(reason, "This item changed on another device. Refresh and try again.")); } }
  async function showHistory(item: VaultItem) { if (!vault) return; try { const entries = await listVaultItemHistory(vault, item); setHistory({ itemId: item.id, entries }); } catch (reason) { setError(customerError(reason, "Revision history could not be decrypted. Try again.")); } }
  function openVault(filterValue: VaultFilter = "all") { setFilter(filterValue); setView("vault"); setSelected(null); }
  function lockVault() { clearPendingClipboard(); document.documentElement.classList.add("vault-privacy-lock"); requests.current.select(null); workspaceLoadVersion.current += 1; workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); pendingOrganizationInvite?.token.fill(0); pendingEmergency?.token.fill(0); onLock(); }
  async function signOut() { lockVault(); requests.current.select(null); workspaceLoadVersion.current += 1; workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); pendingOrganizationInvite?.token.fill(0); await supabase!.auth.signOut(); }
  const autoLock = useEffectEvent(() => lockVault());
  useEffect(() => {
    document.documentElement.classList.remove("vault-privacy-lock");
  }, []);
  useEffect(() => () => workspaces.forEach(entry => entry.key.fill(0)), [workspaces]);
  const companion = ["mobile", "desktop", "android"].includes(clientMode);
  const quickAccess = useEffectEvent(() => {
    if (!companion) return;
    setView("home"); setSelected(null); setEditor(null);
    requestAnimationFrame(() => window.dispatchEvent(new Event("passkey-x:quick-access")));
  });
  const addFromShortcut = useEffectEvent(() => { if (companion) { setView("vault"); setEditor("new"); } });
  useEffect(() => {
    const open = () => quickAccess();
    const add = () => addFromShortcut();
    const keydown = (event: KeyboardEvent) => {
      if (!companion || !event.isTrusted || !(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key.toLowerCase() === "k") { event.preventDefault(); quickAccess(); }
      if (event.key.toLowerCase() === "n" && event.shiftKey) { event.preventDefault(); addFromShortcut(); }
      if (event.key.toLowerCase() === "l") { event.preventDefault(); autoLock(); }
    };
    window.addEventListener("passkey-x:open-quick-access", open);
    window.addEventListener("passkey-x:add-login", add);
    document.addEventListener("keydown", keydown);
    return () => { window.removeEventListener("passkey-x:open-quick-access", open); window.removeEventListener("passkey-x:add-login", add); document.removeEventListener("keydown", keydown); };
  }, [companion]);
  const planLabel = entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1);
  return <EnterpriseProvider tenantId={vault?.tenantId ?? null} identityId={profile.identity_id} workspaceId={vault?.workspaceId ?? null} currentItemId={selected?.id ?? null}><PolicyLifecycle tenantId={vault?.tenantId ?? null} onLock={lockVault} /><RevealAudit revealed={revealed} itemId={selected?.id ?? null} /><main className={`vault-app client-${clientMode}`}>
    <aside className="vault-sidebar"><Brand /><nav>{NAV_SECTIONS.map((section) => <div className="nav-section" key={section.label}><span className="nav-section-label">{section.label}</span>{section.views.map((viewId) => { const entry = NAV.find((candidate) => candidate.id === viewId)!; const Icon = entry.icon; return <button key={entry.id} data-mobile-primary={["home", "vault", "generator", "account-security", "settings"].includes(entry.id)} className={`nav-item ${view === entry.id ? "active" : ""}`} onClick={() => { setView(entry.id); setSelected(null); }}><Icon /> {entry.label}{entry.id === "vault" && <span>{items.length}</span>}</button>; })}</div>)}</nav><div className="plan-chip"><Sparkles /><div><strong>{planLabel}</strong><span>{entitlement.ai_credits_remaining} private AI credits</span></div></div><div className="sidebar-account"><div className="avatar">{initials}</div><div><strong>{email.split("@")[0]}</strong><span>{vault?.name ?? "Opening workspace"}</span></div><MoreHorizontal /></div></aside>
    <section className="vault-content"><header><div><p className="eyebrow">Passkey-X {clientMode === "desktop" ? "Desktop" : clientMode === "android" || clientMode === "mobile" ? "Mobile" : ""} / {vault?.suite ?? "Personal"}</p><h1>{view === "home" ? companion ? "Your everyday vault" : "Good to see you" : NAV.find((entry) => entry.id === view)?.label}</h1><select className="mobile-view-picker" aria-label="Go to section" value={view} onChange={event => { setView(event.target.value as View); setSelected(null); }}>{NAV.map(entry => <option key={entry.id} value={entry.id}>{entry.label}</option>)}</select></div><div className="header-actions">{!companion && <CommandPaletteButton />}<ThemeToggle /><Link className="client-header-link" href="/download" aria-label="Get Passkey-X apps"><Download /></Link>{workspaces.length > 0 && <select className="workspace-switcher" aria-label="Current workspace" value={vault?.workspaceId ?? ""} onChange={(event) => void switchWorkspace(event.target.value)}>{workspaces.map((entry) => <option key={entry.workspaceId} value={entry.workspaceId}>{entry.name}</option>)}</select>}<Button variant="outline" onClick={lockVault}><LockKeyhole /> Lock</Button><Button variant="ghost" size="icon" aria-label="Sign out" onClick={() => void signOut()}><LogOut /></Button></div></header>
      {error && <div className="vault-error" role="alert">{error}<button aria-label="Dismiss" onClick={() => setError("")}><X /></button></div>}
      {notice && <div className="vault-notice" role="status">{notice}<button aria-label="Dismiss" onClick={() => setNotice("")}><X /></button></div>}
      <ComplianceBanner passwordFacts={passwordFacts} onOpenAccountSecurity={() => { setView("account-security"); setSelected(null); }} onOpenSettings={() => { setView("settings"); setSelected(null); }} />
      <ProvisioningBanner onJoined={(text) => setNotice(text)} />{vault && <OrgRecoveryEnrollment tenantId={vault.tenantId} identityId={profile.identity_id} rootKey={rootKey} />}<EmergencyRequestNotice identityId={profile.identity_id} onReview={() => setView("emergency")} />{pendingEmergency && <EmergencyInviteBanner link={pendingEmergency} rootKey={rootKey} onDone={(text) => { setPendingEmergency(null); if (text) { setNotice(text); setView("emergency"); } }} />}{(pendingLink || pendingOrganizationInvite) && <div className="secure-link-banner"><span className="feature-icon">{pendingLink?.kind === "capsule" ? <Share2 /> : <UserPlus />}</span><div><strong>{pendingOrganizationInvite ? "Organization invitation" : pendingLink?.kind === "invite" ? "Workspace invitation" : "Access Capsule"}</strong><p>{pendingOrganizationInvite ? "This one-time link adds your verified account to the organization directory. It does not grant vault access or deliver encryption keys." : "This link is addressed to your verified email. Its 256-bit secret stayed in the URL fragment and was not sent to the server."}</p></div><Button disabled={accepting} onClick={() => void acceptPendingLink()}>{accepting ? "Accepting…" : "Review and accept"}</Button></div>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /><p>Decrypting your workspace on this device…</p></div> : <>
        {clientMode === "android" && vault && <NativeAutofillReview key={vault.workspaceId} vault={vault} items={items} onSaved={() => refresh(vault)} />}
        {view === "home" && companion && <CompanionHome mode={clientMode} items={items} onSelect={item => { setView("vault"); setSelected(item); setRevealed(false); }} onNew={() => { setView("vault"); setEditor("new"); }} onVault={() => openVault()} onGenerator={() => setView("generator")} onSecurity={() => setView("security")} onRefresh={async () => { if (vault) { try { await refresh(vault); } catch { setError("Could not refresh. Check your connection and try again."); } } }} />}
        {view === "home" && !companion && <Dashboard items={items} trash={trash} health={health} entitlement={entitlement} identityId={profile.identity_id} workspaceCount={workspaces.length} onNavigate={(next) => { setView(next as View); setSelected(null); }} onOpenVault={openVault} onNew={() => { setEditor("new"); setView("vault"); }} />}
        {view === "vault" && vault && <VaultView vault={vault} items={visibleItems} allItems={items} trash={trash} filter={filter} query={query} selected={selected} revealed={revealed} onQuery={setQuery} onFilter={setFilter} onNew={() => setEditor("new")} onSelect={(item) => { setSelected(item); setRevealed(false); setHistory(null); }} onReveal={() => setRevealed(!revealed)} onClose={() => setSelected(null)} onEdit={(item) => setEditor(item)} onDelete={removeItem} onRestore={restoreItem} onToggle={toggle} onHistory={showHistory} onRotate={(item) => { setRotateSecret(generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); setEditor(item); }} />}
        {view === "workspaces" && vault && <WorkspacesView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} workspaces={workspaces} vault={vault} onSelect={switchWorkspace} onReload={reloadWorkspaces} />}
        {view === "organization" && vault && <OrganizationView key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "admin" && vault && <AdminConsole key={vault.tenantId} vault={vault} entitlement={entitlement} workspaceNames={new Map(workspaces.map((entry) => [entry.workspaceId, entry.name]))} onOpenBilling={() => setView("billing")} />}
        {view === "saas-ai" && vault && <SaasAiManager key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "runtime" && vault && <RuntimeAccessView key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "notifications" && vault && <NotificationsView key={vault.tenantId} vault={vault} />}
        {view === "missions" && vault && <MissionsView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "sharing" && vault && <SharingView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "send" && vault && <SecureSendView key={vault.tenantId} vault={vault} />}
        {view === "emergency" && vault && <EmergencyAccessView key={vault.workspaceId} vault={vault} workspaces={workspaces} identityId={profile.identity_id} rootKey={rootKey} onOpened={(workspaceId) => reloadWorkspaces(workspaceId)} />}
        {view === "inbox" && vault && <AccessInboxView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} vault={vault} items={items} />}
        {view === "security" && <SecurityCenter tenantId={vault?.tenantId ?? null} items={items} clientKind={clientMode === "desktop" ? "desktop" : clientMode === "android" ? "android" : clientMode === "mobile" ? "mobile" : "web"} onOpen={(id) => { const item = items.find((candidate) => candidate.id === id); if (item) { setView("vault"); setSelected(item); } }} />}
        {view === "account-security" && <AccountSecurityView />}
        {view === "generator" && <GeneratorView />}
        {vault && <AutomationsView key={`${vault.identityId}:${vault.tenantId}:${vault.workspaceId}`} vault={vault} items={items} visible={view === "automations"} onNavigate={setView} />}
        {view === "devices" && <DevicesView identityId={profile.identity_id} />}
        {view === "billing" && vault && <BillingView vault={vault} entitlement={entitlement} onRefresh={() => refreshEntitlement(vault)} />}
        {view === "settings" && vault && <SettingsView email={email} items={items} vault={vault} profile={profile} entitlement={entitlement} onImported={() => refresh(vault)} onProfileChange={onProfileChange} onPasswordFacts={onPasswordFacts} />}
      </>}
    </section>
    <CommandPalette enabled={!companion} items={items} views={NAV} onNavigate={(next) => { setView(next as View); setSelected(null); }} onOpenItem={(item) => { setView("vault"); setFilter("all"); setSelected(item); setRevealed(false); setHistory(null); }} onNewItem={() => { setView("vault"); setEditor("new"); }} onLock={lockVault} />
    {editor && <ItemEditor key={editor === "new" ? "new" : `${editor.id}:${rotateSecret ? "rotate" : "edit"}`} item={editor === "new" ? undefined : editor} initialSecret={editor === "new" ? undefined : rotateSecret ?? undefined} onClose={() => { setEditor(null); setRotateSecret(null); }} onSave={async (kind, payload) => { await saveItem(kind, payload); setRotateSecret(null); }} />}
    {history && selected && history.itemId === selected.id && <HistoryDialog item={selected} history={history.entries} onClose={() => setHistory(null)} />}
  </main></EnterpriseProvider>;
}

function Dashboard({ items, trash, health, entitlement, identityId, workspaceCount, onNavigate, onOpenVault, onNew }: { items: VaultItem[]; trash: VaultItem[]; health: ReturnType<typeof passwordHealth>; entitlement: Entitlement; identityId: string; workspaceCount: number; onNavigate: (view: string) => void; onOpenVault: (filter?: VaultFilter) => void; onNew: () => void }) {
  const recent = items.slice(0, 4);
  return <div className="dashboard"><section className="welcome-card"><div><span className="status-pill"><ShieldCheck /> Vault protected</span><h2>Your digital life, under your control.</h2><p>Every item is encrypted before it leaves this device. Search and security checks happen locally.</p><div className="welcome-actions"><Button onClick={onNew}><Plus /> Add secure item</Button><Button variant="outline" onClick={() => onOpenVault()}>Open vault <ChevronRight /></Button></div></div><Image src="/brand/passkey-x-mark.png" alt="" width={220} height={220} /></section><OnboardingChecklist identityId={identityId} itemCount={items.length} workspaceCount={workspaceCount} onNavigate={onNavigate} onNewItem={onNew} /><div className="metric-grid"><Metric icon={Vault} label="Protected items" value={items.length} detail={`${trash.length} in trash`} onClick={() => onOpenVault()} /><Metric icon={CircleGauge} label="Security score" value={`${health.score}%`} detail={`${health.findings.filter((finding) => finding.severity !== "good").length} findings`} /><Metric icon={Bot} label="Automation runs" value={entitlement.automation_runs_remaining} detail="remaining this month" /><Metric icon={Laptop} label="Device limit" value={entitlement.max_devices ?? "∞"} detail={`${entitlement.plan_code} plan`} /></div><div className="dashboard-columns"><Card><CardHeader><div><CardTitle>Recently updated</CardTitle><CardDescription>Decrypted only on this device</CardDescription></div><Button variant="ghost" onClick={() => onOpenVault()}>View all</Button></CardHeader><CardContent>{recent.length ? <div className="recent-list">{recent.map((item) => { const Icon = ITEM_TYPES[item.contentType].icon; return <button key={item.id} onClick={() => onOpenVault(item.contentType)}><span className="item-kind-icon"><Icon /></span><span><strong>{item.payload.title}</strong><small>{ITEM_TYPES[item.contentType].label}</small></span><ChevronRight /></button>; })}</div> : <div className="small-empty"><Vault /><strong>Your vault is ready</strong><span>Add your first password, passkey, note, or credential.</span></div>}</CardContent></Card>{entitlement.plan_code === "free" ? <SponsorCard /> : <PlanSummaryCard entitlement={entitlement} />}</div></div>;
}

function Metric({ icon: Icon, label, value, detail, onClick }: { icon: typeof Vault; label: string; value: string | number; detail: string; onClick?: () => void }) { return <button className="metric-card" onClick={onClick}><span className="metric-icon"><Icon /></span><span><small>{label}</small><strong>{value}</strong><em>{detail}</em></span></button>; }
function SponsorCard() { return <Card className="sponsor-card"><CardHeader><div className="sponsor-label">Passkey-X sponsor · privacy safe</div><CardTitle>Safer accounts start with MFA</CardTitle><CardDescription>This first-party educational card is not selected from vault contents. No third-party script or tracker runs here.</CardDescription></CardHeader><CardContent><Button variant="outline">Read the security guide</Button><p>Sponsored cards only appear on Home for Free accounts.</p></CardContent></Card>; }
function PlanSummaryCard({ entitlement }: { entitlement: Entitlement }) { return <Card className="plan-summary-card"><CardHeader><div className="sponsor-label">Active workspace plan</div><CardTitle>{entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1)}</CardTitle><CardDescription>Entitlements are confirmed by signed server-side billing events, never by a browser redirect.</CardDescription></CardHeader><CardContent><div className="plan-summary-row"><ShieldCheck /><span>{entitlement.subscription_status.replaceAll("_", " ")}</span></div>{entitlement.valid_until && <p>Current period ends {new Date(entitlement.valid_until).toLocaleDateString()}.</p>}</CardContent></Card>; }

function WorkspacesView({ identityId, rootKey, workspaces, vault, onSelect, onReload }: {
  identityId: string; rootKey: Uint8Array; workspaces: WorkspaceVault[]; vault: WorkspaceVault;
  onSelect: (id: string) => Promise<void>; onReload: (id?: string) => Promise<void>;
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
  useEffect(() => { let active = true; Promise.all([listWorkspaceMembers(vault), listWorkspaceInvites(vault)]).then(([nextMembers, nextInvites]) => { if (active) { setMembers(nextMembers); setInvites(nextInvites); } }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load collaboration details. Try again.")); }); return () => { active = false; }; }, [vault]);

  async function createWorkspace(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const created = await createSharedWorkspace(identityId, rootKey, name, suite);
      created.key.fill(0); // the reload opens its own copy of the key
      await onReload(created.workspaceId); setName(""); setMessage(`${created.name} is ready.`);
    } catch (reason) { setMessage(customerError(reason, "Unable to create this workspace. Try again.")); }
    finally { setBusy(false); }
  }
  async function invite(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage(""); setShareLink("");
    try {
      const link = await createWorkspaceInvite(vault, recipient, role, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), window.location.origin);
      setShareLink(link); setRecipient(""); await refreshLists();
    } catch (reason) { setMessage(customerError(reason, "Unable to create this invitation. Try again.")); }
    finally { setBusy(false); }
  }
  async function revokeMember(member: WorkspaceMember) {
    if (!window.confirm("Revoke this member now? Future server access ends immediately and the workspace will be marked for key rotation.")) return;
    setBusy(true); setMessage("");
    try { await revokeWorkspaceMember(vault, member.identityId); await onReload(vault.workspaceId); setMessage("Member revoked. Cryptographic key rotation is now required."); }
    catch (reason) { setMessage(customerError(reason, "Unable to revoke this member. Try again.")); }
    finally { setBusy(false); }
  }
  async function revokeInvite(inviteRow: WorkspaceInvite) {
    setBusy(true); setMessage("");
    try { await revokeWorkspaceInvite(inviteRow.id); await refreshLists(); }
    catch (reason) { setMessage(customerError(reason, "Unable to revoke this invitation. Try again.")); }
    finally { setBusy(false); }
  }

  const canManage = vault.role === "owner" || vault.role === "manager";
  return <div className="feature-page phase2-page">
    <div className="feature-intro"><div><span className="status-pill"><Users /> Encrypted collaboration</span><h2>One account, isolated workspaces</h2><p>Family, client, team and Business workspace names and keys are encrypted in this browser. Invitations release a wrapped key only after the exact email is verified.</p></div><div className="credit-meter"><span>Workspaces</span><strong>{workspaces.length}</strong><small>active</small></div></div>
    <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Your workspaces</CardTitle><CardDescription>Switching changes which client-side key is active.</CardDescription></CardHeader><CardContent><div className="workspace-list">{workspaces.map((entry) => <button key={entry.workspaceId} className={entry.workspaceId === vault.workspaceId ? "active" : ""} onClick={() => void onSelect(entry.workspaceId)}><span className="feature-icon">{entry.suite === "professional" ? <BriefcaseBusiness /> : <Users />}</span><span><strong>{entry.name}</strong><small>{entry.suite} · {entry.role}</small></span>{entry.keyRotationRequired ? <ShieldAlert /> : <ChevronRight />}</button>)}</div></CardContent></Card>
      <Card><CardHeader><CardTitle>Create a workspace</CardTitle><CardDescription>For a household, client engagement, team or multi-department office.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={createWorkspace}><div><Label htmlFor="workspace-name">Encrypted name</Label><Input id="workspace-name" required minLength={2} value={name} onChange={(event) => setName(event.target.value)} placeholder="Client Aurora" /></div><div><Label htmlFor="workspace-suite">Suite</Label><select id="workspace-suite" value={suite} onChange={(event) => setSuite(event.target.value as WorkspaceSuite)}><option value="family">Family</option><option value="professional">Professional / client</option><option value="team">Team · one workgroup</option><option value="business">Business · departments and teams</option></select></div><Button disabled={busy}>{busy ? "Creating…" : "Create encrypted workspace"}</Button></form></CardContent></Card>
    </div>
    {vault.keyRotationRequired && <div className="rotation-warning"><ShieldAlert /><div><strong>Workspace key rotation required</strong><p>A member was revoked. Their server access and envelopes are disabled. Because a device may have retained a previously decrypted value, move sensitive credentials into a freshly keyed workspace before future use.</p></div></div>}
    {vault.suite !== "personal" && <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Invite a verified member</CardTitle><CardDescription>The full link contains a 256-bit secret in its fragment. Send it through a trusted channel.</CardDescription></CardHeader><CardContent>{canManage ? <form className="form-stack" onSubmit={invite}><div><Label htmlFor="invite-email">Recipient email</Label><Input id="invite-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="invite-role">Role</Label><select id="invite-role" value={role} onChange={(event) => setRole(event.target.value as WorkspaceRole)}><option value="manager">Manager</option><option value="editor">Member / editor</option><option value="viewer">Guest / viewer</option></select></div><div><Label htmlFor="invite-expiry">Expires</Label><select id="invite-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div></div><Button disabled={busy}><UserPlus /> {busy ? "Creating…" : "Create secure invitation"}</Button></form> : <p className="field-hint">Only workspace owners and managers can invite members.</p>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} audit={false} /><small>Passkey-X stores only its verifier. The secret cannot be recovered later.</small></div>}</CardContent></Card>
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
  useEffect(() => { let active = true; listSentCapsules(vault).then((next) => { if (active) setSent(next); }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load active shares. Try again.")); }); return () => { active = false; }; }, [vault]);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); const item = items.find((candidate) => candidate.id === itemId); if (!item) return;
    setBusy(true); setMessage(""); setShareLink("");
    try { setShareLink(await createAccessCapsule(vault, item, recipient, policy, purpose, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), oneTime ? 1 : 0, window.location.origin)); setRecipient(""); await refresh(); }
    catch (reason) { setMessage(customerError(reason, "Unable to create this Access Capsule. Try again.")); }
    finally { setBusy(false); }
  }
  async function revoke(capsule: SentCapsule) { if (!window.confirm("Revoke this Access Capsule?")) return; setBusy(true); try { await revokeAccessCapsule(capsule.id); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to revoke this Access Capsule. Try again.")); } finally { setBusy(false); } }
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Share2 /> Access Capsule</span><h2>Share a purpose, not a copied password</h2><p>Passkey-X encrypts a snapshot with a fresh share key. Email verification, expiry, usage limits and revocation control future delivery.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Create Access Capsule</CardTitle><CardDescription>No plaintext credential is placed in the link, database, audit record or email.</CardDescription></CardHeader><CardContent>{items.length ? <form className="form-stack" onSubmit={submit}><div><Label htmlFor="share-item">Item</Label><select id="share-item" value={itemId} onChange={(event) => setItemId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div><Label htmlFor="share-email">Verified recipient email</Label><Input id="share-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="share-policy">Reveal policy</Label><select id="share-policy" value={policy} onChange={(event) => setPolicy(event.target.value as "reveal" | "fill_only")}><option value="fill_only">Fill-only / no reveal</option><option value="reveal">Reveal allowed</option></select></div><div><Label htmlFor="share-purpose">Purpose</Label><select id="share-purpose" value={purpose} onChange={(event) => setPurpose(event.target.value)}><option value="family">Family</option><option value="client">Client</option><option value="project">Project</option><option value="support">Support</option><option value="handover">Handover</option><option value="other">Other</option></select></div></div><div className="inline-fields"><div><Label htmlFor="share-expiry">Expires</Label><select id="share-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div><label className="check-row"><input type="checkbox" checked={oneTime} onChange={(event) => setOneTime(event.target.checked)} /> One-time use</label></div><Button disabled={busy}><Send /> {busy ? "Encrypting…" : "Create secure link"}</Button></form> : <div className="small-empty"><Vault /><strong>Add an item first</strong><span>Access Capsules are encrypted snapshots of an existing item.</span></div>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} audit={false} /><small>The fragment secret is shown only once.</small></div>}</CardContent></Card><Card><CardHeader><CardTitle>Sent capsules</CardTitle><CardDescription>Revocation stops future server delivery. It cannot erase knowledge already captured by a recipient device.</CardDescription></CardHeader><CardContent><div className="member-list">{sent.length ? sent.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{items.find((item) => item.id === capsule.itemId)?.payload.title ?? "Encrypted item"}</strong><small>{capsule.revealPolicy.replace("_", "-")} · {capsule.status} · {capsule.maxUses ? `${capsule.useCount}/${capsule.maxUses} uses` : "unlimited uses"}</small></div>{["pending","accepted"].includes(capsule.status) && <Button variant="ghost" disabled={busy} onClick={() => void revoke(capsule)}>Revoke</Button>}</article>) : <div className="small-empty"><Send /><strong>No active shares</strong><span>Created capsules will appear here.</span></div>}</div></CardContent></Card></div>{policy === "fill_only" && <div className="rotation-warning neutral"><ShieldAlert /><div><strong>Fill-only is not DRM</strong><p>Passkey-X hides the value in its normal interface, but a compromised recipient device or target website may still capture a filled credential.</p></div></div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
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
  useEffect(() => { let mounted = true; listMissions(vault).then((next) => { if (mounted) setMissions(next); }).catch((reason) => { if (mounted) setMessage(customerError(reason, "Unable to load Missions. Try again.")); }); return () => { mounted = false; }; }, [vault]);
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createMission(vault, title, selectedIds, duration); setTitle(""); setSelectedIds([]); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to create this Mission. Try again.")); } finally { setBusy(false); } }
  async function run(mission: Mission) { setBusy(true); setMessage(""); try { const expiresAt = await startMission(vault, mission); setActive(mission); setActiveExpiresAt(new Date(expiresAt)); } catch (reason) { setMessage(customerError(reason, "Unable to start this Mission. Try again.")); } finally { setBusy(false); } }
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
  useEffect(() => { let active = true; Promise.all([listReceivedCapsules(identityId, rootKey), listAccessRequests(vault)]).then(([nextCapsules, nextRequests]) => { if (active) { setCapsules(nextCapsules); setRequests(nextRequests); } }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load the access inbox. Try again.")); }); return () => { active = false; }; }, [identityId, rootKey, vault]);
  async function openCapsule(capsule: ReceivedCapsule) { setBusy(true); setMessage(""); try { await consumeAccessCapsule(capsule.id); setOpened(capsule); setCapsules((current) => current.filter((entry) => entry.id !== capsule.id)); } catch (reason) { setMessage(customerError(reason, "This Access Capsule is no longer available.")); } finally { setBusy(false); } }
  async function request(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createAccessRequest(vault, itemId || null, scope, purpose, duration); setPurpose(""); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to request access. Try again.")); } finally { setBusy(false); } }
  async function decide(row: AccessRequest, decision: "approved" | "denied") { setBusy(true); setMessage(""); try { await decideAccessRequest(row.id, decision); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to record this decision. Try again.")); } finally { setBusy(false); } }
  const canApprove = vault.role === "owner" || vault.role === "manager";
  const canRequest = vault.role !== "owner";
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Inbox /> Access inbox</span><h2>Timeboxed access with a clear decision trail</h2><p>Purposes are encrypted with the workspace key. Decisions and expiry remain visible as authorization metadata and audit evidence.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Received Access Capsules</CardTitle><CardDescription>Opening records a use. Fill-only entries never expose the secret in this interface.</CardDescription></CardHeader><CardContent><div className="member-list">{capsules.length ? capsules.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{capsule.payload.title}</strong><small>{capsule.revealPolicy.replace("_", "-")} · expires {new Date(capsule.expiresAt).toLocaleString()}</small></div><Button variant="outline" disabled={busy} onClick={() => void openCapsule(capsule)}>Open</Button></article>) : <div className="small-empty"><Inbox /><strong>Inbox is clear</strong><span>Accepted capsules that are still valid appear here.</span></div>}</div></CardContent></Card><Card><CardHeader><CardTitle>{canRequest ? "Request temporary access" : "Pending approvals"}</CardTitle><CardDescription>{canRequest ? "Ask an owner or manager for an attributable, expiring scope." : "Review requests without exposing their vault contents."}</CardDescription></CardHeader><CardContent>{canRequest && <form className="form-stack" onSubmit={request}><div><Label htmlFor="request-item">Resource</Label><select id="request-item" value={itemId} onChange={(event) => setItemId(event.target.value)}><option value="">Whole workspace</option>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div className="inline-fields"><div><Label htmlFor="request-scope">Scope</Label><select id="request-scope" value={scope} onChange={(event) => setScope(event.target.value as AccessRequest["requestedScope"])}><option value="use">Use</option><option value="reveal">Reveal</option><option value="edit">Edit</option>{vault.role === "manager" && <option value="manage">Manage</option>}</select></div><div><Label htmlFor="request-duration">Duration</Label><select id="request-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={480}>8 hours</option></select></div></div><div><Label htmlFor="request-purpose">Encrypted purpose</Label><textarea id="request-purpose" required rows={3} value={purpose} onChange={(event) => setPurpose(event.target.value)} placeholder="Why this access is needed" /></div><Button disabled={busy}><Send /> Submit request</Button></form>}<div className="request-list">{requests.map((row) => <article key={row.id}><div><strong>{row.requestedScope} for {row.itemId ? items.find((item) => item.id === row.itemId)?.payload.title ?? "item" : "workspace"}</strong><p>{row.purpose}</p><small>{row.status} · {row.durationMinutes} minutes · requester {row.requesterIdentityId.slice(0, 8)}</small></div>{canApprove && row.status === "pending" && <div><Button disabled={busy} onClick={() => void decide(row, "approved")}><Check /> Approve</Button><Button variant="outline" disabled={busy} onClick={() => void decide(row, "denied")}><X /> Deny</Button></div>}</article>)}</div></CardContent></Card></div>{opened && <div className="capsule-open"><div className="detail-heading"><div><span>{opened.revealPolicy.replace("_", "-")}</span><h2>{opened.payload.title}</h2></div><button aria-label="Close capsule" onClick={() => setOpened(null)}><X /></button></div>{opened.payload.username && <DetailField label="Username" value={opened.payload.username} copyable={opened.revealPolicy === "reveal"} />}{opened.revealPolicy === "reveal" && opened.payload.secret && <DetailField label="Shared secret" value={opened.payload.secret} copyable />}{opened.payload.url && <DetailField label="Website" value={opened.payload.url} copyable />}{opened.revealPolicy === "fill_only" && <div className="rotation-warning neutral"><ShieldCheck /><div><strong>Fill-only policy active</strong><p>The secret is intentionally hidden here. Use the trusted Passkey-X extension to fill it at the matching site. A compromised endpoint can still capture a filled value.</p></div></div>}</div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

function VaultView({ vault, items, allItems, trash, filter, query, selected, revealed, onQuery, onFilter, onNew, onSelect, onReveal, onClose, onEdit, onDelete, onRestore, onToggle, onHistory, onRotate }: { vault: WorkspaceVault; items: VaultItem[]; allItems: VaultItem[]; trash: VaultItem[]; filter: VaultFilter; query: string; selected: VaultItem | null; revealed: boolean; onQuery: (value: string) => void; onFilter: (value: VaultFilter) => void; onNew: () => void; onSelect: (item: VaultItem) => void; onReveal: () => void; onClose: () => void; onEdit: (item: VaultItem) => void; onDelete: (item: VaultItem) => void; onRestore: (item: VaultItem) => void; onToggle: (item: VaultItem, key: "favorite" | "archived") => void; onHistory: (item: VaultItem) => void ; onRotate?: (item: VaultItem) => void}) {
  return <div className="vault-view"><div className="vault-toolbar"><div className="search-box"><Search /><input aria-label="Search vault" placeholder="Search locally in your decrypted vault" value={query} onChange={(event) => onQuery(event.target.value)} /></div><Button onClick={onNew}><Plus /> New item</Button></div><div className="filter-strip"><button className={filter === "all" ? "active" : ""} onClick={() => onFilter("all")}>All <span>{allItems.filter((item) => !item.payload.archived).length}</span></button><button className={filter === "favorites" ? "active" : ""} onClick={() => onFilter("favorites")}><Star /> Favorites</button><button className={filter === "archive" ? "active" : ""} onClick={() => onFilter("archive")}><Archive /> Archive</button><button className={filter === "trash" ? "active" : ""} onClick={() => onFilter("trash")}><Trash2 /> Trash <span>{trash.length}</span></button><select aria-label="Filter item type" value={(filter in ITEM_TYPES) ? filter : "all"} onChange={(event) => onFilter(event.target.value as VaultFilter)}><option value="all">All item types</option>{(Object.keys(ITEM_TYPES) as ItemKind[]).map((kind) => <option key={kind} value={kind}>{ITEM_TYPES[kind].plural}</option>)}</select></div>{items.length === 0 ? <div className="empty-vault"><div className="empty-icon"><Vault /></div><h2>{query ? "No matching items" : filter === "trash" ? "Trash is empty" : "Nothing here yet"}</h2><p>{query ? "Try another search or filter." : "Add a protected item. Its contents will be encrypted before syncing."}</p>{filter !== "trash" && <Button onClick={onNew}><Plus /> Add secure item</Button>}</div> : <div className={`items-layout ${selected ? "with-detail" : ""}`}><div className="item-list">{items.map((item) => { const Icon = ITEM_TYPES[item.contentType].icon; return <button key={item.id} className={`item-row ${selected?.id === item.id ? "selected" : ""}`} onClick={() => onSelect(item)}><span className="item-kind-icon"><Icon /></span><span className="item-summary"><strong>{item.payload.title}</strong><small>{item.payload.username || item.payload.url || ITEM_TYPES[item.contentType].label}</small></span><span className="item-badges">{item.payload.favorite && <Star />}{item.payload.archived && <Archive />}<span>{ITEM_TYPES[item.contentType].label}</span></span></button>; })}</div>{selected && <aside className="item-detail"><div className="detail-heading"><div><span>{ITEM_TYPES[selected.contentType].label}</span><h2>{selected.payload.title}</h2></div><button aria-label="Close details" onClick={onClose}><X /></button></div>{selected.payload.username && <DetailField label={ITEM_TYPES[selected.contentType].userLabel ?? "Username"} value={selected.payload.username} copyable />}{selected.payload.secret && <div className="detail-field"><span>{ITEM_TYPES[selected.contentType].secretLabel ?? "Secret"}</span><div><code>{revealed ? selected.payload.secret : "••••••••••••"}</code><button aria-label={revealed ? "Hide secret" : "Reveal secret"} onClick={onReveal}>{revealed ? <EyeOff /> : <Eye />}</button><CopyButton value={selected.payload.secret} /></div></div>}{selected.payload.url && <DetailField label="Website" value={selected.payload.url} copyable />}{selected.payload.notes && <DetailField label="Notes" value={selected.payload.notes} />}{selected.payload.tags?.length ? <DetailField label="Tags" value={selected.payload.tags.join(", ")} /> : null}<ItemFields item={selected} revealed={revealed} onRotate={onRotate ? () => onRotate(selected) : undefined} />{!selected.deletedAt && <AttachmentPanel vault={vault} item={selected} />}<div className="detail-meta"><span>Revision {selected.revision}</span><span>Updated {new Date(selected.payload.updatedAt).toLocaleDateString()}</span></div><div className="detail-actions">{selected.deletedAt ? <Button onClick={() => onRestore(selected)}><RefreshCw /> Restore</Button> : <><Button variant="outline" onClick={() => onEdit(selected)}><Pencil /> Edit</Button><Button variant="ghost" aria-label="Toggle favorite" onClick={() => onToggle(selected, "favorite")}><Heart className={selected.payload.favorite ? "filled" : ""} /></Button><Button variant="ghost" aria-label="Toggle archive" onClick={() => onToggle(selected, "archived")}><Archive /></Button><Button variant="ghost" aria-label="View history" onClick={() => onHistory(selected)}><History /></Button><Button variant="ghost" className="danger-button" onClick={() => onDelete(selected)}><Trash2 /></Button></>}</div></aside>}</div>}</div>;
}

function AttachmentPanel({ vault, item }: { vault: WorkspaceVault; item: VaultItem }) {
  const [attachments, setAttachments] = useState<VaultAttachment[]>([]); const [busy, setBusy] = useState(false); const [message, setMessage] = useState("");
  async function refresh() { try { setAttachments(await listEncryptedAttachments(vault, item.id)); } catch (reason) { setMessage(customerError(reason, "Unable to load attachments. Try again.")); } }
  useEffect(() => { let active = true; listEncryptedAttachments(vault, item.id).then((next) => { if (active) setAttachments(next); }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load attachments. Try again.")); }); return () => { active = false; }; }, [item.id, vault]);
  async function upload(file: File) { setBusy(true); setMessage(""); try { await uploadEncryptedAttachment(vault, item.id, file); await refresh(); } catch (reason) { setMessage(customerError(reason, "This attachment could not be uploaded. Try again.")); } finally { setBusy(false); } }
  return <div className="attachment-panel"><span>Encrypted attachments</span>{attachments.map((attachment) => <button key={attachment.id} onClick={() => { setMessage(""); downloadEncryptedAttachment(vault, attachment).catch((reason) => setMessage(customerError(reason, "This attachment could not be decrypted or downloaded. Try again."))); }}><Paperclip /><span>{attachment.name}</span><small>{Math.max(1, Math.round(attachment.size / 1024))} KB</small><Download /></button>)}<label><Paperclip /><span>{busy ? "Encrypting…" : "Add attachment"}</span><input type="file" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.target.value = ""; }} /></label>{message && <small className="attachment-error">{message}</small>}</div>;
}

function DetailField({ label, value, copyable = false }: { label: string; value: string; copyable?: boolean }) { return <div className="detail-field"><span>{label}</span><div><p>{value}</p>{copyable && <CopyButton value={value} />}</div></div>; }
function CopyButton({ value, audit = true }: { value: string; audit?: boolean }) { return <PolicyCopyButton value={value} audit={audit} />; }


function GeneratorView() {
  const [mode, setMode] = useState<"password" | "passphrase">("password"); const [length, setLength] = useState(24); const [value, setValue] = useState(() => generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); const [options, setOptions] = useState({ uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true });
  function regenerate() { setValue(mode === "password" ? generatePassword({ length, ...options }) : generatePassphrase(7)); }
  return <div className="feature-page narrow-page"><Card className="generator-card"><CardHeader><span className="feature-icon"><WandSparkles /></span><CardTitle>Private password generator</CardTitle><CardDescription>Generated with the browser cryptographic random-number generator. Values never leave this device.</CardDescription></CardHeader><CardContent><div className="segmented"><button className={mode === "password" ? "active" : ""} onClick={() => { setMode("password"); setValue(generatePassword({ length, ...options })); }}>Password</button><button className={mode === "passphrase" ? "active" : ""} onClick={() => { setMode("passphrase"); setValue(generatePassphrase(7)); }}>Passphrase</button></div><div className="generated-value"><code>{value}</code><CopyButton value={value} /><button aria-label="Generate another" onClick={regenerate}><RefreshCw /></button></div>{mode === "password" && <><div className="range-row"><Label htmlFor="password-length">Length</Label><strong>{length}</strong><input id="password-length" type="range" min="12" max="64" value={length} onChange={(event) => { const next = Number(event.target.value); setLength(next); setValue(generatePassword({ length: next, ...options })); }} /></div><div className="option-grid">{(["uppercase", "lowercase", "numbers", "symbols", "avoidAmbiguous"] as const).map((key) => <label key={key}><input type="checkbox" disabled={key !== "avoidAmbiguous" && options[key] && [options.uppercase, options.lowercase, options.numbers, options.symbols].filter(Boolean).length === 1} checked={options[key]} onChange={(event) => { const next = { ...options, [key]: event.target.checked }; setOptions(next); try { setValue(generatePassword({ length, ...next })); } catch { /* wait for another option */ } }} /><span>{key === "avoidAmbiguous" ? "Avoid ambiguous" : key[0].toUpperCase() + key.slice(1)}</span></label>)}</div></>}<p className="field-hint">Passphrases use seven randomly selected words. <a href="/third-party-notices.txt" target="_blank" rel="noreferrer">Wordlist attribution</a></p><div className="privacy-note"><ShieldCheck /><span>Clipboard copies are cleared after 30 seconds when the copied value is still present.</span></div></CardContent></Card></div>;
}

type AccountPasskey = { id: string; friendly_name?: string; created_at: string; last_used_at?: string };

function AccountSecurityView() {
  const { refreshCompliance } = useEnterprise();
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]); const [busy, setBusy] = useState(false); const [loading, setLoading] = useState(passkeysEnabled); const [message, setMessage] = useState("");
  async function refresh() { if (!passkeysEnabled) return; const { data, error } = await supabase!.auth.passkey.list(); if (error) setMessage(customerError(error, "Your passkeys could not be loaded. Try again.")); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }
  useEffect(() => { if (!passkeysEnabled) return; let active = true; supabase!.auth.passkey.list().then(({ data, error }) => { if (!active) return; if (error) setMessage(customerError(error, "Your passkeys could not be loaded. Try again.")); else setPasskeys((data ?? []) as AccountPasskey[]); setLoading(false); }); return () => { active = false; }; }, []);
  async function register() { setBusy(true); setMessage(""); try { const { error } = await supabase!.auth.registerPasskey(); if (error) throw error; refreshCompliance(); setMessage("Passkey registered. Your vault password remains separate."); await refresh(); } catch (reason) { setMessage(customerError(reason, "Passkey registration could not be completed. Try again.")); } finally { setBusy(false); } }
  async function rename(passkey: AccountPasskey) { const friendlyName = window.prompt("Passkey name", passkey.friendly_name ?? "My passkey")?.trim(); if (!friendlyName) return; setBusy(true); const { error } = await supabase!.auth.passkey.update({ passkeyId: passkey.id, friendlyName }); if (error) setMessage(customerError(error, "This passkey could not be renamed. Try again.")); else await refresh(); setBusy(false); }
  async function remove(passkey: AccountPasskey) { if (!window.confirm(`Remove ${passkey.friendly_name ?? "this passkey"}? It will no longer sign in to Passkey-X.`)) return; setBusy(true); const { error } = await supabase!.auth.passkey.delete({ passkeyId: passkey.id }); if (error) setMessage(customerError(error, "This passkey could not be removed. Try again.")); else { setMessage("Passkey removed."); await refresh(); } setBusy(false); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Fingerprint /> Account protection</span><h2>Sign-in security</h2><p>Use phishing-resistant passkeys and optional mobile verification for your account. Neither method replaces or discloses the separate vault password.</p></div><Button disabled={!passkeysEnabled || busy} onClick={() => void register()}><Plus /> Add passkey</Button></div>{!passkeysEnabled && <Card className="passkey-readiness"><CardHeader><CardTitle>Passkeys are unavailable</CardTitle><CardDescription>Passwordless sign-in is not available in this environment. Continue using your login password; your encrypted vault is unaffected.</CardDescription></CardHeader></Card>}{passkeysEnabled && <Card><CardHeader><CardTitle>Your passkeys</CardTitle><CardDescription>Your public sign-in credential is stored securely. The private key remains on your authenticator and never leaves it.</CardDescription></CardHeader><CardContent>{loading ? <div className="loading-ring" /> : passkeys.length ? <div className="account-passkey-list">{passkeys.map((passkey) => <article key={passkey.id}><span className="device-icon"><Fingerprint /></span><div><strong>{passkey.friendly_name ?? "Passkey"}</strong><small>Added {new Date(passkey.created_at).toLocaleDateString()}{passkey.last_used_at ? ` · Last used ${new Date(passkey.last_used_at).toLocaleDateString()}` : ""}</small></div><Button variant="ghost" onClick={() => void rename(passkey)} disabled={busy}><Pencil /> Rename</Button><Button variant="outline" onClick={() => void remove(passkey)} disabled={busy}><Trash2 /> Remove</Button></article>)}</div> : <div className="small-empty"><Fingerprint /><strong>No passkeys registered</strong><span>Add one after signing in with your existing account method.</span></div>}</CardContent></Card>}<TotpCard /><PhoneMfaCard />{message && <p className="settings-message" role="status">{message}</p>}<div className="privacy-note"><ShieldCheck /><span>Account authentication establishes a session only. Client-side Argon2id and AES-256-GCM vault encryption are unchanged.</span></div></div>;
}

function PhoneMfaCard() {
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

function DevicesView({ identityId }: { identityId: string }) {
  const [devices, setDevices] = useState<DeviceRow[]>([]); const [loading, setLoading] = useState(true); const [message, setMessage] = useState("");
  async function refresh() { const { data, error } = await supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }); if (error) setMessage(customerError(error, "Your devices could not be loaded. Try again.")); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }
  useEffect(() => { let active = true; supabase!.from("devices").select("id,status,created_at,last_seen_at,revoked_at").eq("identity_id", identityId).order("created_at", { ascending: false }).then(({ data, error }) => { if (!active) return; if (error) setMessage(customerError(error, "Your devices could not be loaded. Try again.")); else setDevices((data ?? []) as DeviceRow[]); setLoading(false); }); return () => { active = false; }; }, [identityId]);
  async function revoke(device: DeviceRow) { if (!window.confirm("Revoke this device? It cannot be trusted again.")) return; const { error } = await supabase!.from("devices").update({ status: "revoked", revoked_at: new Date().toISOString() }).eq("id", device.id).neq("status", "revoked"); if (error) setMessage(customerError(error, "This device could not be revoked. Try again.")); else await refresh(); }
  return <div className="feature-page"><div className="feature-intro"><div><span className="status-pill"><Laptop /> Trusted-device boundary</span><h2>Devices with vault access</h2><p>Free accounts support two active devices. Revocation is one-way and removes device-key eligibility.</p></div></div>{message && <p className="form-message" role="alert">{message}</p>}<div className="device-list">{loading ? <div className="loading-ring" /> : devices.map((device, index) => <Card key={device.id}><CardContent><span className="device-icon"><Laptop /></span><div><strong>{index === devices.length - 1 ? "Initial browser" : `Browser device ${devices.length - index}`}</strong><span>Added {new Date(device.created_at).toLocaleDateString()} · {device.status}</span><code>{device.id.slice(0, 8)}…{device.id.slice(-4)}</code></div><span className={`device-status ${device.status}`}>{device.status}</span>{device.status !== "revoked" && <Button variant="outline" onClick={() => revoke(device)}>Revoke</Button>}</CardContent></Card>)}</div><div className="privacy-note"><ShieldCheck /><span>Passkey-X stores only a public device key and encrypted labels. Private device key material stays protected in the client.</span></div></div>;
}

function formatPrice(price: BillingPrice | undefined) {
  if (!price) return "Not configured";
  return new Intl.NumberFormat(price.currency === "inr" ? "en-IN" : "en-US", {
    style: "currency", currency: price.currency.toUpperCase(), maximumFractionDigits: price.currency === "inr" ? 0 : 2,
  }).format(price.unitAmount / 100);
}

function formatCatalogPrice(plan: PublicCatalogPlan, currency: BillingCurrency, interval: BillingInterval) {
  if (plan.billingModel === "contract") return "Custom";
  const price = plan.prices.find((entry) => entry.currency === currency && entry.interval === interval);
  if (!price) return "Not available";
  return new Intl.NumberFormat(currency === "inr" ? "en-IN" : "en-US", {
    style: "currency", currency: currency.toUpperCase(), maximumFractionDigits: currency === "inr" ? 0 : 2,
  }).format(price.unitAmount / 100);
}

function BillingView({ vault, entitlement, onRefresh }: { vault: WorkspaceVault; entitlement: Entitlement; onRefresh: () => Promise<void> }) {
  const [currency, setCurrency] = useState<BillingCurrency>("inr");
  const [interval, setInterval] = useState<BillingInterval>("month");
  const [prices, setPrices] = useState<BillingPrice[]>([]);
  const [catalogPlans, setCatalogPlans] = useState<PublicCatalogPlan[]>([]);
  const [selectedPlan] = useState<Exclude<PlanCode, "free"> | null>(() => readPlanSelection());
  const [seatCounts, setSeatCounts] = useState({ team: 3, business: 5 });
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState(() => {
    if (typeof window === "undefined") return "";
    const result = new URLSearchParams(window.location.search).get("billing");
    if (result === "success") return "Checkout completed. Your plan activates only after the signed Stripe webhook is verified.";
    if (result === "cancelled") return "Checkout was cancelled. Your current plan is unchanged.";
    if (result === "portal-return") return "Billing portal closed. Refresh to read the latest verified entitlement.";
    const selected = readPlanSelection();
    return selected ? `You selected ${selected[0].toUpperCase() + selected.slice(1)}. Confirm the billing options below to continue.` : "";
  });
  const canManage = vault.role === "owner";

  useEffect(() => {
    let active = true;
    loadPublicPlanCatalog()
      .then((catalog) => { if (active) setCatalogPlans(catalog); })
      .catch(() => { if (active) setMessage("The launch catalog could not be loaded. Your current plan is unchanged."); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    if (!billingEnabled || !canManage) return () => { active = false; };
    loadBillingCatalog(vault.tenantId)
      .then((catalog) => { if (active) setPrices(catalog); })
      .catch((reason) => { if (active) setMessage(customerError(reason, "Plan pricing could not be loaded. Your current plan is unchanged.")); });
    return () => { active = false; };
  }, [canManage, vault.tenantId]);

  async function checkout(plan: Exclude<PlanCode, "free">) {
    setBusy(plan); setMessage("");
    const quantity = plan === "team" || plan === "business" ? seatCounts[plan] : 1;
    try { const url = await beginCheckout(vault.tenantId, plan, interval, currency, quantity); clearPlanSelection(); window.location.assign(url); }
    catch (reason) { setMessage(customerError(reason, "Checkout could not be started. Your current plan is unchanged.")); setBusy(""); }
  }

  async function portal() {
    setBusy("portal"); setMessage("");
    try { window.location.assign(await openCustomerPortal(vault.tenantId)); }
    catch (reason) { setMessage(customerError(reason, "The billing portal could not be opened. Try again shortly.")); setBusy(""); }
  }

  async function refresh() {
    setBusy("refresh"); setMessage("");
    try { await onRefresh(); setMessage("Verified workspace entitlement refreshed."); }
    catch { setMessage("The entitlement could not be refreshed. Try again shortly."); }
    finally { setBusy(""); }
  }

  return <div className="feature-page billing-page"><div className="feature-intro"><div><span className="status-pill"><CreditCard /> SaaS workspace billing</span><h2>Choose the right protection for this workspace</h2><p>Checkout and subscription management are hosted by Stripe. Passkey-X receives billing status only—never card details or vault contents.</p></div><div className="billing-status"><small>Current plan</small><strong>{entitlement.plan_code}</strong><span>{entitlement.subscription_status.replaceAll("_", " ")}</span></div></div>
    <div className="billing-toolbar"><div className="billing-segment" role="group" aria-label="Billing currency"><button className={currency === "inr" ? "active" : ""} onClick={() => setCurrency("inr")}>INR</button><button className={currency === "usd" ? "active" : ""} onClick={() => setCurrency("usd")}>USD</button></div><div className="billing-segment" role="group" aria-label="Billing interval"><button className={interval === "month" ? "active" : ""} onClick={() => setInterval("month")}>Monthly</button><button className={interval === "year" ? "active" : ""} onClick={() => setInterval("year")}>Annual</button></div>{entitlement.source === "stripe" && <Button variant="outline" disabled={!canManage || busy !== ""} onClick={() => void portal()}><CreditCard /> {busy === "portal" ? "Opening…" : "Manage billing"}</Button>}<Button variant="ghost" disabled={busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button></div>
    {stripeTestMode && <div className="billing-notice"><ShieldAlert /><div><strong>Stripe sandbox checkout</strong><p>Use Stripe test cards only. No real payment will be collected and sandbox subscriptions must not be treated as commercial orders.</p></div></div>}
    {!billingEnabled && <div className="billing-notice"><ShieldCheck /><div><strong>Test billing is safely disabled</strong><p>Checkout stays unavailable until all twenty Stripe test Price IDs, the restricted key, and the signed webhook secret are installed in Supabase.</p></div></div>}
    {!canManage && <div className="billing-notice"><ShieldAlert /><div><strong>Workspace owner access required</strong><p>Members can see the verified plan. Only an owner can start Checkout or open the Customer Portal.</p></div></div>}
    <div className="pricing-grid">{catalogPlans.map((plan) => { const livePrice = prices.find((entry) => entry.plan === plan.code && entry.currency === currency && entry.interval === interval); const current = entitlement.plan_code === plan.code; const selected = selectedPlan === plan.code; const canCheckout = ["personal", "family", "professional", "team", "business"].includes(plan.code); const displayPrice = livePrice ? formatPrice(livePrice) : formatCatalogPrice(plan, currency, interval); const seatPlan = plan.code === "team" || plan.code === "business" ? plan.code : null; const seatCount = seatPlan ? seatCounts[seatPlan] : 1; const minimumSeats = plan.minSeats ?? 1; const maximumSeats = plan.maxSeats ?? minimumSeats; return <Card key={plan.code} className={`pricing-card ${current ? "current" : ""} ${selected ? "selected" : ""} ${plan.code === "business" ? "featured" : ""}`}><CardHeader>{plan.code === "business" && <span className="popular-pill">For offices</span>}{selected && !current && <span className="selected-plan-pill">Your selection</span>}<CardTitle>{plan.name}</CardTitle><CardDescription>{plan.summary}</CardDescription></CardHeader><CardContent><div className="plan-price"><strong>{displayPrice}</strong><span>{plan.billingModel === "per_seat" ? `per user / ${interval}` : plan.billingModel === "contract" ? "contract pricing" : plan.code === "free" ? "forever" : `per ${interval}`}</span>{plan.trialDays > 0 && <small>{plan.trialDays}-day test trial</small>}</div>{seatPlan && <div><Label htmlFor={`billing-seats-${seatPlan}`}>Seats</Label><Input id={`billing-seats-${seatPlan}`} type="number" inputMode="numeric" min={minimumSeats} max={maximumSeats} value={seatCount} onChange={(event) => { const next = Number(event.target.value); setSeatCounts((currentCounts) => ({ ...currentCounts, [seatPlan]: Number.isSafeInteger(next) ? Math.min(maximumSeats, Math.max(minimumSeats, next)) : minimumSeats })); }} /><p className="field-hint">{minimumSeats}–{maximumSeats} users · Checkout quantity is validated on the server.</p></div>}<ul>{plan.features.slice(0, 6).map((feature) => <li key={feature}><Check /> {feature}</li>)}</ul>{plan.code === "free" ? <Button variant="outline" disabled>{current ? "Current plan" : "Included"}</Button> : plan.code === "enterprise" ? <Button variant="outline" disabled>Sales-assisted</Button> : !canCheckout ? <Button variant="outline" disabled>Checkout pending</Button> : <Button disabled={!billingEnabled || !canManage || !livePrice || busy !== "" || current} onClick={() => void checkout(plan.code as Exclude<PlanCode, "free">)}>{current ? "Current plan" : busy === plan.code ? "Opening secure Checkout…" : `Choose ${plan.name}`}</Button>}</CardContent></Card>; })}</div>
    {message && <p className="settings-message" role="status">{message}</p>}<div className="privacy-note"><ShieldCheck /><span>Plan access changes only after a verified Stripe webhook updates the tenant entitlement. Redirect query parameters cannot unlock paid features.</span></div><p className="billing-footnote">Taxes are not calculated or collected until Vlightsoft confirms the required registrations and explicitly enables Stripe Tax.</p>
  </div>;
}

function SettingsView({ email, items, vault, profile, entitlement, onImported, onProfileChange, onPasswordFacts }: { email: string; items: VaultItem[]; vault: WorkspaceVault; profile: CryptoProfile; entitlement: Entitlement; onImported: () => Promise<void> | void; onProfileChange: (profile: CryptoProfile) => void; onPasswordFacts: (facts: VaultPasswordFacts) => void }) {
  const { canExport, policy, record } = useEnterprise();
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false); const [exportPassword, setExportPassword] = useState(""); const [showExport, setShowExport] = useState(false);
  async function exportVault(event: React.FormEvent) { event.preventDefault(); if (!canExport) { record("policy.blocked", null); setMessage("Your organization's policy does not allow vault export."); setShowExport(false); return; } setBusy(true); setMessage(""); let master: Uint8Array | null = null; let verified: Uint8Array | null = null; try { master = await deriveMasterKey(exportPassword, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters }); verified = await unwrapKey(master, { algorithm: "AES-256-GCM", nonce: toBase64Url(bytea(profile.master_nonce)), ciphertext: toBase64Url(bytea(profile.master_wrapped_root)) }, "1accessos:account-root:v1"); const data = await createEncryptedExport({ product: "Passkey-X", version: 1, items }, exportPassword); downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), `passkey-x-export-${new Date().toISOString().slice(0, 10)}.pxvault`); setExportPassword(""); setShowExport(false); record("vault.exported", null); setMessage("Encrypted export download started."); } catch { setMessage("Vault reauthentication failed or the browser blocked the download; no export was saved."); } finally { master?.fill(0); verified?.fill(0); setBusy(false); } }
  return <div className="feature-page"><div className="settings-grid"><Card><CardHeader><CardTitle>Account</CardTitle><CardDescription>Signed in as {email}</CardDescription></CardHeader><CardContent><div className="setting-row"><span>Plan</span><strong>{entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1)}</strong></div><div className="setting-row"><span>Billing status</span><strong>{entitlement.subscription_status.replaceAll("_", " ")}</strong></div><div className="setting-row"><span>Encryption</span><strong>Argon2id + AES-256-GCM</strong></div><div className="setting-row"><span>Workspace</span><code>{vault.workspaceId.slice(0, 8)}…</code></div></CardContent></Card><ImportCard vault={vault} onImported={onImported} /><Card><CardHeader><CardTitle>Encrypted backup</CardTitle><CardDescription>Reauthenticate with your vault password before a portable encrypted export is created.</CardDescription></CardHeader><CardContent>{canExport ? <Button variant="outline" onClick={() => setShowExport(true)}><Download /> Export {items.length} items</Button> : <p className="field-hint">Export is {policy.exportMode === "blocked" ? "disabled" : "limited to owners and admins"} by your organization.</p>}</CardContent></Card><Card><CardHeader><CardTitle>Workspace entitlement</CardTitle><CardDescription>Plan access is tenant-scoped and controlled by verified server-side billing events.</CardDescription></CardHeader><CardContent><p className="field-hint">Use Plans & billing to compare tiers or manage an active Stripe subscription. Billing never receives vault fields.</p></CardContent></Card><ChangeVaultPasswordCard profile={profile} onProfileChange={onProfileChange} onPasswordChanged={onPasswordFacts} /><AccountDeletionCard email={email} /></div>{message && <p className="settings-message" role="status">{message}</p>}{showExport && <div className="modal-backdrop"><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="export-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={() => setShowExport(false)}><X /></button><CardTitle id="export-title">Confirm encrypted export</CardTitle><CardDescription>Enter your vault password. The export is encrypted locally with a fresh salt.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={exportVault}><div><Label htmlFor="export-password">Vault password</Label><Input id="export-password" type="password" autoComplete="current-password" required value={exportPassword} onChange={(event) => setExportPassword(event.target.value)} /></div><Button disabled={busy}>{busy ? "Encrypting…" : "Reauthenticate and download"}</Button></form></CardContent></Card></div>}</div>;
}

function ItemEditor({ item, initialSecret, onClose, onSave }: { item?: VaultItem; initialSecret?: string; onClose: () => void; onSave: (kind: ItemKind, payload: VaultPayload) => Promise<void> }) {
  const [kind, setKind] = useState<ItemKind>(item?.contentType ?? "login"); const [title, setTitle] = useState(item?.payload.title ?? ""); const [username, setUsername] = useState(item?.payload.username ?? ""); const [secret, setSecret] = useState(initialSecret ?? item?.payload.secret ?? ""); const [url, setUrl] = useState(item?.payload.url ?? ""); const [notes, setNotes] = useState(item?.payload.notes ?? ""); const [tags, setTags] = useState(item?.payload.tags?.join(", ") ?? ""); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(""); const meta = ITEM_TYPES[kind];
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { const now = new Date().toISOString(); await onSave(kind, { ...item?.payload, version: 1, passwordChangedAt: !item || (item.payload.secret ?? "") !== secret ? (secret ? now : undefined) : item.payload.passwordChangedAt ?? item.payload.updatedAt, title: title.trim(), username: username.trim() || undefined, secret: secret || undefined, url: url.trim() || undefined, notes: notes.trim() || undefined, tags: tags.split(",").map((value) => value.trim()).filter(Boolean), favorite: item?.payload.favorite ?? false, archived: item?.payload.archived ?? false, updatedAt: now }); } catch (reason) { setMessage(customerError(reason, "Unable to save this item. Try again.")); setBusy(false); } }
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="editor-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={onClose}><X /></button><CardTitle id="editor-title">{item ? "Edit encrypted item" : "Add encrypted item"}</CardTitle><CardDescription>Everything below is encrypted in this browser before it leaves the device.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={submit}><div><Label htmlFor="item-kind">Type</Label><select id="item-kind" value={kind} disabled={Boolean(item)} onChange={(event) => setKind(event.target.value as ItemKind)}>{(Object.keys(ITEM_TYPES) as ItemKind[]).map((value) => <option key={value} value={value}>{ITEM_TYPES[value].label}</option>)}</select></div><div><Label htmlFor="item-title">Name</Label><Input id="item-title" required autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="A name you will recognize" /></div>{kind !== "secure-note" && <div><Label htmlFor="item-username">{meta.userLabel ?? "Username"}</Label><Input id="item-username" value={username} onChange={(event) => setUsername(event.target.value)} /></div>}{kind !== "secure-note" && <div><div className="label-row"><Label htmlFor="item-secret">{meta.secretLabel ?? "Secret"}</Label>{kind === "login" && <button type="button" onClick={() => setSecret(generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true }))}><WandSparkles /> Generate</button>}</div><Input id="item-secret" value={secret} onChange={(event) => setSecret(event.target.value)} /></div>}<div><Label htmlFor="item-url">Website or host</Label><Input id="item-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https:// or host name" /></div><div><Label htmlFor="item-tags">Tags</Label><Input id="item-tags" value={tags} onChange={(event) => setTags(event.target.value)} placeholder="work, finance, production" /></div><div><Label htmlFor="item-notes">Notes</Label><textarea id="item-notes" rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></div>{message && <p className="form-message" role="alert">{message}</p>}<div className="editor-actions"><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button disabled={busy}>{busy ? "Encrypting…" : "Encrypt and save"}</Button></div></form></CardContent></Card></div>;
}

function HistoryDialog({ item, history, onClose }: { item: VaultItem; history: VaultHistoryEntry[]; onClose: () => void }) { return <div className="modal-backdrop"><Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="history-title"><CardHeader><button className="modal-close" aria-label="Close" onClick={onClose}><X /></button><CardTitle id="history-title">Revision history</CardTitle><CardDescription>{item.payload.title} · decrypted locally</CardDescription></CardHeader><CardContent><div className="history-list">{history.map((entry) => <article key={entry.revision}><span>v{entry.revision}</span><div><strong>{new Date(entry.createdAt).toLocaleString()}</strong><small>{entry.payload.title}{entry.payload.username ? ` · ${entry.payload.username}` : ""}</small></div></article>)}</div></CardContent></Card></div>; }
