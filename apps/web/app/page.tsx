"use client";

import { useEffect, useRef, useState } from "react";
import type { VaultPasswordFacts } from "@/components/enterprise/compliance-banner";
import { MfaChallengeScreen } from "@/components/enterprise/mfa";
import type { Session } from "@supabase/supabase-js";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useClientMode } from "@/lib/browser/client-mode";
import { isSupabaseConfigured, supabase } from "@/lib/supabase/client";
import { authSessionTransition } from "@/lib/auth/session-machine";
import { ConfigurationNotice, FatalNotice, AuthScreen, AccountPasswordReset, VaultSetup, UnlockScreen } from "@/components/app/shell/auth-screens";
import { type CryptoProfile, Brand, customerError } from "@/components/app/shell/shared";
import { VaultShell } from "@/components/app/shell/vault-shell";
import { DesktopFinishSetup, DesktopSignIn } from "@/components/desktop/desktop-sign-in";
import { DesktopBrowserLink } from "@/components/desktop/browser-link";
import { DesktopGuardRunner } from "@/components/desktop/security-check";
import { desktop, desktopPolicy, isDesktopApp, policyAllowsEmail } from "@/lib/desktop/bridge";
import { isNetworkError, lastOfflineProfile, saveOfflineProfile, serverReachable, configureOfflineCache, type OfflineProfile } from "@/lib/desktop/offline-cache";
import { parsePendingLink, PENDING_LINK_KEY } from "@/lib/desktop/handoff";

export default function Home() {
  return <><DesktopBrowserLink /><DesktopGuardRunner /><HomeScreen /></>;
}

function HomeScreen() {
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
  const sessionEmail = session?.user.email ?? "";
  // Desktop app: organization restrictions for this computer, and the saved copy for offline use.
  const [policyNotice, setPolicyNotice] = useState("");
  const [offlineProfile, setOfflineProfile] = useState<OfflineProfile<CryptoProfile> | null>(null);

  useEffect(() => {
    if (!isDesktopApp()) return;
    void configureOfflineCache(desktop.settings().then((settings) => settings.offlineAccess));
  }, []);

  // A managed computer only accepts accounts from the organization's email domains.
  useEffect(() => {
    if (!sessionUserId || !isDesktopApp()) return;
    let active = true;
    desktopPolicy().then((policy) => {
      if (!active || policyAllowsEmail(policy, sessionEmail)) return;
      const domains = policy.allowedEmailDomains.map((domain) => `@${domain}`).join(", ");
      setPolicyNotice(`${policy.organizationName ?? "Your organization"} manages this computer. Sign in with your ${domains} account.`);
      void supabase?.auth.signOut();
    });
    return () => { active = false; };
  }, [sessionUserId, sessionEmail]);

  // No session in the desktop app: if the servers can't be reached, offer the saved copy.
  useEffect(() => {
    if (loading || session || !isDesktopApp() || !supabase) return;
    let active = true;
    (async () => {
      const saved = await lastOfflineProfile<CryptoProfile>();
      if (!saved || !active) return;
      const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
      if (await serverReachable(`${url}/auth/v1/health`)) return;
      const policy = await desktopPolicy();
      const settings = await desktop.settings().catch(() => null);
      if (active && settings?.offlineAccess && policyAllowsEmail(policy, saved.email)) setOfflineProfile(saved);
    })().catch(() => undefined);
    return () => { active = false; };
  }, [loading, session]);

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
    supabase.from("account_crypto_profiles").select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root,recovery_nonce,recovery_wrapped_root,recovery_verifier").maybeSingle().then(async ({ data, error: profileError }) => {
      if (!active) return;
      if (profileError && isDesktopApp() && isNetworkError(profileError)) {
        // Offline in the desktop app: use the saved profile of this account, if there is one.
        const saved = await lastOfflineProfile<CryptoProfile>();
        if (!active) return;
        if (saved && saved.userId === sessionUserId) { setProfile(saved.profile); setLoading(false); return; }
      }
      if (profileError) setError(customerError(profileError, "Your secure vault profile could not be loaded. Try signing in again."));
      else if (data && isDesktopApp()) void saveOfflineProfile(sessionUserId, sessionEmail, data as CryptoProfile);
      setProfile(data as CryptoProfile | null); setLoading(false);
    });
    return () => { active = false; };
  }, [sessionUserId, sessionEmail, mfaState]);

  // Web: an SSO sign-in started on /desktop-link returns here; send it back to finish approving the desktop app.
  useEffect(() => {
    if (!sessionUserId || isDesktopApp()) return;
    try { if (parsePendingLink(window.sessionStorage.getItem(PENDING_LINK_KEY))) window.location.replace("/desktop-link/"); } catch { /* storage blocked */ }
  }, [sessionUserId]);

  const inDesktopApp = clientMode === "desktop" && isDesktopApp();
  if (loading || !clientMode) return <main className="center-screen"><div className="loading-ring" aria-label="Loading Passkey-X" /></main>;
  if (!isSupabaseConfigured) return <ConfigurationNotice />;
  if (accountRecovery && session) return <AccountPasswordReset email={session.user.email ?? "your account"} onComplete={() => { setAccountRecovery(false); void supabase?.auth.signOut(); }} />;
  if (error) return <FatalNotice message={error} />;
  if (session && mfaState === "checking") return <main className="center-screen"><div className="loading-ring" aria-label="Checking account security" /></main>;
  if (session && mfaState === "required") return <MfaChallengeScreen brand={<Brand />} onComplete={() => setMfaState("satisfied")} footer={<><Button type="button" variant="ghost" onClick={() => void supabase?.auth.signOut()}>Use another account</Button><div className="privacy-note"><ShieldCheck /><span>Two-step verification (authenticator app or SMS) verifies the account session only. It cannot reset the vault password, decrypt vault data, or replace the recovery key.</span></div></>} />;
  if (!session && inDesktopApp && offlineProfile) {
    // Offline: unlock the saved encrypted copy with the vault password (read-only until online).
    if (!rootKey) return <UnlockScreen profile={offlineProfile.profile} email={offlineProfile.email} onUnlock={(key) => { if (document.hidden) key.fill(0); else setRootKey(key); }} onProfileChange={() => undefined} />;
    return <VaultShell clientMode={clientMode} email={offlineProfile.email} profile={offlineProfile.profile} rootKey={rootKey} passwordFacts={null} onPasswordFacts={() => undefined} onProfileChange={() => undefined} onLock={() => { rootKey.fill(0); setRootKey(null); }} />;
  }
  if (!session) return inDesktopApp ? <DesktopSignIn notice={policyNotice} /> : <AuthScreen clientMode={clientMode} />;
  if (!profile && inDesktopApp) return <DesktopFinishSetup email={session.user.email ?? "your account"} />;
  if (!profile) return <VaultSetup email={session.user.email ?? "your account"} onComplete={setProfile} />;
  if (!rootKey) return <UnlockScreen profile={profile} email={session.user.email ?? ""} onUnlock={(key, facts) => { if (document.hidden || activeUserId.current !== sessionUserId) key.fill(0); else { setPasswordFacts(facts ?? null); setRootKey(key); } }} onProfileChange={setProfile} />;
  return <VaultShell clientMode={clientMode} email={session.user.email ?? ""} profile={profile} rootKey={rootKey} passwordFacts={passwordFacts} onPasswordFacts={setPasswordFacts} onProfileChange={setProfile} onLock={() => { rootKey.fill(0); setRootKey(null); }} />;
}
