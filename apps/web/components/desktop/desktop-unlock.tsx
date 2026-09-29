"use client";

import { useEffect, useRef, useState } from "react";
import { Fingerprint } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { CryptoProfile } from "@/components/app/shell/shared";
import { biometricLabel, desktop, type DesktopInfo, isDesktopApp, profileFingerprint } from "@/lib/desktop/bridge";
import { fromBase64Url } from "@/lib/crypto/vault";

/**
 * "Unlock with Touch ID / Windows Hello" on the desktop unlock screen. Shown only when this
 * computer supports it and the person turned it on for this vault. If the vault password was
 * changed since, the saved unlock is ignored and removed.
 */
export function DesktopBiometricUnlock({ profile, onUnlock }: { profile: CryptoProfile; onUnlock: (key: Uint8Array) => void }) {
  const [kind, setKind] = useState<DesktopInfo["biometric"]>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const prompted = useRef(false);

  async function unlock() {
    setBusy(true); setMessage("");
    let key: Uint8Array | null = null;
    try {
      const fingerprint = await profileFingerprint(profile.master_wrapped_root, profile.salt);
      const secret = await desktop.biometric.unlock(profile.identity_id, fingerprint);
      if (!secret) { setMessage("Unlock with your vault password this time."); return; }
      key = fromBase64Url(secret);
      if (key.length !== 32 || document.hidden) throw new Error("rejected");
      onUnlock(key); key = null;
    } catch { setMessage("Fingerprint/face unlock didn't complete. Use your vault password."); }
    finally { key?.fill(0); setBusy(false); }
  }

  useEffect(() => {
    if (!isDesktopApp()) return;
    let active = true;
    (async () => {
      const info = await desktop.info();
      if (!info.biometric) return;
      const fingerprint = await profileFingerprint(profile.master_wrapped_root, profile.salt);
      const enrolled = await desktop.biometric.enrolled(profile.identity_id, fingerprint);
      if (!active) return;
      if (!enrolled) return;
      setKind(info.biometric);
      // Ask once when the unlock screen opens in the foreground.
      if (!prompted.current && document.hasFocus()) { prompted.current = true; void unlock(); }
    })().catch(() => undefined);
    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile.identity_id, profile.master_wrapped_root, profile.salt]);

  if (!kind) return null;
  return <>
    <Button type="button" size="lg" variant="outline" disabled={busy} onClick={() => void unlock()}><Fingerprint /> {busy ? "Waiting for " + biometricLabel(kind) + "…" : `Unlock with ${biometricLabel(kind)}`}</Button>
    {message && <p className="field-hint" role="status">{message}</p>}
  </>;
}
