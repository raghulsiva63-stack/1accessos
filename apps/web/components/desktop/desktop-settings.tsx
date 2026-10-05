"use client";

import { useEffect, useState } from "react";
import { Building2, CloudOff, Fingerprint, Keyboard, Laptop, Link2, MonitorOff, Power, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { CryptoProfile } from "@/components/app/shell/shared";
import {
  biometricLabel, DEFAULT_DESKTOP_SETTINGS, desktop, desktopPolicy, type DesktopInfo, type DesktopPolicy, type DesktopSettings, profileFingerprint, UNMANAGED_POLICY,
} from "@/lib/desktop/bridge";
import { BrowserPairingsList } from "@/components/desktop/browser-link";
import { SecurityCheckPanel } from "@/components/desktop/security-check";
import { removeAllPairings } from "@/lib/desktop/browser-link";
import { configureOfflineCache } from "@/lib/desktop/offline-cache";
import { toBase64Url } from "@/lib/crypto/vault";

const CLIPBOARD_CHOICES = [15, 30, 60, 90];

/** Settings > This computer (desktop app only). */
export function DesktopSettingsPanel({ profile, rootKey }: { profile: CryptoProfile; rootKey: Uint8Array }) {
  const [info, setInfo] = useState<DesktopInfo | null>(null);
  const [settings, setSettings] = useState<DesktopSettings>(DEFAULT_DESKTOP_SETTINGS);
  const [policy, setPolicy] = useState<DesktopPolicy>(UNMANAGED_POLICY);
  const [enrolled, setEnrolled] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    (async () => {
      const [nextInfo, nextSettings, nextPolicy] = await Promise.all([desktop.info(), desktop.settings(), desktopPolicy()]);
      const fingerprint = await profileFingerprint(profile.master_wrapped_root, profile.salt);
      const nextEnrolled = nextInfo.biometric ? await desktop.biometric.enrolled(profile.identity_id, fingerprint) : false;
      if (!active) return;
      setInfo(nextInfo); setSettings(nextSettings); setPolicy(nextPolicy); setEnrolled(nextEnrolled);
    })().catch(() => { if (active) setMessage("Desktop settings could not be loaded."); });
    return () => { active = false; };
  }, [profile.identity_id, profile.master_wrapped_root, profile.salt]);

  async function save(next: DesktopSettings) {
    setMessage("");
    try {
      const saved = await desktop.saveSettings(next);
      setSettings(saved);
      if (saved.offlineAccess !== settings.offlineAccess) await configureOfflineCache(saved.offlineAccess);
      if (settings.browserIntegration && !saved.browserIntegration) await removeAllPairings();
    }
    catch { setMessage("That setting could not be saved."); }
  }

  async function toggleBiometric() {
    if (!info?.biometric) return;
    setBusy(true); setMessage("");
    try {
      if (enrolled) {
        await desktop.biometric.remove(profile.identity_id);
        setEnrolled(false);
        setMessage(`${biometricLabel(info.biometric)} unlock is off on this computer.`);
      } else {
        const fingerprint = await profileFingerprint(profile.master_wrapped_root, profile.salt);
        // The key is protected by the system (Windows Hello key or macOS Keychain) and only
        // released after a fingerprint, face or device PIN check.
        await desktop.biometric.enroll(profile.identity_id, toBase64Url(rootKey), fingerprint);
        setEnrolled(true);
        setMessage(`${biometricLabel(info.biometric)} unlock is on. You'll still need your vault password after changing it or on a new computer.`);
      }
    } catch { setMessage("Fingerprint/face unlock could not be changed. Make sure it is set up in your system settings."); }
    finally { setBusy(false); }
  }

  async function update() {
    setBusy(true); setMessage("");
    try {
      const result = await desktop.checkForUpdates();
      setMessage(result === "managed" ? "Your organization's IT installs updates on this computer." : result === "declined" ? "The update will be offered again next time." : result === "none" ? "You have the latest version." : "Automatic updates are not available in this build. Download the latest version from passkey-x.com/download.");
    } catch { setMessage("Could not check for updates. Try again later."); }
    finally { setBusy(false); }
  }

  if (!info) return message ? <p className="form-message">{message}</p> : null;
  const label = biometricLabel(info.biometric);
  const enforced = (value: boolean | number | null) => value !== null;
  const managedHint = <small className="managed-hint">Set by {policy.organizationName ?? "your organization"}</small>;
  return <><section className="desktop-settings" aria-labelledby="desktop-settings-title">
    <h3 id="desktop-settings-title"><Laptop /> This computer</h3>
    <p className="field-hint">Passkey-X {info.version} for {info.os === "macos" ? "macOS" : info.os === "windows" ? "Windows" : "Linux"}. These settings apply to this app only.</p>
    {policy.managed && <p className="desktop-managed-note" role="note"><Building2 aria-hidden="true" /><span>{policy.organizationName ?? "Your organization"} manages this computer. Some settings are fixed by IT.{policy.supportUrl ? <> <a href={policy.supportUrl} target="_blank" rel="noreferrer">Get help</a></> : null}</span></p>}
    <ul className="desktop-settings-list">
      <li>
        <span className="desktop-settings-icon"><Fingerprint /></span>
        <div><strong>{label ? `Unlock with ${label}` : "Fingerprint or face unlock"}</strong>
          <p>{policy.disableBiometric ? "Turned off by your organization. Use your vault password." : label ? "Unlock without typing your vault password. You'll need the password again after you change it or sign out." : "Not available on this computer. Use your vault password."}</p></div>
        {label && <Button variant={enrolled ? "outline" : "default"} disabled={busy} onClick={() => void toggleBiometric()}>{enrolled ? "Turn off" : "Turn on"}</Button>}
      </li>
      <li>
        <span className="desktop-settings-icon"><Keyboard /></span>
        <div><strong>Quick access shortcut {info.hotkey && <kbd>{info.hotkey}</kbd>}</strong>
          <p>{settings.hotkeyEnabled && !info.hotkeyActive ? "Another app is using this shortcut, so it isn't active." : "Open Passkey-X over any app, find a login and copy it."}</p></div>
        <label className="switch-row"><input type="checkbox" checked={settings.hotkeyEnabled} disabled={enforced(policy.hotkeyEnabled)} onChange={(event) => void save({ ...settings, hotkeyEnabled: event.target.checked })} /> On</label>
        {enforced(policy.hotkeyEnabled) && managedHint}
      </li>
      <li>
        <span className="desktop-settings-icon"><ShieldCheck /></span>
        <div><strong>Locking</strong>
          <p>{info.os === "linux" ? "The vault always locks when your computer sleeps, when you quit, and after your idle time." : "The vault always locks when your computer sleeps or the screen locks, when you quit, and after your idle time."}</p>
          <label className="switch-row"><input type="checkbox" checked={settings.lockOnBlur} disabled={enforced(policy.lockOnBlur)} onChange={(event) => void save({ ...settings, lockOnBlur: event.target.checked })} /> Also lock when I switch to another app</label>
          <label className="switch-row"><input type="checkbox" checked={settings.lockOnHide} disabled={enforced(policy.lockOnHide)} onChange={(event) => void save({ ...settings, lockOnHide: event.target.checked })} /> Also lock when the window is hidden</label>
          {policy.idleLockMinutes && <p className="field-hint">Your organization locks the vault after {policy.idleLockMinutes} idle minute{policy.idleLockMinutes === 1 ? "" : "s"} at most.</p>}
        </div>
      </li>
      <li>
        <span className="desktop-settings-icon"><MonitorOff /></span>
        <div><strong>Clipboard and screen</strong>
          <p>Copied passwords are hidden from clipboard history and cleared after
            {" "}<select aria-label="Clear clipboard after" value={settings.clipboardSeconds} onChange={(event) => void save({ ...settings, clipboardSeconds: Number(event.target.value) })}>{CLIPBOARD_CHOICES.filter((value) => !policy.maxClipboardSeconds || value <= policy.maxClipboardSeconds).map((value) => <option key={value} value={value}>{value} seconds</option>)}</select>.
            {" "}{info.contentProtection ? "Screenshots and screen sharing show a blank window." : "Screenshot blocking isn't supported on this system."}</p></div>
      </li>
      <li>
        <span className="desktop-settings-icon"><Power /></span>
        <div><strong>Start with my computer</strong>
          <p>Passkey-X starts in the {info.os === "macos" ? "menu bar" : "system tray"} when you sign in, so quick access is ready. The vault stays locked until you open it.</p></div>
        <label className="switch-row"><input type="checkbox" checked={settings.autoStart} disabled={enforced(policy.autoStart)} onChange={(event) => void save({ ...settings, autoStart: event.target.checked })} /> On</label>
        {enforced(policy.autoStart) && managedHint}
      </li>
      <li>
        <span className="desktop-settings-icon"><CloudOff /></span>
        <div><strong>Use without internet</strong>
          <p>Keep an encrypted copy of your vault on this computer so you can unlock and read it offline. Changes still need a connection. Turning this off deletes the copy.</p></div>
        <label className="switch-row"><input type="checkbox" checked={settings.offlineAccess} disabled={enforced(policy.offlineAccess)} onChange={(event) => void save({ ...settings, offlineAccess: event.target.checked })} /> On</label>
        {enforced(policy.offlineAccess) && managedHint}
      </li>
      <li>
        <span className="desktop-settings-icon"><Link2 /></span>
        <div><strong>Browser extension</strong>
          <p>Let the Passkey-X extension in Chrome, Edge or Brave unlock while this app is unlocked, after you approve it here with a matching code. It locks when this app locks.</p>
          {settings.browserIntegration && <BrowserPairingsList />}</div>
        <label className="switch-row"><input type="checkbox" checked={settings.browserIntegration} disabled={enforced(policy.browserIntegration)} onChange={(event) => void save({ ...settings, browserIntegration: event.target.checked })} /> On</label>
        {enforced(policy.browserIntegration) && managedHint}
      </li>
      <li>
        <span className="desktop-settings-icon"><RefreshCw /></span>
        <div><strong>Updates</strong><p>{policy.disableUpdates ? "Your organization's IT installs updates on this computer." : info.updater ? "Updates are checked automatically and only installed if they carry Vlightsoft's signature." : "Download new versions from passkey-x.com/download."}</p></div>
        {!policy.disableUpdates && <Button variant="outline" disabled={busy} onClick={() => void update()}>Check for updates</Button>}
      </li>
    </ul>
    {message && <p className="form-message" role="status">{message}</p>}
  </section>
  <SecurityCheckPanel />
  </>;
}
