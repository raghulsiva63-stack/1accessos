"use client";

import { useEffect, useState } from "react";
import { Fingerprint, Keyboard, Laptop, MonitorOff, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { CryptoProfile } from "@/components/app/shell/shared";
import {
  biometricLabel, DEFAULT_DESKTOP_SETTINGS, desktop, type DesktopInfo, type DesktopSettings, profileFingerprint,
} from "@/lib/desktop/bridge";
import { toBase64Url } from "@/lib/crypto/vault";

const CLIPBOARD_CHOICES = [15, 30, 60, 90];

/** Settings > This computer (desktop app only). */
export function DesktopSettingsPanel({ profile, rootKey }: { profile: CryptoProfile; rootKey: Uint8Array }) {
  const [info, setInfo] = useState<DesktopInfo | null>(null);
  const [settings, setSettings] = useState<DesktopSettings>(DEFAULT_DESKTOP_SETTINGS);
  const [enrolled, setEnrolled] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    (async () => {
      const [nextInfo, nextSettings] = await Promise.all([desktop.info(), desktop.settings()]);
      const fingerprint = await profileFingerprint(profile.master_wrapped_root, profile.salt);
      const nextEnrolled = nextInfo.biometric ? await desktop.biometric.enrolled(profile.identity_id, fingerprint) : false;
      if (!active) return;
      setInfo(nextInfo); setSettings(nextSettings); setEnrolled(nextEnrolled);
    })().catch(() => { if (active) setMessage("Desktop settings could not be loaded."); });
    return () => { active = false; };
  }, [profile.identity_id, profile.master_wrapped_root, profile.salt]);

  async function save(next: DesktopSettings) {
    setMessage("");
    try { setSettings(await desktop.saveSettings(next)); }
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
      setMessage(result === "declined" ? "The update will be offered again next time." : result === "none" ? "You have the latest version." : "Automatic updates are not available in this build. Download the latest version from passkey-x.com/download.");
    } catch { setMessage("Could not check for updates. Try again later."); }
    finally { setBusy(false); }
  }

  if (!info) return message ? <p className="form-message">{message}</p> : null;
  const label = biometricLabel(info.biometric);
  return <section className="desktop-settings" aria-labelledby="desktop-settings-title">
    <h3 id="desktop-settings-title"><Laptop /> This computer</h3>
    <p className="field-hint">Passkey-X {info.version} for {info.os === "macos" ? "macOS" : info.os === "windows" ? "Windows" : "Linux"}. These settings apply to this app only.</p>
    <ul className="desktop-settings-list">
      <li>
        <span className="desktop-settings-icon"><Fingerprint /></span>
        <div><strong>{label ? `Unlock with ${label}` : "Fingerprint or face unlock"}</strong>
          <p>{label ? "Unlock without typing your vault password. You'll need the password again after you change it or sign out." : "Not available on this computer. Use your vault password."}</p></div>
        {label && <Button variant={enrolled ? "outline" : "default"} disabled={busy} onClick={() => void toggleBiometric()}>{enrolled ? "Turn off" : "Turn on"}</Button>}
      </li>
      <li>
        <span className="desktop-settings-icon"><Keyboard /></span>
        <div><strong>Quick access shortcut {info.hotkey && <kbd>{info.hotkey}</kbd>}</strong>
          <p>{settings.hotkeyEnabled && !info.hotkeyActive ? "Another app is using this shortcut, so it isn't active." : "Open Passkey-X over any app, find a login and copy it."}</p></div>
        <label className="switch-row"><input type="checkbox" checked={settings.hotkeyEnabled} onChange={(event) => void save({ ...settings, hotkeyEnabled: event.target.checked })} /> On</label>
      </li>
      <li>
        <span className="desktop-settings-icon"><ShieldCheck /></span>
        <div><strong>Locking</strong>
          <p>{info.os === "linux" ? "The vault always locks when your computer sleeps, when you quit, and after your idle time." : "The vault always locks when your computer sleeps or the screen locks, when you quit, and after your idle time."}</p>
          <label className="switch-row"><input type="checkbox" checked={settings.lockOnBlur} onChange={(event) => void save({ ...settings, lockOnBlur: event.target.checked })} /> Also lock when I switch to another app</label>
          <label className="switch-row"><input type="checkbox" checked={settings.lockOnHide} onChange={(event) => void save({ ...settings, lockOnHide: event.target.checked })} /> Also lock when the window is hidden</label>
        </div>
      </li>
      <li>
        <span className="desktop-settings-icon"><MonitorOff /></span>
        <div><strong>Clipboard and screen</strong>
          <p>Copied passwords are hidden from clipboard history and cleared after
            {" "}<select aria-label="Clear clipboard after" value={settings.clipboardSeconds} onChange={(event) => void save({ ...settings, clipboardSeconds: Number(event.target.value) })}>{CLIPBOARD_CHOICES.map((value) => <option key={value} value={value}>{value} seconds</option>)}</select>.
            {" "}{info.contentProtection ? "Screenshots and screen sharing show a blank window." : "Screenshot blocking isn't supported on this system."}</p></div>
      </li>
      <li>
        <span className="desktop-settings-icon"><RefreshCw /></span>
        <div><strong>Updates</strong><p>{info.updater ? "Updates are checked automatically and only installed if they carry Vlightsoft's signature." : "Download new versions from passkey-x.com/download."}</p></div>
        <Button variant="outline" disabled={busy} onClick={() => void update()}>Check for updates</Button>
      </li>
    </ul>
    {message && <p className="form-message" role="status">{message}</p>}
  </section>;
}
