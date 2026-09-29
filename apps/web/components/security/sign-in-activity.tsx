"use client";

import { useEffect, useState } from "react";
import { Globe, Laptop, LoaderCircle, LogOut, MailCheck, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  listMySessions, listMySignIns, loadNotificationPreferences, revokeMySession, saveNotificationPreferences,
  signOutOtherSessions, type AccountSession, type NotificationPreferences, type SignInRecord,
} from "@/lib/security/client";

function when(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function countryName(code: string | null) {
  if (!code) return null;
  try { return new Intl.DisplayNames(undefined, { type: "region" }).of(code) ?? code; } catch { return code; }
}

/**
 * Where the account is signed in, what signed in recently (with new-device / new-network /
 * new-country flags) and which security emails the person wants. Only a device label and a
 * network prefix are ever stored — never a full IP address.
 */
export function SignInActivity() {
  const [sessions, setSessions] = useState<AccountSession[]>([]);
  const [history, setHistory] = useState<SignInRecord[]>([]);
  const [preferences, setPreferences] = useState<NotificationPreferences | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    void Promise.allSettled([listMySessions(), listMySignIns(20), loadNotificationPreferences()]).then(([sessionResult, historyResult, preferenceResult]) => {
      if (!active) return;
      if (sessionResult.status === "fulfilled") setSessions(sessionResult.value);
      if (historyResult.status === "fulfilled") setHistory(historyResult.value);
      if (preferenceResult.status === "fulfilled") setPreferences(preferenceResult.value);
      setMessage([sessionResult, historyResult].some((result) => result.status === "rejected") ? "Sign-in activity is being enabled for your account. Try again shortly." : "");
      setLoading(false);
    });
    return () => { active = false; };
  }, [version]);

  async function revoke(session: AccountSession) {
    if (!window.confirm(`Sign out ${session.device_label}? It will need to sign in again.`)) return;
    setBusy(session.session_id); setMessage("");
    try {
      const done = await revokeMySession(session.session_id);
      setMessage(done ? "That device was signed out. It may keep access for up to an hour until its current token expires; its vault stays locked." : "That session had already ended.");
      setVersion((value) => value + 1);
    } catch (reason) {
      setMessage(/two-step/iu.test(String((reason as { message?: string })?.message)) ? "Finish two-step verification first, then try again." : "That session could not be signed out. Try again.");
    } finally { setBusy(""); }
  }

  async function revokeOthers() {
    if (!window.confirm("Sign out every other device and browser? This device stays signed in.")) return;
    setBusy("others"); setMessage("");
    try { await signOutOtherSessions(); setMessage("All other sessions were signed out."); setVersion((value) => value + 1); }
    catch { setMessage("Other sessions could not be signed out. Try again."); }
    finally { setBusy(""); }
  }

  async function togglePreference(key: keyof NotificationPreferences) {
    if (!preferences) return;
    const next = { ...preferences, [key]: !preferences[key] };
    setPreferences(next);
    try { await saveNotificationPreferences(next); }
    catch { setPreferences(preferences); setMessage("Your email choice could not be saved. Try again."); }
  }

  const others = sessions.filter((session) => !session.is_current).length;

  return <div className="si-stack">
    <Card>
      <CardHeader>
        <div className="panel-heading"><div><CardTitle>Signed-in devices</CardTitle><CardDescription>Every browser and app that is signed in to your account. Sign out anything you don&apos;t recognise.</CardDescription></div>
          <div className="inline-actions"><Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
            {others > 0 && <Button variant="outline" size="sm" disabled={busy !== ""} onClick={() => void revokeOthers()}>{busy === "others" ? <LoaderCircle className="spin" /> : <LogOut />} Sign out everywhere else</Button>}</div></div>
      </CardHeader>
      <CardContent>
        {message && <p className="form-message neutral-message" role="status">{message}</p>}
        {loading ? <div className="loading-ring" /> : sessions.length === 0 ? <p className="field-hint">No active sessions found.</p> :
          <ul className="si-list">{sessions.map((session) => <li key={session.session_id} className="si-row">
            <Laptop />
            <div className="si-main"><strong>{session.device_label}{session.is_current ? " · this device" : ""}</strong>
              <small>Last active {when(session.last_active_at)}{session.network_label ? ` · network ${session.network_label}` : ""}{session.country ? ` · ${countryName(session.country)}` : ""}</small></div>
            {session.two_step ? <span className="si-tag good"><ShieldCheck /> 2-step</span> : <span className="si-tag">Password only</span>}
            {!session.is_current && <Button variant="outline" size="sm" disabled={busy !== ""} onClick={() => void revoke(session)}>{busy === session.session_id ? <LoaderCircle className="spin" /> : <LogOut />} Sign out</Button>}
          </li>)}</ul>}
      </CardContent>
    </Card>

    <Card>
      <CardHeader><CardTitle>Recent sign-ins</CardTitle><CardDescription>New devices, networks and countries are flagged, and you get an email for them.</CardDescription></CardHeader>
      <CardContent>
        {loading ? <div className="loading-ring" /> : history.length === 0 ? <p className="field-hint">Sign-ins appear here from now on.</p> :
          <ul className="si-list">{history.map((entry) => {
            const flagged = entry.new_device || entry.new_country;
            return <li key={entry.id} className={`si-row ${flagged ? "warn" : ""}`}>
              {flagged ? <ShieldAlert /> : <Globe />}
              <div className="si-main"><strong>{entry.device_label}</strong><small>{when(entry.created_at)}{entry.network_label ? ` · network ${entry.network_label}` : ""}{entry.country ? ` · ${countryName(entry.country)}` : ""}</small></div>
              <span className="inline-actions">
                {entry.new_device && <span className="si-tag warn">New device</span>}
                {entry.new_network && <span className="si-tag">New network</span>}
                {entry.new_country && <span className="si-tag bad">New country</span>}
              </span>
            </li>;
          })}</ul>}
      </CardContent>
    </Card>

    <Card>
      <CardHeader><CardTitle><MailCheck /> Security emails</CardTitle><CardDescription>Choose which security emails you receive. Emails never contain passwords or vault content.</CardDescription></CardHeader>
      <CardContent>
        {!preferences ? <div className="loading-ring" /> : <div className="si-toggles">
          <label><input type="checkbox" checked={preferences.new_sign_in_email} onChange={() => void togglePreference("new_sign_in_email")} /><span>New sign-ins<small>A new device, country or unusual activity signs in to your account.</small></span></label>
          <label><input type="checkbox" checked={preferences.breach_email} onChange={() => void togglePreference("breach_email")} /><span>Data breaches<small>Your work email appears in a new data breach (when your organization uses Breach watch).</small></span></label>
          <label><input type="checkbox" checked={preferences.weekly_report_email} onChange={() => void togglePreference("weekly_report_email")} /><span>Weekly security report<small>For organization owners and security admins.</small></span></label>
        </div>}
      </CardContent>
    </Card>
  </div>;
}
