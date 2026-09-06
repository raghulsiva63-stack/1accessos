"use client";

import { useEffect, useState } from "react";
import { Bell, Check, KeyRound, MessageSquareText, RefreshCw, Send, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { supabase } from "@/lib/supabase/client";
import type { WorkspaceVault } from "@/lib/vault/items";

type SmsStatus = {
  settings: {
    sms_enabled?: boolean;
    security_email_enabled?: boolean;
    event_types?: string[];
    credential_status?: string;
    sender_profile_hint?: string | null;
    last_verified_at?: string | null;
  };
  subscription: {
    masked_phone?: string;
    event_types?: string[];
    enabled?: boolean;
    verified_at?: string | null;
  } | null;
  deliveries: Array<{ id: string; event_type: string; status: string; error_code: string | null; created_at: string; delivered_at: string | null }>;
  canManage: boolean;
};

const DEFAULT_EVENTS = ["new_device", "security_alert", "access_approved", "recovery_changed"];
const EVENT_LABELS: Record<string, string> = {
  new_device: "New device",
  security_alert: "Security alert",
  access_requested: "Access requested",
  access_approved: "Access approved",
  recovery_changed: "Recovery changed",
  billing_notice: "Billing notice",
  agent_killed: "Agent killed",
};

function errorMessage(reason: unknown) {
  const text = reason instanceof Error ? reason.message : String(reason ?? "");
  if (/credential|profile/iu.test(text)) return "The Sent credential or Sender Profile could not be verified.";
  if (/phone/iu.test(text)) return "Enter a valid mobile number in international format, such as +14155550123.";
  if (/expired|code/iu.test(text)) return "That verification code is invalid or expired.";
  if (/rate|locked/iu.test(text)) return "Too many verification attempts. Try again later.";
  return "The notification setting could not be updated. Try again.";
}

export function NotificationsView({ vault }: { vault: WorkspaceVault }) {
  const [status, setStatus] = useState<SmsStatus | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [profileId, setProfileId] = useState("");
  const [phone, setPhone] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [code, setCode] = useState("");
  const [events, setEvents] = useState(DEFAULT_EVENTS);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");

  async function invoke(action: string, extra: Record<string, unknown> = {}) {
    if (!supabase) throw new Error("unavailable");
    const { data, error } = await supabase.functions.invoke("tenant-sms", {
      body: { action, tenantId: vault.tenantId, ...extra },
    });
    if (error) throw error;
    if (data?.error) throw new Error(String(data.error));
    return data;
  }

  async function refresh() {
    setBusy("refresh");
    try {
      const next = await invoke("status") as SmsStatus;
      setStatus(next);
      setEvents(next.settings.event_types?.length ? next.settings.event_types : DEFAULT_EVENTS);
      setMessage("");
    } catch (reason) { setMessage(errorMessage(reason)); }
    finally { setBusy(""); }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [vault.tenantId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function run(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label); setMessage("");
    try { await action(); setMessage(success); await refresh(); }
    catch (reason) { setMessage(errorMessage(reason)); }
    finally { setBusy(""); }
  }

  function toggleEvent(eventName: string) {
    setEvents((current) => current.includes(eventName) ? current.filter((entry) => entry !== eventName) : [...current, eventName]);
  }

  return <div className="feature-page notification-page">
    <div className="feature-intro"><div><span className="status-pill"><Bell /> Notification center</span><h2>Email and customer-controlled SMS</h2><p>Security notifications are separate from vault encryption and account-login MFA. Each tenant supplies its own Sent credential and each recipient verifies their own phone.</p></div><Button variant="outline" disabled={busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button></div>
    {message && <p className="settings-message" role="status">{message}</p>}
    <div className="notification-grid">
      <Card><CardHeader><CardTitle><ShieldCheck /> Notification status</CardTitle><CardDescription>Provider state is visible; credential values are write-only and never returned to the browser.</CardDescription></CardHeader><CardContent>
        <div className="setting-row"><span>Email security notices</span><strong>{status?.settings.security_email_enabled === false ? "Disabled" : "Enabled"}</strong></div>
        <div className="setting-row"><span>Tenant SMS</span><strong>{status?.settings.sms_enabled ? "Enabled" : "Disabled"}</strong></div>
        <div className="setting-row"><span>Sent credential</span><strong>{status?.settings.credential_status?.replaceAll("_", " ") ?? "Checking"}</strong></div>
        {status?.settings.sender_profile_hint && <div className="setting-row"><span>Sender Profile</span><code>{status.settings.sender_profile_hint}</code></div>}
        <div className="event-toggle-grid">{Object.entries(EVENT_LABELS).map(([eventName, label]) => <label key={eventName}><input type="checkbox" checked={events.includes(eventName)} disabled={!status?.canManage || busy !== ""} onChange={() => toggleEvent(eventName)} /><span>{label}</span></label>)}</div>
        {status?.canManage && <div className="inline-actions"><Button disabled={busy !== "" || status.settings.credential_status !== "verified"} onClick={() => void run("toggle", () => invoke(status.settings.sms_enabled ? "disable" : "enable", { eventTypes: events }), status.settings.sms_enabled ? "Tenant SMS disabled." : "Tenant SMS enabled for verified recipients.")}>{status.settings.sms_enabled ? "Disable tenant SMS" : "Enable tenant SMS"}</Button></div>}
      </CardContent></Card>

      {status?.canManage && <Card><CardHeader><CardTitle><KeyRound /> Sent tenant credential</CardTitle><CardDescription>Use a profile-scoped key when possible. Organization keys require a Sender Profile ID. Saving rotates the encrypted credential and disables SMS until you re-enable it.</CardDescription></CardHeader><CardContent>
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("credential", async () => { await invoke("save_credential", { apiKey, senderProfileId: profileId.trim() || undefined }); setApiKey(""); }, "Sent credential verified and encrypted."); }}>
          <div><Label htmlFor="sent-api-key">Sent API key</Label><Input id="sent-api-key" type="password" autoComplete="off" required pattern="[0-9a-fA-F-]{36}" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="Write-only UUID key" /></div>
          <div><Label htmlFor="sent-profile-id">Sender Profile ID</Label><Input id="sent-profile-id" autoComplete="off" pattern="[0-9a-fA-F-]{36}" value={profileId} onChange={(event) => setProfileId(event.target.value)} placeholder="Required for an organization key" /></div>
          <Button disabled={busy !== "" || apiKey.length !== 36}>{busy === "credential" ? "Verifying…" : "Verify and save credential"}</Button>
        </form>
      </CardContent></Card>}

      <Card><CardHeader><CardTitle><MessageSquareText /> Your SMS destination</CardTitle><CardDescription>Verify once before notifications can be delivered. The phone is encrypted server-side; only its masked form is returned.</CardDescription></CardHeader><CardContent>
        {status?.subscription?.masked_phone && <div className="verified-destination"><Check /><span><strong>{status.subscription.masked_phone}</strong><small>{status.subscription.verified_at ? "Verified" : "Verification pending"} · {status.subscription.enabled ? "enabled" : "disabled"}</small></span></div>}
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("send-code", async () => { const result = await invoke("send_verification", { phone, eventTypes: events }) as { challengeId: string }; setChallengeId(result.challengeId); }, "A verification code was accepted by Sent for delivery."); }}>
          <div><Label htmlFor="notification-phone">Mobile number</Label><Input id="notification-phone" type="tel" autoComplete="tel" required pattern="\+[1-9][0-9]{7,14}" value={phone} onChange={(event) => setPhone(event.target.value)} placeholder="+14155550123" /></div>
          <Button variant="outline" disabled={busy !== "" || status?.settings.credential_status !== "verified"}>{busy === "send-code" ? "Sending…" : "Send verification code"}</Button>
        </form>
        {challengeId && <form className="form-stack verification-form" onSubmit={(event) => { event.preventDefault(); void run("verify", () => invoke("verify_phone", { challengeId, code }), "Phone verified and notifications enabled."); }}><div><Label htmlFor="notification-code">Verification code</Label><Input id="notification-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/gu, ""))} /></div><Button disabled={busy !== "" || code.length !== 6}>{busy === "verify" ? "Verifying…" : "Verify phone"}</Button></form>}
        <Button className="test-notification-button" variant="ghost" disabled={busy !== "" || !status?.settings.sms_enabled || !status?.subscription?.enabled} onClick={() => void run("test", () => invoke("send_test"), "Test security notification accepted for delivery.")}><Send /> Send test notification</Button>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><Bell /> Recent SMS activity</CardTitle><CardDescription>Provider message text, phone numbers, and credentials are never stored in this activity view.</CardDescription></CardHeader><CardContent><div className="notification-history">{status?.deliveries.map((delivery) => <article key={delivery.id}><span className={`delivery-state ${delivery.status}`}>{delivery.status}</span><div><strong>{EVENT_LABELS[delivery.event_type] ?? delivery.event_type.replaceAll("_", " ")}</strong><small>{new Date(delivery.created_at).toLocaleString()}{delivery.error_code ? ` · ${delivery.error_code}` : ""}</small></div></article>)}{!status?.deliveries.length && <p className="field-hint">No tenant SMS deliveries yet.</p>}</div></CardContent></Card>
    </div>
    <div className="privacy-note"><ShieldCheck /><span>Passkey-X sends real provider requests with sandbox disabled for this panel. A Sent acceptance response means queued by the provider; delivery is confirmed later by a signed webhook.</span></div>
  </div>;
}
