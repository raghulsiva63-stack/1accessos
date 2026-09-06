"use client";

import { useEffect, useMemo, useState } from "react";
import { Bot, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { dueReminders, parsePreferences, preferenceKey, RECIPES, serializePreferences, type Preferences, type RecipeId } from "@/lib/automations/local";
import type { VaultItem, WorkspaceVault } from "@/lib/vault/items";

export function AutomationsView({ vault, items, visible, onNavigate }: {
  vault: WorkspaceVault; items: VaultItem[]; visible: boolean;
  onNavigate: (view: "automations" | "security" | "devices") => void;
}) {
  const storageKey = preferenceKey(vault.identityId, vault.tenantId, vault.workspaceId);
  const [now, setNow] = useState(() => Date.now());
  const [preferences, setPreferences] = useState(() => {
    if (typeof window === "undefined") return parsePreferences(null, Date.now());
    try { return parsePreferences(window.localStorage.getItem(storageKey), Date.now()); }
    catch { return parsePreferences(null, Date.now()); }
  });
  const [message, setMessage] = useState("");
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60_000);
    function synchronize(event: StorageEvent) {
      if (event.key === storageKey || event.key === null) {
        try { setPreferences(parsePreferences(window.localStorage.getItem(storageKey), Date.now())); }
        catch { setMessage("Browser storage is unavailable. Settings apply only until this workspace closes."); }
      }
    }
    window.addEventListener("storage", synchronize);
    return () => { window.clearInterval(timer); window.removeEventListener("storage", synchronize); };
  }, [storageKey]);
  const reminders = useMemo(() => dueReminders(items, preferences, now), [items, preferences, now]);
  function save(next: Preferences, timestamp: number) {
    setNow(timestamp); setPreferences(next);
    try { window.localStorage.setItem(storageKey, serializePreferences(next, timestamp)); setMessage(""); }
    catch { setMessage("Browser storage is unavailable. Settings apply only until this workspace closes."); }
  }
  function toggle(id: RecipeId, timestamp: number) {
    save({ ...preferences, [id]: { enabled: !preferences[id].enabled, reviewedAt: 0 } }, timestamp);
  }
  if (!visible) return reminders.length ? <div className="vault-notice" role="status"><span>{reminders.length} local review{reminders.length === 1 ? "" : "s"} due in this workspace.</span><Button variant="outline" onClick={() => onNavigate("automations")}>Review routines</Button></div> : null;
  return <div className="feature-page">
    <div className="feature-intro"><div><span className="status-pill"><Bot /> Local routines</span><h2>Useful routines, under your control</h2><p>Checks run while this workspace is unlocked in your browser. Overdue reviews appear when you return. Local checks use no hosted AI or automation credits.</p></div></div>
    {message && <p className="form-message" role="status">{message}</p>}
    <div className="recipe-grid">{RECIPES.map(({ id, title, detail, interval }) => <Card key={id}>
      <CardHeader><CardTitle>{title}</CardTitle><CardDescription>{detail}</CardDescription></CardHeader>
      <CardContent><label className="switch-row"><span>{preferences[id].enabled ? "Enabled" : "Disabled"}</span><input type="checkbox" aria-label={title} checked={preferences[id].enabled} onChange={() => toggle(id, Date.now())} /></label>
        {preferences[id].enabled && <p className="field-hint">{preferences[id].reviewedAt ? `Next review: ${new Date(preferences[id].reviewedAt + interval).toLocaleDateString()}` : "First review due now"}</p>}
      </CardContent></Card>)}</div>
    <Card><CardHeader><CardTitle>Reviews due</CardTitle><CardDescription>Results use active login records in this workspace. Archived and deleted records are excluded.</CardDescription></CardHeader><CardContent>
      {!reminders.length ? <p>No reviews due. Enable a routine above to begin.</p> : <div className="finding-list">{reminders.map((reminder) => <article className="finding warning" key={reminder.id}><ShieldCheck /><div><strong>{reminder.title}</strong><p>{reminder.detail}</p><div className="inline-actions"><Button variant="outline" onClick={() => onNavigate(reminder.destination)}>Open {reminder.destination === "devices" ? "devices" : "security findings"}</Button><Button onClick={() => save({ ...preferences, [reminder.id]: { enabled: true, reviewedAt: Date.now() } }, Date.now())}>Mark reviewed</Button></div></div></article>)}</div>}
    </CardContent></Card>
    <Card><CardHeader><CardTitle>Security Concierge</CardTitle><CardDescription>Local rule-based checks identify weak, reused, and older login records. Hosted AI is not connected.</CardDescription></CardHeader><CardContent><div className="privacy-mode"><ShieldCheck /><div><strong>Privacy mode: Local only</strong><span>Only routine switches and review times are saved in this browser, separately for each identity, tenant, and workspace. Findings remain in memory. Clearing browser data resets reminders.</span></div></div></CardContent></Card>
  </div>;
}
