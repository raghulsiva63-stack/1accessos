"use client";

import { useEffect, useState } from "react";
import { BellRing, Hash, LoaderCircle, MessageSquare, Pencil, Plus, RefreshCw, Send, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { relativeTime } from "@/lib/enterprise/admin";
import {
  CHAT_EVENTS, CHAT_SETUP, channelHealth, createChatChannel, deleteChatChannel, listChatChannels, testChatChannel, updateChatChannel, validChatUrl,
  type ChatChannel, type ChatEvent, type ChatKind, type Severity,
} from "@/lib/enterprise/connectors";
import { integrationError, StatusMessage } from "./shared";

const SEVERITIES: { value: Severity; label: string }[] = [
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and above" },
  { value: "medium", label: "Medium and above" },
  { value: "low", label: "All severities" },
];
const ALL_EVENTS = CHAT_EVENTS.map((entry) => entry.value);

function eventLabel(value: ChatEvent) {
  return CHAT_EVENTS.find((entry) => entry.value === value)?.label ?? value;
}

function KindIcon({ kind }: { kind: ChatKind }) {
  return kind === "slack" ? <Hash aria-hidden="true" /> : <MessageSquare aria-hidden="true" />;
}

/** Event checkboxes + minimum severity, shared by the add and edit forms. */
function EventPicker({ idPrefix, events, onEvents, severity, onSeverity }: {
  idPrefix: string; events: ChatEvent[]; onEvents: (events: ChatEvent[]) => void; severity: Severity; onSeverity: (severity: Severity) => void;
}) {
  const alerts = events.includes("alerts");
  return <>
    <fieldset className="cx-checks"><legend>Send these to the channel</legend>
      {CHAT_EVENTS.map((entry) => <label key={entry.value}>
        <input type="checkbox" checked={events.includes(entry.value)} onChange={(event) => onEvents(event.target.checked ? [...events, entry.value] : events.filter((value) => value !== entry.value))} />
        <span><strong>{entry.label}</strong><small>{entry.hint}</small></span>
      </label>)}
    </fieldset>
    <div className="cx-field-narrow">
      <Label htmlFor={`${idPrefix}-severity`}>Minimum alert severity</Label>
      <select id={`${idPrefix}-severity`} className="cx-select" value={severity} disabled={!alerts} aria-describedby={`${idPrefix}-severity-hint`} onChange={(event) => onSeverity(event.target.value as Severity)}>
        {SEVERITIES.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}
      </select>
      <small className="cx-field-hint" id={`${idPrefix}-severity-hint`}>{alerts ? "Only security alerts at or above this severity are posted." : "Applies to security alerts — select them above to choose."}</small>
    </div>
  </>;
}

function EditChannel({ channel, busy, onCancel, onSave }: {
  channel: ChatChannel; busy: boolean; onCancel: () => void;
  onSave: (changes: { name: string; events: ChatEvent[]; minSeverity: Severity; url?: string }) => void;
}) {
  const [name, setName] = useState(channel.name);
  const [events, setEvents] = useState<ChatEvent[]>(channel.events);
  const [severity, setSeverity] = useState<Severity>(channel.min_severity);
  const [url, setUrl] = useState("");
  const [touched, setTouched] = useState(false);
  const urlError = url.trim() && !validChatUrl(channel.kind, url) ? `Paste the incoming webhook URL from ${CHAT_SETUP[channel.kind].label}.` : "";
  const prefix = `cx-chat-edit-${channel.id}`;
  return <form className="webhook-form cx-form cx-edit" onSubmit={(event) => {
    event.preventDefault(); setTouched(true);
    if (urlError || events.length === 0) return;
    onSave({ name, events, minSeverity: severity, url: url.trim() || undefined });
  }}>
    <div className="cx-fields">
      <div><Label htmlFor={`${prefix}-name`}>Name</Label><Input id={`${prefix}-name`} required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} /></div>
      <div><Label htmlFor={`${prefix}-url`}>New webhook URL (optional)</Label>
        <Input id={`${prefix}-url`} type="url" autoComplete="off" spellCheck={false} maxLength={700} value={url} placeholder={`Keep the current ${channel.url_host} URL`} aria-invalid={touched && urlError ? true : undefined} aria-describedby={touched && urlError ? `${prefix}-url-error` : undefined} onBlur={() => setTouched(true)} onChange={(event) => setUrl(event.target.value)} />
        {touched && urlError && <small className="cx-field-error" id={`${prefix}-url-error`} role="alert">{urlError}</small>}</div>
    </div>
    <EventPicker idPrefix={prefix} events={events} onEvents={setEvents} severity={severity} onSeverity={setSeverity} />
    {touched && events.length === 0 && <small className="cx-field-error" role="alert">Choose at least one kind of message.</small>}
    <div className="inline-actions"><Button size="sm" disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <ShieldCheck />} Save changes</Button><Button size="sm" type="button" variant="ghost" onClick={onCancel}>Cancel</Button></div>
  </form>;
}

export function ChatChannelsCard({ tenantId, isAdmin }: { tenantId: string; isAdmin: boolean }) {
  const [channels, setChannels] = useState<ChatChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState("");
  const [version, setVersion] = useState(0);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [kind, setKind] = useState<ChatKind>("slack");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [urlTouched, setUrlTouched] = useState(false);
  const [events, setEvents] = useState<ChatEvent[]>(ALL_EVENTS);
  const [severity, setSeverity] = useState<Severity>("high");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) { setLoading(true); setNow(Date.now()); } })
      .then(() => listChatChannels(tenantId))
      .then((rows) => { if (active) setChannels(rows); }, (reason) => { if (active) setMessage(integrationError(reason, "Slack and Teams channels could not be loaded.")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [tenantId, version]);

  async function run(key: string, action: () => Promise<void>, success?: string) {
    setBusy(key); setMessage(""); setNotice("");
    try { await action(); if (success) setNotice(success); setVersion((value) => value + 1); }
    catch (reason) { setMessage(integrationError(reason)); }
    finally { setBusy(""); }
  }

  function resetForm() {
    setAdding(false); setName(""); setUrl(""); setUrlTouched(false); setEvents(ALL_EVENTS); setSeverity("high"); setKind("slack");
  }

  const urlError = url.trim() && !validChatUrl(kind, url) ? `Paste the incoming webhook URL from ${CHAT_SETUP[kind].label} (it starts with ${CHAT_SETUP[kind].placeholder.split("/").slice(0, 3).join("/")}/).` : "";

  function create(event: React.FormEvent) {
    event.preventDefault();
    setUrlTouched(true);
    if (urlError || !url.trim() || events.length === 0) return;
    void run("create", async () => {
      await createChatChannel(tenantId, kind, name, url, events, severity);
      resetForm();
    }, `${CHAT_SETUP[kind].label} channel added. Send a test message to check it.`);
  }

  const setup = CHAT_SETUP[kind];

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><BellRing /> Slack &amp; Teams alerts</CardTitle>
        <CardDescription>Post security alerts, breach watch findings, rotation reminders and the weekly report to a Slack or Microsoft Teams channel. Messages contain alert titles and counts only — never passwords or vault data.</CardDescription></div>
        <div className="inline-actions"><Button variant="ghost" size="icon-sm" aria-label="Refresh Slack and Teams channels" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
          {isAdmin && !adding && <Button size="sm" onClick={() => { setAdding(true); setMessage(""); setNotice(""); }}><Plus /> Add channel</Button>}</div></div>
    </CardHeader>
    <CardContent>
      {adding && <form className="webhook-form cx-form" onSubmit={create} noValidate>
        <div className="cx-segmented" role="radiogroup" aria-label="Chat app">
          {(Object.keys(CHAT_SETUP) as ChatKind[]).map((value) => <label key={value} className={kind === value ? "active" : ""}>
            <input type="radio" name="cx-chat-kind" value={value} checked={kind === value} onChange={() => { setKind(value); setUrlTouched(false); }} />
            <KindIcon kind={value} /> {CHAT_SETUP[value].label}
          </label>)}
        </div>
        <ol className="cx-steps">{setup.steps.map((step) => <li key={step}>{step}</li>)}</ol>
        <div className="cx-fields">
          <div><Label htmlFor="cx-chat-name">Name</Label><Input id="cx-chat-name" required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder={kind === "slack" ? "#security-alerts" : "Security team"} /></div>
          <div><Label htmlFor="cx-chat-url">Webhook URL</Label>
            <Input id="cx-chat-url" type="url" required autoComplete="off" spellCheck={false} maxLength={700} value={url} placeholder={setup.placeholder}
              aria-invalid={urlTouched && (urlError || !url.trim()) ? true : undefined} aria-describedby={urlTouched && (urlError || !url.trim()) ? "cx-chat-url-error" : "cx-chat-url-note"}
              onBlur={() => setUrlTouched(true)} onChange={(event) => setUrl(event.target.value)} />
            {urlTouched && (urlError || !url.trim()) ? <small className="cx-field-error" id="cx-chat-url-error" role="alert">{urlError || "Paste the webhook URL."}</small>
              : <small className="cx-field-hint" id="cx-chat-url-note">Treated like a password: stored privately and never shown again.</small>}</div>
        </div>
        <EventPicker idPrefix="cx-chat" events={events} onEvents={setEvents} severity={severity} onSeverity={setSeverity} />
        {urlTouched && events.length === 0 && <small className="cx-field-error" role="alert">Choose at least one kind of message.</small>}
        <div className="inline-actions"><Button disabled={busy !== "" || name.trim().length < 2}>{busy === "create" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Add channel</Button><Button type="button" variant="ghost" onClick={resetForm}>Cancel</Button></div>
      </form>}
      <StatusMessage text={message} />
      <StatusMessage text={notice} tone="neutral" />
      {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : channels.length === 0 && !adding ? <div className="empty-state"><BellRing /><p>No Slack or Teams channels yet.</p></div> :
        <ul className="webhook-list">{channels.map((channel) => {
          const health = channelHealth(channel);
          return <li key={channel.id}>
            <div className="webhook-main"><span className={`webhook-dot ${health.tone}`} aria-hidden="true" /><div>
              <span className="cx-title"><span className="cx-kind"><KindIcon kind={channel.kind} /> {CHAT_SETUP[channel.kind].label}</span><strong>{channel.name}</strong></span>
              <code>{channel.url_host}</code>
              <span className="cx-chips" aria-label="Messages sent">{channel.events.map((value) => <span key={value} className="cx-chip">{value === "alerts" ? `${eventLabel(value)} · ${SEVERITIES.find((entry) => entry.value === channel.min_severity)?.label.toLowerCase() ?? channel.min_severity}` : eventLabel(value)}</span>)}</span>
              <small>{health.label} · last message {relativeTime(channel.last_success_at, now)}</small>
              {channel.last_error && <small className="webhook-error">Last error: {channel.last_error}{channel.last_status ? ` (HTTP ${channel.last_status})` : ""}{channel.last_attempt_at ? ` · ${relativeTime(channel.last_attempt_at, now)}` : ""}</small>}
              {editing === channel.id && <EditChannel channel={channel} busy={busy === `edit:${channel.id}`} onCancel={() => setEditing(null)}
                onSave={(changes) => void run(`edit:${channel.id}`, async () => { await updateChatChannel(channel.id, changes); setEditing(null); }, "Channel updated.")} />}
            </div></div>
            {isAdmin && <div className="webhook-actions">
              <Button size="sm" variant="outline" disabled={busy !== "" || !channel.enabled} onClick={() => void run(`test:${channel.id}`, () => testChatChannel(channel.id), "Test message sent. Check the channel, then refresh to see the result.")}>{busy === `test:${channel.id}` ? <LoaderCircle className="spin" /> : <Send />} Test</Button>
              <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`toggle:${channel.id}`, () => updateChatChannel(channel.id, { enabled: !channel.enabled }), channel.enabled ? "Channel paused." : "Channel resumed.")}>{channel.enabled ? "Pause" : "Resume"}</Button>
              <Button size="sm" variant="ghost" disabled={busy !== "" || editing === channel.id} onClick={() => setEditing(channel.id)}><Pencil /> Edit</Button>
              <Button size="icon-sm" variant="ghost" aria-label={`Delete ${channel.name}`} disabled={busy !== ""} onClick={() => { if (window.confirm(`Delete “${channel.name}”? Passkey-X stops posting to this channel immediately.`)) void run(`delete:${channel.id}`, () => deleteChatChannel(channel.id), "Channel deleted."); }}><Trash2 /></Button>
            </div>}
          </li>;
        })}</ul>}
    </CardContent>
  </Card>;
}
