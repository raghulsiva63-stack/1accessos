"use client";

import { useEffect, useState } from "react";
import { Activity, KeyRound, LoaderCircle, Plus, RefreshCw, Send, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { relativeTime } from "@/lib/enterprise/admin";
import { createAuditDestination, DESTINATIONS, replaceDestinationCredential, type DestinationField, type DestinationFormat } from "@/lib/enterprise/connectors";
import {
  deleteAuditWebhook, listAuditWebhooks, rotateAuditWebhookSecret, setAuditWebhookEnabled,
  SIGNATURE_EXAMPLE, testAuditWebhook, WEBHOOK_EVENT_FILTERS, webhookHealth, type AuditWebhook,
} from "@/lib/enterprise/webhooks";
import { Badge, htmlPattern, integrationError, SecretReveal, StatusMessage } from "./shared";

const FORMATS = Object.keys(DESTINATIONS) as DestinationFormat[];
const MAX_DESTINATIONS = 5;

function formatOf(hook: AuditWebhook): DestinationFormat {
  return hook.format && hook.format in DESTINATIONS ? hook.format : "generic";
}

/** Where a destination delivers to; Sentinel keeps its endpoint in the destination settings. */
function destinationTarget(hook: AuditWebhook) {
  const settings = hook.destination ?? {};
  const target = hook.url || settings.endpoint || "";
  const extra = [settings.index && `index ${settings.index}`, settings.site, settings.stream].filter(Boolean).join(" · ");
  return [target, extra].filter(Boolean).join(" · ") || "—";
}

function DestinationInput({ field, id, value, onChange }: { field: DestinationField; id: string; value: string; onChange: (value: string) => void }) {
  const hintId = field.hint ? `${id}-hint` : undefined;
  if (field.kind === "select") {
    return <select id={id} className="cx-select" required={field.required} value={value} aria-describedby={hintId} onChange={(event) => onChange(event.target.value)}>
      <option value="" disabled>Choose…</option>
      {(field.options ?? []).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>;
  }
  const type = field.kind === "secret" ? "password" : field.kind === "url" ? "url" : "text";
  return <Input id={id} type={type} required={field.required} value={value} placeholder={field.placeholder} aria-describedby={hintId}
    autoComplete="off" spellCheck={false} maxLength={field.kind === "secret" ? 2000 : 500}
    pattern={field.kind === "url" ? "https://.*" : htmlPattern(field.pattern)}
    title={field.kind === "url" ? "An https:// address" : field.pattern ? `Format: ${field.pattern}` : undefined}
    onChange={(event) => onChange(event.target.value)} />;
}

export function AuditStreamingCard({ tenantId, isAdmin }: { tenantId: string; isAdmin: boolean }) {
  const [hooks, setHooks] = useState<AuditWebhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState("");
  const [secret, setSecret] = useState("");
  const [version, setVersion] = useState(0);
  const [adding, setAdding] = useState(false);
  const [format, setFormat] = useState<DestinationFormat>("generic");
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [filters, setFilters] = useState<string[]>([]);
  const [replacing, setReplacing] = useState<string | null>(null);
  const [credential, setCredential] = useState("");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) { setLoading(true); setNow(Date.now()); } })
      .then(() => listAuditWebhooks(tenantId))
      .then((rows) => { if (active) setHooks(rows); }, (reason) => { if (active) setMessage(integrationError(reason, "Audit streaming could not be loaded.")); })
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
    setAdding(false); setName(""); setValues({}); setFilters([]); setFormat("generic");
  }

  function create(event: React.FormEvent) {
    event.preventDefault();
    const chosen = format;
    void run("create", async () => {
      const created = await createAuditDestination(tenantId, name, chosen, values, filters);
      resetForm();
      if (chosen === "generic" && created.secret) setSecret(created.secret);
      else setNotice(`${DESTINATIONS[chosen].label} destination created. Credential saved — it can't be viewed again.`);
    });
  }

  function saveCredential(event: React.FormEvent, hook: AuditWebhook) {
    event.preventDefault();
    void run(`credential:${hook.id}`, async () => {
      await replaceDestinationCredential(hook.id, credential);
      setReplacing(null); setCredential("");
    }, "Credential replaced. The old one is no longer used — it can't be viewed again.");
  }

  const spec = DESTINATIONS[format];
  const showSignature = hooks.some((hook) => formatOf(hook) === "generic") || (adding && format === "generic");

  return <>
    <Card>
      <CardHeader>
        <div className="panel-heading"><div><CardTitle>Audit streaming</CardTitle><CardDescription>Send your organization’s audit events to Splunk, Datadog, Microsoft Sentinel, Elastic or any HTTPS endpoint. Events are metadata only — never vault content. Credentials are write-only: they are kept private on the server and never shown again.</CardDescription></div>
          <div className="inline-actions"><Button variant="ghost" size="icon-sm" aria-label="Refresh audit streaming destinations" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
            {isAdmin && !adding && <Button size="sm" onClick={() => { setAdding(true); setMessage(""); setNotice(""); }} disabled={hooks.length >= MAX_DESTINATIONS}><Plus /> Add destination</Button>}</div></div>
      </CardHeader>
      <CardContent>
        {secret && <SecretReveal secret={secret} onDone={() => setSecret("")} />}
        {adding && <form className="webhook-form cx-form" onSubmit={create}>
          <fieldset className="cx-tiles"><legend>Destination</legend>
            {FORMATS.map((value) => <label key={value} className={`cx-tile${format === value ? " active" : ""}`}>
              <input type="radio" name="cx-destination-format" value={value} checked={format === value} onChange={() => { setFormat(value); setValues({}); }} />
              <strong>{DESTINATIONS[value].label}</strong><small>{DESTINATIONS[value].description}</small>
            </label>)}
          </fieldset>
          <p className="cx-hint" id="cx-destination-docs">{spec.docs}</p>
          <div className="cx-fields">
            <div><Label htmlFor="cx-destination-name">Name</Label><Input id="cx-destination-name" required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder={format === "generic" ? "SIEM receiver" : `${DESTINATIONS[format].label.split(" (")[0]} production`} /></div>
            {spec.fields.map((field) => {
              const id = `cx-destination-${field.key}`;
              return <div key={`${format}:${field.key}`}>
                <Label htmlFor={id}>{field.label}</Label>
                <DestinationInput field={field} id={id} value={values[field.key] ?? ""} onChange={(value) => setValues((current) => ({ ...current, [field.key]: value }))} />
                {field.hint && <small className="cx-field-hint" id={`${id}-hint`}>{field.hint}</small>}
              </div>;
            })}
          </div>
          <fieldset className="webhook-filters"><legend>Events to send</legend>
            <label className={filters.length === 0 ? "active" : ""}><input type="checkbox" checked={filters.length === 0} onChange={() => setFilters([])} /> All events</label>
            {WEBHOOK_EVENT_FILTERS.map((entry) => <label key={entry.value} className={filters.includes(entry.value) ? "active" : ""}><input type="checkbox" checked={filters.includes(entry.value)} onChange={(event) => setFilters(event.target.checked ? [...filters, entry.value] : filters.filter((value) => value !== entry.value))} /> {entry.label}</label>)}
          </fieldset>
          <div className="inline-actions"><Button disabled={busy !== ""}>{busy === "create" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Create destination</Button><Button type="button" variant="ghost" onClick={resetForm}>Cancel</Button></div>
          <p className="field-hint">Streaming starts with new events. Delivery is in order and at-least-once: a batch is retried with backoff until the destination accepts it.{format !== "generic" && " The credential is sent once and can't be viewed again — you can replace it later."}</p>
        </form>}
        <StatusMessage text={message} />
        <StatusMessage text={notice} tone="neutral" />
        {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : hooks.length === 0 && !adding ? <div className="empty-state"><Activity /><p>No streaming destinations yet.</p></div> :
          <ul className="webhook-list">{hooks.map((hook) => {
            const health = webhookHealth(hook);
            const hookFormat = formatOf(hook);
            const vendor = hookFormat !== "generic";
            return <li key={hook.id}>
              <div className="webhook-main"><span className={`webhook-dot ${health.tone}`} aria-hidden="true" /><div>
                <span className="cx-title"><strong>{hook.name}</strong><Badge>{DESTINATIONS[hookFormat].label}</Badge></span>
                <code>{destinationTarget(hook)}</code>
                <small>{health.label} · last delivery {relativeTime(hook.last_success_at, now)}{hook.event_prefixes.length ? ` · ${hook.event_prefixes.length} event filter${hook.event_prefixes.length === 1 ? "" : "s"}` : " · all events"}</small>
                {hook.last_error && <small className="webhook-error">Last error: {hook.last_status === 421 ? "the address resolves to a private or internal network, so delivery was blocked" : hook.last_status === 504 ? "the endpoint did not respond in time" : (hook.last_status === 401 || hook.last_status === 403) && vendor ? "the destination rejected the credential — replace it" : hook.last_error}{hook.last_status && hook.last_status !== 421 ? ` (HTTP ${hook.last_status})` : ""}</small>}
                {hook.last_test_at && <small>Test {relativeTime(hook.last_test_at, now)}: {hook.last_test_status === null ? "waiting for a response…" : hook.last_test_status >= 200 && hook.last_test_status < 300 ? `delivered (HTTP ${hook.last_test_status})` : hook.last_test_status === 0 ? "no response" : `failed (HTTP ${hook.last_test_status})`}</small>}
                {replacing === hook.id && <form className="cx-inline-form" onSubmit={(event) => saveCredential(event, hook)}>
                  <Label htmlFor={`cx-credential-${hook.id}`}>New {(DESTINATIONS[hookFormat].fields.find((field) => field.target === "credential")?.label ?? "credential").toLowerCase()}</Label>
                  <div className="cx-inline-row">
                    <Input id={`cx-credential-${hook.id}`} type="password" autoComplete="off" spellCheck={false} required maxLength={2000} value={credential} onChange={(event) => setCredential(event.target.value)} />
                    <Button size="sm" disabled={busy !== "" || !credential.trim()}>{busy === `credential:${hook.id}` ? <LoaderCircle className="spin" /> : <KeyRound />} Save</Button>
                    <Button size="sm" type="button" variant="ghost" onClick={() => { setReplacing(null); setCredential(""); }}>Cancel</Button>
                  </div>
                </form>}
              </div></div>
              {isAdmin && <div className="webhook-actions">
                <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`test:${hook.id}`, () => testAuditWebhook(hook.id), "Test event sent. Refresh in a few seconds to see the result.")}>{busy === `test:${hook.id}` ? <LoaderCircle className="spin" /> : <Send />} Test</Button>
                <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`toggle:${hook.id}`, () => setAuditWebhookEnabled(hook.id, !hook.enabled))}>{hook.enabled ? "Pause" : "Resume"}</Button>
                {vendor
                  ? <Button size="sm" variant="ghost" disabled={busy !== "" || replacing === hook.id} onClick={() => { setReplacing(hook.id); setCredential(""); }}><KeyRound /> Replace credential</Button>
                  : <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => { if (window.confirm("Rotate the signing secret? Your receiver must be updated with the new secret.")) void run(`rotate:${hook.id}`, async () => { setSecret(await rotateAuditWebhookSecret(hook.id)); }); }}><KeyRound /> Rotate secret</Button>}
                <Button size="icon-sm" variant="ghost" aria-label={`Delete ${hook.name}`} disabled={busy !== ""} onClick={() => { if (window.confirm(`Delete “${hook.name}”? Streaming to this destination stops immediately.`)) void run(`delete:${hook.id}`, () => deleteAuditWebhook(hook.id), "Destination deleted."); }}><Trash2 /></Button>
              </div>}
            </li>;
          })}</ul>}
      </CardContent>
    </Card>
    {showSignature && <Card>
      <CardHeader><CardTitle>Verify signatures</CardTitle><CardDescription>HTTPS webhook requests carry <code>X-PasskeyX-Timestamp</code> and <code>X-PasskeyX-Signature: v1=HMAC-SHA256(secret, timestamp + &quot;.&quot; + body)</code>. Reject requests older than five minutes.</CardDescription></CardHeader>
      <CardContent><pre className="code-sample">{SIGNATURE_EXAMPLE}</pre></CardContent>
    </Card>}
  </>;
}
