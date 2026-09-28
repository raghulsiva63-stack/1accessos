"use client";

import { useEffect, useState } from "react";
import { Activity, Check, Copy, KeyRound, LoaderCircle, Plus, RefreshCw, Send, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { relativeTime } from "@/lib/enterprise/admin";
import {
  createAuditWebhook, deleteAuditWebhook, listAuditWebhooks, rotateAuditWebhookSecret, setAuditWebhookEnabled,
  SIGNATURE_EXAMPLE, testAuditWebhook, WEBHOOK_EVENT_FILTERS, webhookHealth, type AuditWebhook,
} from "@/lib/enterprise/webhooks";
import type { WorkspaceVault } from "@/lib/vault/items";
import { copySecret } from "@/components/enterprise/vault-guards";

function webhookError(reason: unknown) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : "";
  if (/public https address/iu.test(detail)) return "Use a public https:// address. IP addresses, localhost and internal hostnames are not allowed.";
  if (/at most 5/iu.test(detail)) return "An organization can have up to 5 audit webhooks.";
  if (/wait a few seconds/iu.test(detail)) return "Wait a few seconds before sending another test.";
  if (/requires an organization/iu.test(detail)) return "Audit streaming is available for organizations.";
  return adminErrorMessage(reason, "The change could not be saved.");
}

function SecretReveal({ secret, onDone }: { secret: string; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  return <div className="webhook-secret" role="status">
    <KeyRound /><div><strong>Signing secret — shown once</strong><p>Store it in your SIEM or receiver. Passkey-X cannot show it again.</p><code>{secret}</code></div>
    <div className="inline-actions"><Button size="sm" onClick={async () => { try { await copySecret(secret, 120); setCopied(true); } catch { /* clipboard blocked */ } }}>{copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy"}</Button><Button size="sm" variant="ghost" onClick={onDone}>I saved it</Button></div>
  </div>;
}

export function IntegrationsPanel({ vault }: { vault: WorkspaceVault }) {
  const { isTenantAdmin } = useEnterprise();
  const [hooks, setHooks] = useState<AuditWebhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [secret, setSecret] = useState("");
  const [version, setVersion] = useState(0);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [filters, setFilters] = useState<string[]>([]);
  const [now] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) setLoading(true); })
      .then(() => listAuditWebhooks(vault.tenantId))
      .then((rows) => { if (active) setHooks(rows); }, (reason) => { if (active) setMessage(webhookError(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function run(key: string, action: () => Promise<void>, success?: string) {
    setBusy(key); setMessage("");
    try { await action(); if (success) setMessage(success); setVersion((value) => value + 1); }
    catch (reason) { setMessage(webhookError(reason)); }
    finally { setBusy(""); }
  }

  function create(event: React.FormEvent) {
    event.preventDefault();
    void run("create", async () => {
      const created = await createAuditWebhook(vault.tenantId, name, url, filters);
      setSecret(created.secret); setAdding(false); setName(""); setUrl(""); setFilters([]);
    });
  }

  return <div className="integrations-panel">
    <Card>
      <CardHeader>
        <div className="panel-heading"><div><CardTitle>Audit streaming</CardTitle><CardDescription>Send your organization’s audit events to a SIEM (Splunk, Sentinel, Datadog, Elastic) or any HTTPS endpoint. Events are metadata only — never vault content — and every request is signed.</CardDescription></div>
          <div className="inline-actions"><Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>{isTenantAdmin && !adding && <Button size="sm" onClick={() => setAdding(true)} disabled={hooks.length >= 5}><Plus /> Add endpoint</Button>}</div></div>
      </CardHeader>
      <CardContent>
        {secret && <SecretReveal secret={secret} onDone={() => setSecret("")} />}
        {adding && <form className="webhook-form" onSubmit={create}>
          <div className="inline-fields"><div><Label htmlFor="webhook-name">Name</Label><Input id="webhook-name" required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Splunk production" /></div>
            <div><Label htmlFor="webhook-url">HTTPS endpoint</Label><Input id="webhook-url" required type="url" pattern="https://.*" maxLength={500} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://siem.example.com/passkey-x" /></div></div>
          <fieldset className="webhook-filters"><legend>Events to send</legend>
            <label className={filters.length === 0 ? "active" : ""}><input type="checkbox" checked={filters.length === 0} onChange={() => setFilters([])} /> All events</label>
            {WEBHOOK_EVENT_FILTERS.map((entry) => <label key={entry.value} className={filters.includes(entry.value) ? "active" : ""}><input type="checkbox" checked={filters.includes(entry.value)} onChange={(event) => setFilters(event.target.checked ? [...filters, entry.value] : filters.filter((value) => value !== entry.value))} /> {entry.label}</label>)}
          </fieldset>
          <div className="inline-actions"><Button disabled={busy !== ""}>{busy === "create" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Create endpoint</Button><Button type="button" variant="ghost" onClick={() => setAdding(false)}>Cancel</Button></div>
          <p className="field-hint">Streaming starts with new events. Delivery is in order and at-least-once: a batch is retried with backoff until your endpoint returns 2xx.</p>
        </form>}
        {message && <p className="form-message" role="status">{message}</p>}
        {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : hooks.length === 0 && !adding ? <div className="empty-state"><Activity /><p>No streaming endpoints yet.</p></div> :
          <ul className="webhook-list">{hooks.map((hook) => {
            const health = webhookHealth(hook);
            return <li key={hook.id}>
              <div className="webhook-main"><span className={`webhook-dot ${health.tone}`} /><div><strong>{hook.name}</strong><code>{hook.url}</code><small>{health.label} · last delivery {relativeTime(hook.last_success_at, now)}{hook.event_prefixes.length ? ` · ${hook.event_prefixes.length} event filter${hook.event_prefixes.length === 1 ? "" : "s"}` : " · all events"}</small>
                {hook.last_error && <small className="webhook-error">Last error: {hook.last_status === 421 ? "the address resolves to a private or internal network, so delivery was blocked" : hook.last_status === 504 ? "the endpoint did not respond in time" : hook.last_error}{hook.last_status && hook.last_status !== 421 ? ` (HTTP ${hook.last_status})` : ""}</small>}
                {hook.last_test_at && <small>Test {relativeTime(hook.last_test_at, now)}: {hook.last_test_status === null ? "waiting for a response…" : hook.last_test_status >= 200 && hook.last_test_status < 300 ? `delivered (HTTP ${hook.last_test_status})` : hook.last_test_status === 0 ? "no response" : `failed (HTTP ${hook.last_test_status})`}</small>}
              </div></div>
              {isTenantAdmin && <div className="webhook-actions">
                <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`test:${hook.id}`, () => testAuditWebhook(hook.id), "Test event sent. Refresh in a few seconds to see the result.")}>{busy === `test:${hook.id}` ? <LoaderCircle className="spin" /> : <Send />} Test</Button>
                <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`toggle:${hook.id}`, () => setAuditWebhookEnabled(hook.id, !hook.enabled))}>{hook.enabled ? "Pause" : "Resume"}</Button>
                <Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => { if (window.confirm("Rotate the signing secret? Your receiver must be updated with the new secret.")) void run(`rotate:${hook.id}`, async () => { setSecret(await rotateAuditWebhookSecret(hook.id)); }); }}><KeyRound /> Rotate secret</Button>
                <Button size="icon-sm" variant="ghost" aria-label={`Delete ${hook.name}`} disabled={busy !== ""} onClick={() => { if (window.confirm(`Delete “${hook.name}”? Streaming to this endpoint stops immediately.`)) void run(`delete:${hook.id}`, () => deleteAuditWebhook(hook.id), "Endpoint deleted."); }}><Trash2 /></Button>
              </div>}
            </li>;
          })}</ul>}
      </CardContent>
    </Card>
    <Card>
      <CardHeader><CardTitle>Verify signatures</CardTitle><CardDescription>Each request carries <code>X-PasskeyX-Timestamp</code> and <code>X-PasskeyX-Signature: v1=HMAC-SHA256(secret, timestamp + &quot;.&quot; + body)</code>. Reject requests older than five minutes.</CardDescription></CardHeader>
      <CardContent><pre className="code-sample">{SIGNATURE_EXAMPLE}</pre></CardContent>
    </Card>
  </div>;
}
