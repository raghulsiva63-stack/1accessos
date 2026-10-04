"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { BookOpen, KeyRound, LoaderCircle, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { relativeTime } from "@/lib/enterprise/admin";
import {
  API_SCOPES, apiKeyState, createOrgApiKey, curlExample, listOrgApiKeys, orgApiBaseUrl, revokeOrgApiKey,
  type ApiScope, type OrgApiKey,
} from "@/lib/enterprise/connectors";
import { Badge, integrationError, SecretReveal, StatusMessage, type Tone } from "./shared";

const EXPIRY_OPTIONS = [30, 90, 180, 365];

const STATE_BADGE: Record<ReturnType<typeof apiKeyState>, { tone: Tone; label: string }> = {
  active: { tone: "good", label: "Active" },
  expiring: { tone: "warn", label: "Expiring soon" },
  expired: { tone: "bad", label: "Expired" },
  revoked: { tone: "idle", label: "Revoked" },
};

function day(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString();
}

function scopeLabel(scope: ApiScope) {
  return API_SCOPES.find((entry) => entry.value === scope)?.label ?? scope;
}

export function ApiKeysCard({ tenantId, isAdmin }: { tenantId: string; isAdmin: boolean }) {
  const [keys, setKeys] = useState<OrgApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState("");
  const [token, setToken] = useState("");
  const [version, setVersion] = useState(0);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiScope[]>(["alerts:read"]);
  const [expiry, setExpiry] = useState(90);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) { setLoading(true); setNow(Date.now()); } })
      .then(() => listOrgApiKeys(tenantId))
      .then((rows) => { if (active) setKeys(rows); }, (reason) => { if (active) setMessage(integrationError(reason, "API keys could not be loaded.")); })
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
    setAdding(false); setName(""); setScopes(["alerts:read"]); setExpiry(90);
  }

  function create(event: React.FormEvent) {
    event.preventDefault();
    if (scopes.length === 0) { setMessage("Choose at least one permission."); return; }
    void run("create", async () => {
      const created = await createOrgApiKey(tenantId, name, scopes, expiry);
      setToken(created.token); resetForm();
    });
  }

  const base = orgApiBaseUrl();

  return <Card>
    <CardHeader>
      <div className="panel-heading"><div><CardTitle><KeyRound /> API keys</CardTitle>
        <CardDescription>Organization API keys let your SIEM, ticketing system, Zapier or Make read audit events, alerts, members and reports. Keys are scoped and expire; vault contents are never available through the API.</CardDescription></div>
        <div className="inline-actions"><Button variant="ghost" size="icon-sm" aria-label="Refresh API keys" onClick={() => setVersion((value) => value + 1)}><RefreshCw /></Button>
          {isAdmin && !adding && <Button size="sm" onClick={() => { setAdding(true); setMessage(""); setNotice(""); }}><Plus /> Create API key</Button>}</div></div>
    </CardHeader>
    <CardContent className="si-stack">
      {token && <SecretReveal secret={token} title="API key — shown once" description="Copy it into your integration now. Passkey-X stores only a hash and cannot show it again." onDone={() => setToken("")} />}
      {adding && <form className="webhook-form cx-form" onSubmit={create}>
        <div className="cx-fields">
          <div><Label htmlFor="cx-key-name">Name</Label><Input id="cx-key-name" required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Jira alert sync" /></div>
          <div><Label htmlFor="cx-key-expiry">Expires after</Label>
            <select id="cx-key-expiry" className="cx-select" value={expiry} onChange={(event) => setExpiry(Number(event.target.value))}>
              {EXPIRY_OPTIONS.map((days) => <option key={days} value={days}>{days} days</option>)}
            </select></div>
        </div>
        <fieldset className="cx-checks"><legend>Permissions</legend>
          {API_SCOPES.map((entry) => <label key={entry.value}>
            <input type="checkbox" checked={scopes.includes(entry.value)} onChange={(event) => setScopes(event.target.checked ? [...scopes, entry.value] : scopes.filter((value) => value !== entry.value))} />
            <span><strong>{entry.label} <code>{entry.value}</code></strong><small>{entry.hint}</small></span>
          </label>)}
        </fieldset>
        <div className="inline-actions"><Button disabled={busy !== "" || scopes.length === 0}>{busy === "create" ? <LoaderCircle className="spin" /> : <ShieldCheck />} Create key</Button><Button type="button" variant="ghost" onClick={resetForm}>Cancel</Button></div>
        <p className="field-hint">Give each integration its own key with only the permissions it needs. The key is shown once after creation.</p>
      </form>}
      <StatusMessage text={message} />
      <StatusMessage text={notice} tone="neutral" />
      {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : keys.length === 0 ? <div className="empty-state"><KeyRound /><p>No API keys yet.</p></div> :
        <ul className="webhook-list">{keys.map((key) => {
          const state = apiKeyState(key, now);
          const badge = STATE_BADGE[state];
          return <li key={key.id} className={state === "revoked" || state === "expired" ? "cx-muted" : undefined}>
            <div className="webhook-main"><div>
              <span className="cx-title"><strong>{key.name}</strong><Badge tone={badge.tone}>{badge.label}</Badge></span>
              <code>{key.prefix}…</code>
              <span className="cx-chips" aria-label="Permissions">{key.scopes.map((scope) => <span key={scope} className="cx-chip" title={scopeLabel(scope)}>{scope}</span>)}</span>
              <small>Created {day(key.created_at)} · {state === "revoked" && key.revoked_at ? `revoked ${day(key.revoked_at)}` : `${state === "expired" ? "expired" : "expires"} ${day(key.expires_at)}`} · last used {relativeTime(key.last_used_at, now).toLowerCase()}</small>
            </div></div>
            {isAdmin && state !== "revoked" && <div className="webhook-actions">
              <Button size="sm" variant="ghost" disabled={busy !== ""} aria-label={`Revoke ${key.name}`} onClick={() => { if (window.confirm(`Revoke “${key.name}”? Integrations using this key stop working immediately. This can't be undone.`)) void run(`revoke:${key.id}`, () => revokeOrgApiKey(key.id), "API key revoked."); }}>{busy === `revoke:${key.id}` ? <LoaderCircle className="spin" /> : <Trash2 />} Revoke</Button>
            </div>}
          </li>;
        })}</ul>}
      <div className="cx-docs">
        <div><span className="cx-label">Base URL</span><code className="cx-base">{base}</code></div>
        <pre className="code-sample">{curlExample(base)}</pre>
        <p className="field-hint"><strong>Zapier / Make:</strong> use the “Webhooks by Zapier” action or Make’s HTTP module with the header <code>Authorization: Bearer &lt;key&gt;</code>. Poll <code>/v1/alerts</code> for new alerts, or <code>/v1/audit-events?after=&lt;last sequence&gt;</code> to page through audit events.</p>
        <p className="field-hint"><Link className="cx-link" href="/api-docs#organization-api"><BookOpen aria-hidden="true" /> Organization API reference</Link></p>
      </div>
    </CardContent>
  </Card>;
}
