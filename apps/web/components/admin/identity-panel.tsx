"use client";

import { useEffect, useState } from "react";
import {
  BadgeCheck, Check, Copy, Download, FileKey, Globe, KeyRound, LifeBuoy, LoaderCircle, RefreshCw, ShieldCheck, Trash2, Upload, UserCog, Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { copySecret } from "@/components/enterprise/vault-guards";
import { downloadBlob } from "@/lib/browser/download";
import { relativeTime } from "@/lib/enterprise/admin";
import {
  createScimToken, listProvisionedUsers, listScimTokens, loadSsoConnection, requestSsoActivation, revokeScimToken,
  saveSsoConnection, scimBaseUrl, setSsoEnforcement, verifySsoDomain,
  type ProvisionedUser, type ScimToken, type SsoConnection,
} from "@/lib/enterprise/identity";
import {
  approveRecovery, denyRecovery, generateRecoveryKit, loadRecoveryKey, loadRecoveryQueue, parseRecoveryKit, publishRecoveryKey,
  type OrganizationRecoveryKey, type RecoveryKit, type RecoveryQueueEntry,
} from "@/lib/enterprise/org-recovery";
import type { WorkspaceVault } from "@/lib/vault/items";

function identityError(reason: unknown, fallback: string) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : "";
  if (/own email domain/iu.test(detail)) return "Use your organization's own email domain, not a public email provider.";
  if (/verify your domain/iu.test(detail)) return "Verify your domain first.";
  if (/metadata URL/iu.test(detail)) return "Add your identity provider's SAML metadata URL first.";
  if (/must be active/iu.test(detail)) return "Single sign-on must be active before it can be required.";
  if (/at most 3/iu.test(detail)) return "An organization can have up to 3 active provisioning tokens.";
  if (/duplicate key|already exists|23505/iu.test(detail)) return "That domain is already connected to another organization.";
  return adminErrorMessage(reason, fallback);
}

function CopyValue({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return <Button size="sm" variant="outline" onClick={async () => { try { await copySecret(value, 120); setCopied(true); } catch { /* clipboard blocked */ } }}>{copied ? <Check /> : <Copy />} {copied ? "Copied" : label}</Button>;
}

function SsoCard({ vault, canEdit }: { vault: WorkspaceVault; canEdit: boolean }) {
  const { isTenantAdmin } = useEnterprise();
  const [connection, setConnection] = useState<SsoConnection | null>(null);
  const [domain, setDomain] = useState("");
  const [metadataUrl, setMetadataUrl] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    loadSsoConnection(vault.tenantId).then((row) => {
      if (!active) return;
      setConnection(row); setDomain(row?.domain ?? ""); setMetadataUrl(row?.metadata_url ?? "");
    }, (reason) => { if (active) setMessage(identityError(reason, "Single sign-on settings could not be loaded.")); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function run(key: string, action: () => Promise<void>) {
    setBusy(key); setMessage("");
    try { await action(); setVersion((value) => value + 1); }
    catch (reason) { setMessage(identityError(reason, "The change could not be saved.")); }
    finally { setBusy(""); }
  }

  const editable = isTenantAdmin && canEdit;
  const steps = [
    { done: Boolean(connection), label: "Add your email domain and identity provider" },
    { done: Boolean(connection?.domain_verified_at), label: "Verify the domain with a DNS TXT record" },
    { done: connection?.status === "requested" || connection?.status === "active", label: "Request activation" },
    { done: connection?.status === "active", label: "Vlightsoft connects your identity provider" },
  ];

  return <Card>
    <CardHeader><CardTitle><Globe /> Single sign-on (SAML)</CardTitle>
      <CardDescription>Members sign in to their account through Okta, Microsoft Entra ID, Google Workspace or any SAML 2.0 provider. Vault passwords stay separate, so SSO never gives your identity provider access to vault data.</CardDescription></CardHeader>
    <CardContent>
      <ol className="identity-steps">{steps.map((step) => <li key={step.label} className={step.done ? "done" : ""}>{step.done ? <BadgeCheck /> : <span />}{step.label}</li>)}</ol>
      <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("save", () => saveSsoConnection(vault.tenantId, domain, metadataUrl)); }}>
        <div className="inline-fields">
          <div><Label htmlFor="sso-domain">Email domain</Label><Input id="sso-domain" required disabled={!editable} value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="acme.com" /></div>
          <div><Label htmlFor="sso-metadata">IdP metadata URL</Label><Input id="sso-metadata" type="url" pattern="https://.*" disabled={!editable} value={metadataUrl} onChange={(event) => setMetadataUrl(event.target.value)} placeholder="https://login.example.com/app/…/sso/saml/metadata" /></div>
        </div>
        {editable && <Button disabled={busy !== ""}>{busy === "save" ? <LoaderCircle className="spin" /> : <Check />} Save</Button>}
      </form>
      {connection && !connection.domain_verified_at && <div className="one-time-link"><strong>Add this TXT record to {connection.domain}</strong><code>{connection.verification_token}</code>
        <div className="inline-actions"><CopyValue value={connection.verification_token} label="Copy record" />
          {editable && <Button size="sm" disabled={busy !== ""} onClick={() => void run("verify", async () => { if (!await verifySsoDomain(vault.tenantId)) throw new Error("The TXT record was not found yet. DNS changes can take up to an hour."); })}>{busy === "verify" ? <LoaderCircle className="spin" /> : <RefreshCw />} Check DNS</Button>}</div>
        <small>You can also add it at _passkey-x.{connection.domain}.</small></div>}
      {connection?.domain_verified_at && connection.status === "draft" && editable && <Button onClick={() => void run("request", () => requestSsoActivation(vault.tenantId))} disabled={busy !== ""}>Request activation</Button>}
      {connection?.status === "requested" && <p className="field-hint">Activation requested. Vlightsoft will connect your identity provider and email you. In your IdP use ACS URL <code>{`${process.env.NEXT_PUBLIC_SUPABASE_URL ?? ""}/auth/v1/sso/saml/acs`}</code> and Entity ID <code>{`${process.env.NEXT_PUBLIC_SUPABASE_URL ?? ""}/auth/v1/sso/saml/metadata`}</code>.</p>}
      {connection?.status === "active" && <label className="toggle-row"><input type="checkbox" disabled={!editable || busy !== ""} checked={connection.enforce_sso} onChange={(event) => void run("enforce", () => setSsoEnforcement(vault.tenantId, event.target.checked))} /> Require SSO for everyone with an @{connection.domain} email</label>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}

function ScimCard({ vault, canEdit }: { vault: WorkspaceVault; canEdit: boolean }) {
  const { isTenantAdmin } = useEnterprise();
  const [tokens, setTokens] = useState<ScimToken[]>([]);
  const [users, setUsers] = useState<ProvisionedUser[]>([]);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);
  const [now] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    Promise.all([listScimTokens(vault.tenantId), listProvisionedUsers(vault.tenantId)])
      .then(([nextTokens, nextUsers]) => { if (active) { setTokens(nextTokens); setUsers(nextUsers); } },
        (reason) => { if (active) setMessage(identityError(reason, "Provisioning settings could not be loaded.")); });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function run(key: string, action: () => Promise<void>) {
    setBusy(key); setMessage("");
    try { await action(); setVersion((value) => value + 1); }
    catch (reason) { setMessage(identityError(reason, "The change could not be saved.")); }
    finally { setBusy(""); }
  }

  const editable = isTenantAdmin && canEdit;
  const activeTokens = tokens.filter((token) => !token.revoked_at);
  const joined = users.filter((user) => user.identity_id).length;

  return <Card>
    <CardHeader><CardTitle><UserCog /> Automatic provisioning (SCIM 2.0)</CardTitle>
      <CardDescription>Your identity provider adds and removes people automatically. New people are pre-approved and join with one click after creating their vault password; removed people lose all vault access immediately and affected workspaces are flagged for key rotation.</CardDescription></CardHeader>
    <CardContent>
      <div className="setting-row"><span>SCIM base URL</span><code className="wrap-code">{scimBaseUrl()}</code></div>
      <div className="setting-row"><span>Provisioned people</span><strong>{users.length} ({joined} joined)</strong></div>
      {secret && <div className="webhook-secret" role="status"><KeyRound /><div><strong>Provisioning token — shown once</strong><p>Paste it into your identity provider as the Bearer token.</p><code>{secret}</code></div>
        <div className="inline-actions"><CopyValue value={secret} label="Copy" /><Button size="sm" variant="ghost" onClick={() => setSecret("")}>I saved it</Button></div></div>}
      <ul className="emergency-list">{activeTokens.map((token) => <li key={token.id}><div><strong>{token.name}</strong><small>…{token.token_hint} · last used {relativeTime(token.last_used_at, now)}</small></div>
        {editable && <Button size="icon-sm" variant="ghost" aria-label={`Revoke ${token.name}`} disabled={busy !== ""} onClick={() => { if (window.confirm(`Revoke “${token.name}”? Provisioning with it stops immediately.`)) void run(`revoke:${token.id}`, () => revokeScimToken(token.id)); }}><Trash2 /></Button>}</li>)}</ul>
      {editable && <form className="inline-fields" onSubmit={(event) => { event.preventDefault(); void run("create", async () => { setSecret(await createScimToken(vault.tenantId, name)); setName(""); }); }}>
        <div><Label htmlFor="scim-name">Token name</Label><Input id="scim-name" required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Okta production" /></div>
        <div className="align-end"><Button disabled={busy !== "" || activeTokens.length >= 3}>{busy === "create" ? <LoaderCircle className="spin" /> : <KeyRound />} Create token</Button></div>
      </form>}
      {users.length > 0 && <details className="provisioned-users"><summary><Users /> Provisioned people</summary>
        <ul>{users.slice(0, 100).map((user) => <li key={user.id}><span>{user.display_name}</span><small>{user.user_name}</small><em className={user.active ? (user.identity_id ? "joined" : "pending") : "inactive"}>{user.active ? (user.identity_id ? "Joined" : "Invited") : "Deactivated"}</em></li>)}</ul></details>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}

function RecoveryCard({ vault }: { vault: WorkspaceVault }) {
  const { policy, isTenantAdmin } = useEnterprise();
  const [key, setKey] = useState<OrganizationRecoveryKey | null>(null);
  const [queue, setQueue] = useState<RecoveryQueueEntry[]>([]);
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [code, setCode] = useState<{ name: string; value: string } | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let active = true;
    Promise.allSettled([loadRecoveryKey(vault.tenantId), loadRecoveryQueue(vault.tenantId)]).then(([nextKey, nextQueue]) => {
      if (!active) return;
      if (nextKey.status === "fulfilled") setKey(nextKey.value);
      if (nextQueue.status === "fulfilled") setQueue(nextQueue.value);
    });
    return () => { active = false; };
  }, [vault.tenantId, version]);

  async function run(label: string, action: () => Promise<void>) {
    setBusy(label); setMessage("");
    try { await action(); setVersion((value) => value + 1); }
    catch (reason) { setMessage(reason instanceof Error && !("code" in reason) ? reason.message : identityError(reason, "The change could not be saved.")); }
    finally { setBusy(""); }
  }

  async function createKey() {
    if (key && !window.confirm("Replace the organization recovery key? Members re-enroll automatically, and the old kit stops working.")) return;
    await run("generate", async () => {
      const generated = await generateRecoveryKit(vault.tenantId);
      downloadBlob(new Blob([JSON.stringify(generated.kit, null, 2)], { type: "application/json" }), `passkey-x-recovery-kit-${generated.kit.fingerprint.replaceAll(":", "")}.json`);
      await publishRecoveryKey(vault.tenantId, generated.kit, generated.publicKey);
      setKit(generated.kit);
      setMessage("Recovery kit downloaded. Store it offline (for example in a safe or an HSM-backed vault). Anyone with this file and admin access can recover member vaults.");
    });
  }

  async function loadKit(file: File) {
    try { setKit(parseRecoveryKit(await file.text(), vault.tenantId)); setMessage("Recovery kit loaded in this browser tab only."); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "That file could not be read."); }
  }

  return <Card>
    <CardHeader><CardTitle><LifeBuoy /> Organization recovery</CardTitle>
      <CardDescription>Optional. When the “Organization account recovery” policy is on, members’ apps encrypt their vault key to your organization’s recovery key so an administrator can help them if they forget their vault password. Members are told when this is on. Vlightsoft can never use it.</CardDescription></CardHeader>
    <CardContent>
      <div className="setting-row"><span>Policy</span><strong>{policy.organizationRecovery ? "On" : "Off — enable it in Policies"}</strong></div>
      <div className="setting-row"><span>Recovery key</span><strong>{key ? `Fingerprint ${key.fingerprint}` : "Not created"}</strong></div>
      {isTenantAdmin && <div className="inline-actions">
        <Button variant={key ? "outline" : "default"} disabled={busy !== ""} onClick={() => void createKey()}>{busy === "generate" ? <LoaderCircle className="spin" /> : <Download />} {key ? "Replace key & download kit" : "Create key & download kit"}</Button>
        <label className="button-like"><Upload /> {kit ? "Kit loaded" : "Load kit"}<input type="file" accept="application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void loadKit(file); event.target.value = ""; }} /></label>
      </div>}
      {code && <div className="webhook-secret" role="status"><FileKey /><div><strong>One-time recovery code for {code.name}</strong><p>Give this to them in person or over a verified channel. It expires in 24 hours.</p><code>{code.value}</code></div>
        <div className="inline-actions"><CopyValue value={code.value} label="Copy" /><Button size="sm" variant="ghost" onClick={() => setCode(null)}>Done</Button></div></div>}
      <h4 className="identity-subheading"><ShieldCheck /> Pending recovery requests</h4>
      {queue.length === 0 ? <p className="field-hint">No one is waiting for recovery.</p> :
        <ul className="emergency-list">{queue.map((entry) => <li key={entry.request_id}><div><strong>{entry.display_name}</strong><small>{entry.email ?? ""} · requested {new Date(entry.created_at).toLocaleString()}</small></div>
          <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`deny:${entry.request_id}`, () => denyRecovery(entry.request_id))}>Deny</Button>
          <Button size="sm" disabled={busy !== "" || !kit} title={kit ? undefined : "Load the recovery kit first"} onClick={() => { if (!kit) return; if (!window.confirm(`Confirm you verified ${entry.display_name}'s identity out of band. Approving decrypts their vault key in this browser.`)) return; void run(`approve:${entry.request_id}`, async () => { const value = await approveRecovery(kit, entry, vault.tenantId); setCode({ name: entry.display_name, value }); }); }}>{busy === `approve:${entry.request_id}` ? <LoaderCircle className="spin" /> : <Check />} Approve</Button></li>)}</ul>}
      {message && <p className="form-message" role="status">{message}</p>}
    </CardContent>
  </Card>;
}

export function IdentityPanel({ vault, canEdit }: { vault: WorkspaceVault; canEdit: boolean }) {
  return <div className="identity-panel">
    <SsoCard vault={vault} canEdit={canEdit} />
    <ScimCard vault={vault} canEdit={canEdit} />
    <RecoveryCard vault={vault} />
  </div>;
}
