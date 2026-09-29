"use client";

import { useEffect, useState } from "react";
import {
  AlarmClock, Check, Copy, HeartHandshake, KeyRound, LifeBuoy, LoaderCircle, LockOpen, ShieldAlert, Siren, Trash2, UserPlus, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { copySecret } from "@/components/enterprise/vault-guards";
import {
  acceptEmergencyGrant, createEmergencyGrant, decideEmergencyAccess, describeWait, isReleased, listEmergencyGrants,
  openEmergencyVault, releaseTime, requestEmergencyAccess, revokeEmergencyAccess,
  type EmergencyGrant, type EmergencyKind, type EmergencyLink,
} from "@/lib/enterprise/emergency";
import type { WorkspaceVault } from "@/lib/vault/items";
import { shareOrigin } from "@/lib/desktop/bridge";

const PERSONAL_WAITS = [24, 48, 72, 168, 336, 720];
const BREAK_GLASS_WAITS = [0, 1, 4, 24];
const ACCESS_DURATIONS = [24, 72, 168, 336];

export function emergencyError(reason: unknown, fallback: string) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : "";
  if (/PGRST202|42883|PGRST205|42P01/iu.test(`${detail} ${(reason as { code?: string } | null)?.code ?? ""}`)) return "Emergency access is being enabled for your account. Try again shortly.";
  if (/waiting period of at least 24 hours/iu.test(detail)) return "Emergency contacts need a waiting period of at least one day.";
  if (/at most 10/iu.test(detail)) return "A vault can have up to 10 emergency contacts.";
  if (/business plan required/iu.test(detail)) return "Break-glass access is part of the Business plan. Upgrade this organization to use it.";
  if (/only organization administrators/iu.test(detail)) return "Only organization administrators can set up break-glass access.";
  if (/sharing|organization members/iu.test(detail)) return "Your organization's sharing policy does not allow this person as an emergency contact.";
  if (/not been released/iu.test(detail)) return "Access has not been released yet.";
  if (/key changed/iu.test(detail)) return "This vault's key changed after access was granted. Ask the owner for a new grant.";
  if (/invalid or expired/iu.test(detail)) return "This emergency access invitation is invalid, expired, or addressed to another email.";
  if (/two-step/iu.test(detail)) return "Complete two-step verification first.";
  return fallback;
}

function statusLabel(grant: EmergencyGrant, now: number) {
  switch (grant.status) {
    case "invited": return "Invitation sent";
    case "active": return "Ready";
    case "requested": return isReleased(grant, now) ? "Released" : "Access requested";
    case "approved": return "Approved";
    case "used": return "Opened";
    default: return "Revoked";
  }
}

/** Banner that accepts a #emergency= invitation link. */
export function EmergencyInviteBanner({ link, rootKey, onDone }: { link: EmergencyLink; rootKey: Uint8Array; onDone: (message: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function accept() {
    setBusy(true); setMessage("");
    try {
      await acceptEmergencyGrant(link, rootKey);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      onDone("You are now an emergency contact. If you ever need access, request it from Emergency access.");
    } catch (reason) { setMessage(emergencyError(reason, "This invitation could not be accepted. Try again.")); }
    finally { setBusy(false); }
  }
  return <div className="secure-link-banner"><span className="feature-icon"><LifeBuoy /></span><div><strong>Emergency access invitation</strong>
    <p>Someone trusts you with emergency access to their vault. Accepting stores the invitation secret encrypted with your own keys; nothing opens until you request access and it is approved or the waiting period passes.</p>
    {message && <p className="form-message" role="alert">{message}</p>}</div>
    <Button disabled={busy} onClick={() => void accept()}>{busy ? <LoaderCircle className="spin" /> : <Check />} Accept</Button>
    <Button variant="ghost" onClick={() => { window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`); onDone(""); }}><X /> Not now</Button>
  </div>;
}

export function EmergencyAccessView({ vault, workspaces, identityId, rootKey, onOpened }: {
  vault: WorkspaceVault;
  workspaces: WorkspaceVault[];
  identityId: string;
  rootKey: Uint8Array;
  onOpened: (workspaceId: string) => Promise<void>;
}) {
  const { isOrganization, isTenantAdmin } = useEnterprise();
  const [grants, setGrants] = useState<EmergencyGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [link, setLink] = useState("");
  const [copied, setCopied] = useState(false);
  const [now] = useState(() => Date.now());
  const canBreakGlass = isOrganization && isTenantAdmin;
  const [kind, setKind] = useState<EmergencyKind>("personal");
  const [email, setEmail] = useState("");
  const [label, setLabel] = useState("");
  const [waitHours, setWaitHours] = useState(72);
  const [accessHours, setAccessHours] = useState(168);
  const canGrant = vault.role === "owner" || vault.role === "manager";

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => { if (active) setLoading(true); })
      .then(() => listEmergencyGrants())
      .then((rows) => { if (active) setGrants(rows); }, (reason) => { if (active) setMessage(emergencyError(reason, "Emergency access could not be loaded.")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [version]);

  const names = new Map(workspaces.map((entry) => [entry.workspaceId, entry.name]));
  const incoming = grants.filter((grant) => grant.grantee_identity_id === identityId && grant.status !== "revoked");
  const outgoing = grants.filter((grant) => grant.grantee_identity_id !== identityId && grant.status !== "revoked");
  const toDecide = outgoing.filter((grant) => grant.status === "requested" && (grant.grantor_identity_id === identityId || (grant.kind === "break_glass" && isTenantAdmin)));

  async function run(key: string, action: () => Promise<void>, success?: string) {
    setBusy(key); setMessage("");
    try { await action(); if (success) setMessage(success); setVersion((value) => value + 1); }
    catch (reason) { setMessage(emergencyError(reason, "That change could not be saved. Try again.")); }
    finally { setBusy(""); }
  }

  function create(event: React.FormEvent) {
    event.preventDefault(); setLink(""); setCopied(false);
    void run("create", async () => {
      setLink(await createEmergencyGrant(vault, { email, label, kind, waitHours, accessHours, origin: shareOrigin() }));
      setEmail(""); setLabel("");
    });
  }

  function chooseKind(next: EmergencyKind) {
    setKind(next);
    setWaitHours(next === "break_glass" ? 0 : 72);
    setAccessHours(next === "break_glass" ? 24 : 168);
  }

  return <div className="feature-page emergency-page">
    <div className="feature-intro"><div>
      <span className="status-pill"><LifeBuoy /> Emergency access</span>
      <h2>Make sure someone you trust can get in when it matters</h2>
      <p>Emergency contacts can request read-only access to a vault. You can deny the request during the waiting period; if you don’t respond, access opens automatically. Everything stays end-to-end encrypted — Vlightsoft can never open your vault.</p>
    </div></div>

    {message && <p className="settings-message" role="status">{message}</p>}

    {toDecide.length > 0 && <Card className="emergency-alert-card"><CardHeader><CardTitle><Siren /> Requests waiting for you</CardTitle>
      <CardDescription>Deny a request to keep the vault closed. Approving opens it now.</CardDescription></CardHeader>
      <CardContent><ul className="emergency-list">{toDecide.map((grant) => {
        const release = releaseTime(grant);
        return <li key={grant.id}><div><strong>{grant.label ?? "Emergency contact"}</strong><small>{names.get(grant.workspace_id) ?? "Vault"} · {grant.kind === "break_glass" ? "Break-glass" : "Emergency contact"} · opens automatically {release ? release.toLocaleString() : "soon"}</small></div>
          <div className="inline-actions"><Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void run(`deny:${grant.id}`, () => decideEmergencyAccess(grant.id, false), "Request denied. The vault stays closed.")}><X /> Deny</Button>
            <Button size="sm" disabled={busy !== ""} onClick={() => void run(`approve:${grant.id}`, () => decideEmergencyAccess(grant.id, true), "Request approved.")}><Check /> Approve now</Button></div></li>;
      })}</ul></CardContent></Card>}

    <div className="settings-grid">
      <Card>
        <CardHeader><CardTitle><HeartHandshake /> Your emergency contacts</CardTitle>
          <CardDescription>People who can request access to your vaults. Only an encrypted copy of a one-time key is stored, unlocked by their own account.</CardDescription></CardHeader>
        <CardContent>
          {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : outgoing.length === 0 ? <div className="empty-state"><LifeBuoy /><p>No emergency contacts yet.</p></div> :
            <ul className="emergency-list">{outgoing.map((grant) => <li key={grant.id}>
              <div><strong>{grant.label ?? (grant.kind === "break_glass" ? "Break-glass holder" : "Emergency contact")}</strong>
                <small>{names.get(grant.workspace_id) ?? "Vault"} · waits {describeWait(grant.wait_hours)} · {Math.round(grant.access_hours / 24) || 1} day access</small></div>
              <span className={`emergency-status ${grant.status}`}>{statusLabel(grant, now)}</span>
              {(grant.grantor_identity_id === identityId || (grant.kind === "break_glass" && isTenantAdmin)) && grant.status !== "used" &&
                <Button size="icon-sm" variant="ghost" aria-label="Remove emergency contact" disabled={busy !== ""} onClick={() => { if (window.confirm("Remove this emergency contact? Their pending access is cancelled.")) void run(`revoke:${grant.id}`, () => revokeEmergencyAccess(grant.id), "Emergency contact removed."); }}><Trash2 /></Button>}
            </li>)}</ul>}

          {canGrant ? <form className="form-stack emergency-form" onSubmit={create}>
            <h3><UserPlus /> Add a contact for “{vault.name}”</h3>
            {canBreakGlass && <div className="billing-segment" role="group" aria-label="Access type">
              <button type="button" className={kind === "personal" ? "active" : ""} onClick={() => chooseKind("personal")}>Emergency contact</button>
              <button type="button" className={kind === "break_glass" ? "active" : ""} onClick={() => chooseKind("break_glass")}>Break-glass</button>
            </div>}
            <div className="inline-fields">
              <div><Label htmlFor="ea-email">Their email</Label><Input id="ea-email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="name@example.com" /></div>
              <div><Label htmlFor="ea-label">Name (optional)</Label><Input id="ea-label" maxLength={80} value={label} onChange={(event) => setLabel(event.target.value)} placeholder={kind === "break_glass" ? "Security on-call" : "Partner"} /></div>
            </div>
            <div className="inline-fields">
              <div><Label htmlFor="ea-wait">Waiting period</Label><select id="ea-wait" value={waitHours} onChange={(event) => setWaitHours(Number(event.target.value))}>
                {(kind === "break_glass" ? BREAK_GLASS_WAITS : PERSONAL_WAITS).map((hours) => <option key={hours} value={hours}>{hours === 0 ? "None — opens on request (alerts admins)" : describeWait(hours)}</option>)}</select></div>
              <div><Label htmlFor="ea-access">Access lasts</Label><select id="ea-access" value={accessHours} onChange={(event) => setAccessHours(Number(event.target.value))}>
                {ACCESS_DURATIONS.map((hours) => <option key={hours} value={hours}>{describeWait(hours)}</option>)}</select></div>
            </div>
            <Button disabled={busy !== ""}>{busy === "create" ? <LoaderCircle className="spin" /> : <KeyRound />} Create invitation link</Button>
            <p className="field-hint">Access is read-only and ends automatically. {kind === "break_glass" ? "Every break-glass request raises a critical security alert for administrators." : "You’ll see requests here and can deny them during the waiting period."}</p>
          </form> : <p className="field-hint">Switch to a vault you own or manage to add emergency contacts.</p>}

          {link && <div className="one-time-link"><strong>Send this link to them now — it is shown once</strong><code>{link}</code>
            <Button size="sm" variant="outline" onClick={async () => { try { await copySecret(link, 120); setCopied(true); } catch { /* clipboard blocked */ } }}>{copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy link"}</Button>
            <small>The one-time key lives only in the link’s # fragment. They must sign in with the same email to accept.</small></div>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle><ShieldAlert /> Vaults you can open in an emergency</CardTitle>
          <CardDescription>Requests are recorded in the owner’s audit log and they are notified.</CardDescription></CardHeader>
        <CardContent>
          {loading ? <div className="vault-loading"><div className="loading-ring" /></div> : incoming.length === 0 ? <div className="empty-state"><HeartHandshake /><p>No one has named you as an emergency contact.</p></div> :
            <ul className="emergency-list">{incoming.map((grant) => {
              const released = isReleased(grant, now);
              const release = releaseTime(grant);
              return <li key={grant.id}>
                <div><strong>{grant.label ?? (grant.kind === "break_glass" ? "Break-glass access" : "Emergency access")}</strong>
                  <small>{grant.status === "requested" && !released && release ? `Opens ${release.toLocaleString()} unless the owner denies it` : `Waiting period ${describeWait(grant.wait_hours)} · read-only for ${describeWait(grant.access_hours)}`}</small></div>
                <span className={`emergency-status ${grant.status}`}>{statusLabel(grant, now)}</span>
                {grant.status === "active" && <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => { if (window.confirm("Request emergency access? The owner will be notified.")) void run(`request:${grant.id}`, async () => { const at = await requestEmergencyAccess(grant.id); setMessage(`Access requested. It opens ${new Date(at).toLocaleString()} unless the owner denies it.`); }); }}><AlarmClock /> Request access</Button>}
                {released && <Button size="sm" disabled={busy !== ""} onClick={() => void run(`open:${grant.id}`, async () => { const opened = await openEmergencyVault(grant.id, rootKey); await onOpened(opened.workspaceId); }, "Vault opened read-only. Find it in your workspace list.")}>{busy === `open:${grant.id}` ? <LoaderCircle className="spin" /> : <LockOpen />} Open vault</Button>}
              </li>;
            })}</ul>}
        </CardContent>
      </Card>
    </div>
  </div>;
}

/** Shows a prominent notice when someone has requested emergency access to the user's vaults. */
export function EmergencyRequestNotice({ identityId, onReview }: { identityId: string; onReview: () => void }) {
  const [pending, setPending] = useState(0);
  useEffect(() => {
    let active = true;
    listEmergencyGrants()
      .then((rows) => { if (active) setPending(rows.filter((grant) => grant.status === "requested" && grant.grantor_identity_id === identityId).length); })
      .catch(() => undefined);
    return () => { active = false; };
  }, [identityId]);
  if (!pending) return null;
  return <div className="secure-link-banner emergency-notice" role="alert"><span className="feature-icon"><Siren /></span><div>
    <strong>{pending === 1 ? "Someone requested emergency access to your vault" : `${pending} emergency access requests are waiting`}</strong>
    <p>If you did not expect this, deny it now. Otherwise access opens automatically when the waiting period ends.</p></div>
    <Button onClick={onReview}>Review</Button></div>;
}
