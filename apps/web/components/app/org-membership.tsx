"use client";

import { useEffect, useRef, useState } from "react";
import { Building2, Check, LifeBuoy, LoaderCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { estimateStrength } from "@/lib/enterprise/health";
import { claimProvisionedMembership, myPendingProvisioning, type PendingProvisioning } from "@/lib/enterprise/identity";
import {
  completeRecovery, enrollInOrganizationRecovery, listMyEnrollments, loadMyRecoveryRequest, loadRecoveryKey, myEnrollment,
  requestOrganizationRecovery,
} from "@/lib/enterprise/org-recovery";

/** Offers to join organizations whose identity provider pre-provisioned this email (SCIM). */
export function ProvisioningBanner({ onJoined }: { onJoined: (message: string) => void }) {
  const [pending, setPending] = useState<PendingProvisioning[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    let active = true;
    myPendingProvisioning().then((rows) => { if (active) setPending(rows); }, () => undefined);
    return () => { active = false; };
  }, []);
  const next = pending[0];
  if (!next) return null;
  async function join() {
    setBusy(true); setMessage("");
    try {
      await claimProvisionedMembership(next.id);
      setPending((rows) => rows.slice(1));
      onJoined("You joined your organization. Administrators can now share vaults with you.");
    } catch { setMessage("Joining failed. Your organization may have reached its seat limit — ask an administrator."); }
    finally { setBusy(false); }
  }
  return <div className="secure-link-banner"><span className="feature-icon"><Building2 /></span><div>
    <strong>Your organization set up an account for {next.display_name}</strong>
    <p>Your company’s identity provider added your email address to its Passkey-X organization. Joining lets administrators share vaults with you; your personal vault stays private.</p>
    {message && <p className="form-message" role="alert">{message}</p>}</div>
    <Button disabled={busy} onClick={() => void join()}>{busy ? <LoaderCircle className="spin" /> : <Check />} Join</Button>
    <Button variant="ghost" onClick={() => setPending((rows) => rows.slice(1))}><X /> Later</Button></div>;
}

/**
 * When an organization turns on recovery, seals this member's account root key to the
 * organization recovery key (once per key) and tells the member it happened.
 */
export function OrgRecoveryEnrollment({ tenantId, identityId, rootKey }: { tenantId: string; identityId: string; rootKey: Uint8Array }) {
  const { isOrganization, policy, loading } = useEnterprise();
  const [notice, setNotice] = useState(false);
  const attempted = useRef<string | null>(null);
  const enabled = isOrganization && policy.organizationRecovery && !loading;
  useEffect(() => {
    if (!enabled || attempted.current === tenantId) return;
    attempted.current = tenantId;
    let active = true;
    (async () => {
      const key = await loadRecoveryKey(tenantId);
      if (!key) return;
      const current = await myEnrollment(tenantId, identityId);
      if (current?.key_id === key.key_id) return;
      await enrollInOrganizationRecovery(rootKey, key, identityId);
      if (active) setNotice(true);
    })().catch(() => undefined);
    return () => { active = false; };
  }, [enabled, identityId, rootKey, tenantId]);
  if (!notice) return null;
  return <div className="secure-link-banner"><span className="feature-icon"><LifeBuoy /></span><div>
    <strong>Organization recovery is on for this organization</strong>
    <p>Your organization can help you regain vault access if you forget your vault password. An administrator needs their offline recovery kit and your request to do this, and every recovery is recorded in the audit log.</p></div>
    <Button variant="ghost" onClick={() => setNotice(false)}><X /> OK</Button></div>;
}

type Stage = "loading" | "none" | "choose" | "pending" | "approved";

/** Unlock-screen flow for members who forgot their vault password but are enrolled in organization recovery. */
export function OrgRecoveryUnlock({ identityId, email, onRecovered, onCancel }: {
  identityId: string;
  email: string;
  onRecovered: (profile: { salt: string; kdf_parameters: unknown; master_nonce: string; master_wrapped_root: string }) => void;
  onCancel: () => void;
}) {
  const [stage, setStage] = useState<Stage>("loading");
  const [tenants, setTenants] = useState<string[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [request, setRequest] = useState<{ id: string; release_nonce: string | null; release_ciphertext: string | null; expires_at: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function refresh(target: string) {
    const current = await loadMyRecoveryRequest(target, identityId);
    setRequest(current);
    setStage(current?.status === "approved" ? "approved" : current ? "pending" : "choose");
  }

  useEffect(() => {
    let active = true;
    listMyEnrollments(identityId).then(async (rows) => {
      if (!active) return;
      const ids = rows.map((row) => row.tenant_id);
      setTenants(ids);
      if (!ids.length) { setStage("none"); return; }
      setTenantId(ids[0]);
      const current = await loadMyRecoveryRequest(ids[0], identityId);
      if (!active) return;
      setRequest(current);
      setStage(current?.status === "approved" ? "approved" : current ? "pending" : "choose");
    }, () => { if (active) setStage("none"); });
    return () => { active = false; };
  }, [identityId]);

  async function ask() {
    setBusy(true); setMessage("");
    try { await requestOrganizationRecovery(tenantId); await refresh(tenantId); }
    catch { setMessage("The request could not be sent. Try again."); }
    finally { setBusy(false); }
  }

  async function finish(event: React.FormEvent) {
    event.preventDefault(); setMessage("");
    if (!request?.release_nonce || !request.release_ciphertext) return;
    if (password !== confirm) { setMessage("The new vault passwords do not match."); return; }
    if (password.length < 12 || estimateStrength(password).score < 2) { setMessage("Choose a stronger vault password: at least 12 characters that are hard to guess."); return; }
    if (password.trim().toLowerCase() === email.trim().toLowerCase()) { setMessage("Your vault password must not be your email address."); return; }
    setBusy(true);
    try {
      const next = await completeRecovery({ id: request.id, release_nonce: request.release_nonce, release_ciphertext: request.release_ciphertext }, code, password);
      setPassword(""); setConfirm(""); setCode("");
      onRecovered(next);
    } catch (reason) { setMessage(reason instanceof Error && !("code" in reason) ? reason.message : "Recovery failed. Check the code and try again."); }
    finally { setBusy(false); }
  }

  return <div className="form-stack org-recovery-unlock">
    {stage === "loading" && <div className="vault-loading"><div className="loading-ring" /></div>}
    {stage === "none" && <p className="field-hint">Your account is not enrolled in organization recovery. Use your recovery key instead.</p>}
    {stage === "choose" && <>
      {tenants.length > 1 && <div><Label htmlFor="org-recovery-tenant">Organization</Label><select id="org-recovery-tenant" value={tenantId} onChange={(event) => { setTenantId(event.target.value); void refresh(event.target.value); }}>{tenants.map((id, index) => <option key={id} value={id}>Organization {index + 1}</option>)}</select></div>}
      <p className="field-hint">Your organization administrators will verify your identity, then give you a one-time recovery code.</p>
      <Button type="button" disabled={busy} onClick={() => void ask()}>{busy ? <LoaderCircle className="spin" /> : <LifeBuoy />} Ask my organization for help</Button>
    </>}
    {stage === "pending" && <><p className="field-hint">Your request is waiting for an administrator. Contact your IT or security team so they can verify it’s you.</p>
      <Button type="button" variant="outline" disabled={busy} onClick={() => void refresh(tenantId)}>Check again</Button></>}
    {stage === "approved" && <form className="form-stack" onSubmit={finish}>
      <div><Label htmlFor="org-recovery-code">One-time recovery code</Label><Input id="org-recovery-code" autoComplete="off" required value={code} onChange={(event) => setCode(event.target.value)} placeholder="PX-ORC1-…" /></div>
      <div><Label htmlFor="org-recovery-password">New vault password</Label><Input id="org-recovery-password" type="password" autoComplete="new-password" minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} /></div>
      <div><Label htmlFor="org-recovery-confirm">Confirm new vault password</Label><Input id="org-recovery-confirm" type="password" autoComplete="new-password" minLength={12} required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></div>
      <Button disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <Check />} Set new vault password</Button>
    </form>}
    {message && <p className="form-message" role="alert">{message}</p>}
    <Button type="button" variant="ghost" onClick={onCancel}>Back</Button>
  </div>;
}
